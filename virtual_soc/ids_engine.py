"""
ML-IDS Engine v3.0 - Hybrid Detection with Multi-Class Attack Classification
- Uses new binary model (99.28%) for ATTACK/BENIGN detection
- Uses OLD multi-class model (14 attack types) for attack type classification
- Enhanced rule-based detection as fallback
"""
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import pickle
import joblib
import numpy as np
import pandas as pd
import os
import uvicorn
from typing import Dict, Any, List, Optional
from collections import deque
from datetime import datetime
import warnings
warnings.filterwarnings("ignore")

app = FastAPI(
    title="ML-IDS Engine v3.0", 
    description="Hybrid Detection with Multi-Class Attack Type Classification"
)

# Store recent events for the dashboard
EVENT_HISTORY = deque(maxlen=100)

# Path configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
MODELS_DIR = os.path.join(os.path.dirname(PROJECT_ROOT), "models")  # New binary model
OUTPUTS_DIR = os.path.join(PROJECT_ROOT, "outputs")  # Old multi-class model

# Detection thresholds (tuned to reduce false positives)
ATTACK_THRESHOLD = 0.25  # Only flag as attack if ML says 25%+ chance
CONFIDENT_BENIGN_THRESHOLD = 0.80  # Trust BENIGN if 80%+ confident

# ============================================
# LOAD NEW BINARY MODEL (ATTACK/BENIGN)
# ============================================
print("Loading new binary model...")
try:
    with open(os.path.join(MODELS_DIR, "random_forest_ids.pkl"), "rb") as f:
        BINARY_MODEL = pickle.load(f)
    with open(os.path.join(MODELS_DIR, "scaler.pkl"), "rb") as f:
        BINARY_SCALER = pickle.load(f)
    with open(os.path.join(MODELS_DIR, "label_encoder.pkl"), "rb") as f:
        BINARY_LABEL_ENCODER = pickle.load(f)
    with open(os.path.join(MODELS_DIR, "feature_names.pkl"), "rb") as f:
        BINARY_FEATURE_NAMES = pickle.load(f)
    
    ATTACK_IDX = list(BINARY_LABEL_ENCODER.classes_).index("ATTACK")
    BENIGN_IDX = list(BINARY_LABEL_ENCODER.classes_).index("BENIGN")
    print(f"  Binary model loaded: {BINARY_LABEL_ENCODER.classes_}")
except Exception as e:
    print(f"WARNING: Could not load binary model: {e}")
    BINARY_MODEL = None

# ============================================
# LOAD OLD MULTI-CLASS MODEL (14 attack types)
# ============================================
print("Loading old multi-class model for attack type classification...")
try:
    MULTICLASS_MODEL = joblib.load(os.path.join(OUTPUTS_DIR, "best_model_randomforest.joblib"))
    MULTICLASS_LABEL_ENCODER = joblib.load(os.path.join(OUTPUTS_DIR, "label_encoder.joblib"))
    MULTICLASS_PREPROCESSOR = joblib.load(os.path.join(OUTPUTS_DIR, "preprocessor.joblib"))
    
    with open(os.path.join(OUTPUTS_DIR, "selected_features.txt"), "r") as f:
        MULTICLASS_SELECTED_FEATURES = [line.strip() for line in f if line.strip()]
    
    MULTICLASS_PREPROCESSOR_FEATURES = list(MULTICLASS_PREPROCESSOR.feature_names_in_)
    MULTICLASS_FEATURE_INDICES = [MULTICLASS_PREPROCESSOR_FEATURES.index(f) for f in MULTICLASS_SELECTED_FEATURES]
    
    print(f"  Multi-class model loaded: {list(MULTICLASS_LABEL_ENCODER.classes_)}")
except Exception as e:
    print(f"WARNING: Could not load multi-class model: {e}")
    MULTICLASS_MODEL = None

print("Models loaded successfully!")


def classify_attack_type_ml(features: Dict[str, Any]) -> tuple:
    """
    Use the old multi-class model to classify attack type.
    Returns (attack_type, confidence)
    """
    if MULTICLASS_MODEL is None:
        return ("Unknown", 0.5)
    
    try:
        # Create DataFrame
        input_df = pd.DataFrame([features])
        
        # Add missing features
        for feat in MULTICLASS_PREPROCESSOR_FEATURES:
            if feat not in input_df.columns:
                input_df[feat] = 0
        
        input_df = input_df[MULTICLASS_PREPROCESSOR_FEATURES]
        input_df = input_df.replace([np.inf, -np.inf], 0).fillna(0)
        
        # Preprocess
        processed = MULTICLASS_PREPROCESSOR.transform(input_df)
        selected = processed[:, MULTICLASS_FEATURE_INDICES]
        selected_df = pd.DataFrame(selected, columns=MULTICLASS_SELECTED_FEATURES)
        
        # Predict
        probs = MULTICLASS_MODEL.predict_proba(selected_df)[0]
        pred_idx = probs.argmax()
        attack_type = MULTICLASS_LABEL_ENCODER.classes_[pred_idx]
        confidence = float(probs[pred_idx])
        
        # Get top 3 predictions (useful for debugging)
        top3_idx = np.argsort(probs)[-3:][::-1]
        top3 = [(MULTICLASS_LABEL_ENCODER.classes_[i], float(probs[i])) for i in top3_idx]
        
        return (attack_type, confidence, top3)
    except Exception as e:
        print(f"Error in ML classification: {e}")
        return ("Unknown", 0.5, [])


def rule_based_classification(features: Dict[str, Any]) -> tuple:
    """
    Rule-based attack classification tuned for 2-second flow windows.
    Returns (attack_type, confidence)
    """
    dst_port = features.get("Destination Port", 0)
    syn_count = features.get("SYN Flag Count", 0)
    rst_count = features.get("RST Flag Count", 0)
    ack_count = features.get("ACK Flag Count", 0)
    psh_count = features.get("PSH Flag Count", 0)
    fin_count = features.get("FIN Flag Count", 0)
    fwd_packets = features.get("Total Fwd Packets", 0)
    bwd_packets = features.get("Total Backward Packets", 0)
    fwd_bytes = features.get("Total Length of Fwd Packets", 0)
    bwd_bytes = features.get("Total Length of Bwd Packets", 0)
    flow_duration = features.get("Flow Duration", 1)
    fwd_packets_s = features.get("Fwd Packets/s", 0)
    init_win_bwd = features.get("Init_Win_bytes_backward", -1)
    
    total_packets = fwd_packets + bwd_packets
    
    # Calculate packets per second
    if flow_duration > 0:
        pps = total_packets / (flow_duration / 1_000_000)
    else:
        pps = fwd_packets  # Assume 1 second if no duration
    
    # Check asymmetry ratio
    is_asymmetric = (bwd_packets == 0) or (fwd_packets > bwd_packets * 2)
    is_very_asymmetric = (bwd_packets == 0) or (fwd_packets > bwd_packets * 5)
    
    # =====================================================
    # DDoS / DoS Detection
    # Tuned for 2-second flow windows
    # =====================================================
    
    # DDoS on web ports: SYN packets + asymmetric + port 80/443
    if dst_port in [80, 443, 8080]:
        # High SYN with no/few responses = SYN Flood
        if syn_count >= 2 and is_very_asymmetric:
            return ("DDoS", 0.90)
        # Multiple packets, mostly SYN, asymmetric
        if fwd_packets >= 2 and syn_count >= 1 and is_asymmetric:
            if ack_count <= syn_count:  # More SYN than ACK = suspicious
                return ("DDoS", 0.85)
        # High packet rate on web port
        if pps > 20:
            return ("DDoS", 0.80)
    
    # DDoS on any port: High packet rate + asymmetric
    if pps > 50 and is_asymmetric:
        return ("DDoS", 0.85)
    
    # DoS Hulk: HTTP bombardment
    if dst_port == 80 and psh_count >= 3 and fwd_packets >= 5:
        return ("DoS Hulk", 0.80)
    
    # DoS Slowloris: Long duration, low rate
    if dst_port in [80, 443] and flow_duration > 30000000:
        if fwd_packets >= 2 and pps < 5:
            return ("DoS slowloris", 0.75)
    
    # DoS GoldenEye
    if dst_port == 80 and psh_count >= 5 and fwd_packets >= 10:
        return ("DoS GoldenEye", 0.75)
    
    # =====================================================
    # PortScan Detection
    # =====================================================
    
    # SYN scan: SYN + RST response, short flow
    if syn_count >= 1 and rst_count >= 1:
        if fwd_packets <= 3 and flow_duration < 2000000:
            return ("PortScan", 0.85)
    
    # SYN scan with no response
    if syn_count >= 1 and bwd_packets == 0 and fwd_packets <= 2:
        if dst_port not in [80, 443, 8080]:  # Not web = likely scan
            return ("PortScan", 0.80)
    
    # =====================================================
    # Brute Force Detection
    # =====================================================
    
    # SSH Brute Force
    if dst_port == 22:
        if fwd_packets >= 3 or syn_count >= 2:
            return ("SSH-Patator", 0.85)
    
    # FTP Brute Force
    if dst_port == 21:
        if fwd_packets >= 3 or syn_count >= 2:
            return ("FTP-Patator", 0.85)
    
    # Telnet Brute Force
    if dst_port == 23 and fwd_packets >= 3:
        return ("Telnet Brute Force", 0.80)
    
    # RDP Brute Force
    if dst_port == 3389 and fwd_packets >= 3:
        return ("RDP Brute Force", 0.80)
    
    # =====================================================
    # Web Attack Detection
    # =====================================================
    
    if dst_port in [80, 443, 8080, 8443]:
        # Web attack: High data volume
        if psh_count >= 3 and fwd_bytes > 1000:
            return ("Web Attack", 0.70)
    
    # =====================================================
    # Bot Detection
    # =====================================================
    
    if flow_duration > 30000000 and fwd_packets >= 3:
        if pps > 0.5 and pps < 10:
            return ("Bot", 0.65)
    
    # =====================================================
    # Infiltration / Data Exfiltration
    # =====================================================
    
    if dst_port > 10000 and fwd_bytes > 5000:
        return ("Infiltration", 0.60)
    
    # =====================================================
    # Heartbleed
    # =====================================================
    
    if dst_port == 443 and bwd_bytes > fwd_bytes * 10:
        return ("Heartbleed", 0.65)
    
    # =====================================================
    # Default: Use port-based heuristic
    # =====================================================
    
    # If attack detected but no specific type, use port to guess
    if dst_port in [80, 443, 8080] and is_asymmetric:
        return ("DDoS", 0.70)  # Web port attack
    
    if dst_port in [22, 21, 23, 3389] and fwd_packets >= 2:
        return ("Brute Force", 0.65)  # Auth port attack
    
    return ("Unknown Attack", 0.50)


class FlowData(BaseModel):
    features: Dict[str, Any]


@app.get("/")
def health_check():
    return {
        "status": "online",
        "version": "3.0",
        "model": "Hybrid (Binary + Multi-class)",
        "binary_classes": list(BINARY_LABEL_ENCODER.classes_) if BINARY_LABEL_ENCODER else [],
        "attack_types": list(MULTICLASS_LABEL_ENCODER.classes_) if MULTICLASS_LABEL_ENCODER else [],
        "detection_mode": "ML + Rules"
    }


@app.post("/predict")
def predict_flow(data: FlowData):
    """
    Hybrid detection:
    1. Use new binary model to detect ATTACK vs BENIGN
    2. Use old multi-class model + rules for attack type classification
    """
    try:
        src_ip = data.features.get("src_ip", "unknown")
        dst_ip = data.features.get("dst_ip", "unknown")
        dst_port = data.features.get("Destination Port", 0)
        
        # ============================================
        # STEP 1: Binary Classification (ATTACK/BENIGN)
        # ============================================
        is_attack = False
        binary_confidence = 0.5
        attack_prob = 0.0
        
        if BINARY_MODEL is not None:
            # Map features to binary model format
            feature_vector = []
            feature_map = {
                "Flow Duration": "Flow Duration",
                "Total Fwd Packets": "Total Fwd Packet",
                "Total Backward Packets": "Total Bwd packets",
                "Total Length of Fwd Packets": "Total Length of Fwd Packet",
                "Total Length of Bwd Packets": "Total Length of Bwd Packet",
                # ... simplified mapping
            }
            
            for feat_name in BINARY_FEATURE_NAMES:
                value = 0.0
                # Direct match
                if feat_name in data.features:
                    value = float(data.features[feat_name])
                # Try alternative names
                for old_name, new_name in feature_map.items():
                    if new_name == feat_name and old_name in data.features:
                        value = float(data.features[old_name])
                        break
                feature_vector.append(value)
            
            X = np.array(feature_vector).reshape(1, -1)
            X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
            X_scaled = BINARY_SCALER.transform(X)
            
            probs = BINARY_MODEL.predict_proba(X_scaled)[0]
            attack_prob = float(probs[ATTACK_IDX])
            benign_prob = float(probs[BENIGN_IDX])
            
            is_attack = attack_prob > ATTACK_THRESHOLD or benign_prob < CONFIDENT_BENIGN_THRESHOLD
            binary_confidence = max(attack_prob, benign_prob)
        
        # ============================================
        # STEP 2: Attack Type Classification
        # ============================================
        attack_type = "BENIGN"
        type_confidence = 1.0
        detection_method = "ml"
        ml_attack_type = "BENIGN"
        
        if is_attack or attack_prob > 0.20:  # Raised threshold to reduce false positives
            # First try rule-based (more accurate for known patterns)
            rule_type, rule_conf = rule_based_classification(data.features)
            
            # Then try ML multi-class
            ml_type, ml_conf, top3 = classify_attack_type_ml(data.features)
            ml_attack_type = ml_type
            
            # Decision: Use rules if confident, else use ML
            if rule_conf >= 0.70 and rule_type != "Unknown Attack":
                attack_type = rule_type
                type_confidence = rule_conf
                detection_method = "rules"
            elif ml_type != "BENIGN" and ml_conf > 0.30:
                attack_type = ml_type
                type_confidence = ml_conf
                detection_method = "ml-multiclass"
            else:
                attack_type = rule_type
                type_confidence = rule_conf
                detection_method = "rules"
            
            is_attack = True
        
        # Final label
        final_label = "ATTACK" if is_attack else "BENIGN"
        
        event = {
            "timestamp": datetime.now().isoformat(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "label": final_label,
            "attack_type": attack_type if is_attack else "BENIGN",
            "confidence": type_confidence if is_attack else binary_confidence,
            "is_malicious": is_attack,
            "detection_method": detection_method,
            "ml_attack_prob": attack_prob,
            "ml_attack_type": ml_attack_type,
            "model": "Hybrid-v3"
        }
        EVENT_HISTORY.append(event)
        
        if is_attack:
            print(f"\n{'='*60}")
            print(f"[ALERT] {attack_type} DETECTED!")
            print(f"  Source: {src_ip} -> {dst_ip}:{dst_port}")
            print(f"  Confidence: {type_confidence:.1%}")
            print(f"  Detection: {detection_method}")
            print(f"  ML Attack Prob: {attack_prob:.1%}")
            print(f"  ML Type Prediction: {ml_attack_type}")
            print(f"{'='*60}\n")
        
        return event

    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/events")
def get_events():
    return list(EVENT_HISTORY)


@app.post("/clear")
def clear_events():
    """Clear all event history"""
    EVENT_HISTORY.clear()
    return {"status": "cleared", "message": "Event history cleared"}


@app.get("/stats")
def get_stats():
    if not EVENT_HISTORY:
        return {"total": 0, "attacks": 0, "benign": 0}
    
    events = list(EVENT_HISTORY)
    attacks = [e for e in events if e["is_malicious"]]
    
    attack_types = {}
    detection_methods = {}
    for e in events:
        if e["is_malicious"]:
            at = e.get("attack_type", "Unknown")
            attack_types[at] = attack_types.get(at, 0) + 1
        dm = e.get("detection_method", "unknown")
        detection_methods[dm] = detection_methods.get(dm, 0) + 1
    
    return {
        "total": len(events),
        "attacks": len(attacks),
        "benign": len(events) - len(attacks),
        "attack_percentage": len(attacks) / len(events) * 100 if events else 0,
        "attack_types": attack_types,
        "detection_methods": detection_methods
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
