"""
Real-Time Intrusion Detection System - Flask Backend
=====================================================
Serves a trained RandomForest model for live attack detection
"""

from flask import Flask, render_template, request, jsonify
import joblib
import pandas as pd
import numpy as np
from collections import Counter, deque
from datetime import datetime
import os
import random

app = Flask(__name__)

# ============================================================
# Model Loading
# ============================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUTS_DIR = os.path.join(os.path.dirname(BASE_DIR), "outputs")

print("Loading model components...")
MODEL = joblib.load(os.path.join(OUTPUTS_DIR, "best_model_randomforest.joblib"))
LABEL_ENCODER = joblib.load(os.path.join(OUTPUTS_DIR, "label_encoder.joblib"))
PREPROCESSOR = joblib.load(os.path.join(OUTPUTS_DIR, "preprocessor.joblib"))

# Features expected by preprocessor (70 features)
PREPROCESSOR_FEATURES = list(PREPROCESSOR.feature_names_in_)

# Features expected by model (30 selected features)
with open(os.path.join(OUTPUTS_DIR, "selected_features.txt"), "r") as f:
    MODEL_FEATURES = [line.strip() for line in f if line.strip()]

# Get indices of selected features for extraction after preprocessing
MODEL_FEATURE_INDICES = [PREPROCESSOR_FEATURES.index(f) for f in MODEL_FEATURES]

CLASSES = list(LABEL_ENCODER.classes_)
print(f"Model loaded. Classes: {CLASSES}")
print(f"Preprocessor uses {len(PREPROCESSOR_FEATURES)} features")
print(f"Model uses {len(MODEL_FEATURES)} selected features")

# ============================================================
# Severity Mapping
# ============================================================
SEVERITY_MAP = {
    "BENIGN": "none",
    "DDoS": "critical",
    "DoS Hulk": "critical",
    "DoS GoldenEye": "critical",
    "DoS Slowhttptest": "high",
    "DoS slowloris": "high",
    "PortScan": "high",
    "FTP-Patator": "high",
    "SSH-Patator": "high",
    "Web Attack – Brute Force": "high",
    "Web Attack – Sql Injection": "critical",
    "Web Attack – XSS": "high",
    "Bot": "critical",
    "Infiltration": "critical",
    "Heartbleed": "critical",
}

# Simulated IP pools for demo
INTERNAL_IPS = ["192.168.1.10", "192.168.1.15", "192.168.1.20", "192.168.1.25", "10.0.0.5"]
EXTERNAL_IPS = ["45.33.32.156", "185.199.108.153", "93.184.216.34", "104.21.56.70", "172.67.154.83"]
ATTACKER_IPS = ["45.227.255.206", "185.220.101.33", "91.121.87.18", "193.27.228.63", "89.248.167.131"]

def get_severity(label, confidence):
    """Get severity level based on attack type and confidence"""
    base_severity = SEVERITY_MAP.get(label, "medium")
    if base_severity == "none":
        return "none"
    # Adjust based on confidence
    if confidence >= 0.95:
        return base_severity
    elif confidence >= 0.8:
        return "high" if base_severity == "critical" else "medium"
    else:
        return "medium" if base_severity in ["critical", "high"] else "low"

def generate_ips(is_attack, label):
    """Generate simulated source and destination IPs"""
    if not is_attack:
        src = random.choice(INTERNAL_IPS)
        dst = random.choice(EXTERNAL_IPS)
    elif label in ["PortScan", "DDoS", "DoS Hulk", "DoS GoldenEye"]:
        src = random.choice(ATTACKER_IPS)
        dst = random.choice(INTERNAL_IPS)
    else:
        src = random.choice(ATTACKER_IPS)
        dst = random.choice(INTERNAL_IPS)
    return src, dst

# ============================================================
# Attack Simulation Presets - Complete 30-feature synthetic data
# Generated from actual attack samples in demo_flows.csv
# ============================================================
ATTACK_PRESETS_30 = {
    "benign_web": {
        "name": "Normal Web Traffic",
        "attack_type": "BENIGN",
        "features": {
            "Destination Port": 80,
            "Init_Win_bytes_backward": 29200,
            "min_seg_size_forward": 20,
            "Fwd Packet Length Max": 6,
            "Bwd Packet Length Mean": 0.0,
            "Subflow Fwd Bytes": 12,
            "Flow IAT Max": 5162649,
            "Flow IAT Mean": 1757259.67,
            "Subflow Bwd Bytes": 0,
            "Average Packet Size": 3.0,
            "Init_Win_bytes_forward": 8192,
            "Fwd IAT Total": 5271779,
            "Flow IAT Std": 2949656.65,
            "Bwd Packet Length Min": 0,
            "Max Packet Length": 6,
            "Fwd Packet Length Mean": 4.0,
            "Bwd Header Length": 32,
            "Fwd IAT Mean": 2635889.5,
            "Fwd Header Length.1": 72,
            "Packet Length Variance": 10.8,
            "act_data_pkt_fwd": 2,
            "Fwd IAT Std": 3573377.55,
            "Active Min": 0,
            "Fwd IAT Min": 109130,
            "Bwd IAT Mean": 0.0,
            "PSH Flag Count": 1,
            "Flow Bytes/s": 2.28,
            "Bwd Packets/s": 0.19,
            "Min Packet Length": 0,
            "Bwd IAT Total": 0,
        }
    },
    "portscan": {
        "name": "Port Scan Attack",
        "attack_type": "PortScan",
        "features": {
            "Destination Port": 84,
            "Init_Win_bytes_backward": 0,
            "min_seg_size_forward": 40,
            "Fwd Packet Length Max": 0,
            "Bwd Packet Length Mean": 6.0,
            "Subflow Fwd Bytes": 0,
            "Flow IAT Max": 44,
            "Flow IAT Mean": 44.0,
            "Subflow Bwd Bytes": 6,
            "Average Packet Size": 3.0,
            "Init_Win_bytes_forward": 29200,
            "Fwd IAT Total": 0,
            "Flow IAT Std": 0.0,
            "Bwd Packet Length Min": 6,
            "Max Packet Length": 6,
            "Fwd Packet Length Mean": 0.0,
            "Bwd Header Length": 20,
            "Fwd IAT Mean": 0.0,
            "Fwd Header Length.1": 40,
            "Packet Length Variance": 12.0,
            "act_data_pkt_fwd": 0,
            "Fwd IAT Std": 0.0,
            "Active Min": 0,
            "Fwd IAT Min": 0,
            "Bwd IAT Mean": 0.0,
            "PSH Flag Count": 1,
            "Flow Bytes/s": 136363.64,
            "Bwd Packets/s": 22727.27,
            "Min Packet Length": 0,
            "Bwd IAT Total": 0,
        }
    },
    "ddos": {
        "name": "DDoS Attack",
        "attack_type": "DDoS",
        "features": {
            "Destination Port": 80,
            "Init_Win_bytes_backward": 229,
            "min_seg_size_forward": 20,
            "Fwd Packet Length Max": 20,
            "Bwd Packet Length Mean": 2321.4,
            "Subflow Fwd Bytes": 50,
            "Flow IAT Max": 6075462,
            "Flow IAT Mean": 736227.91,
            "Subflow Bwd Bytes": 11607,
            "Average Packet Size": 971.92,
            "Init_Win_bytes_forward": 256,
            "Fwd IAT Total": 8016239,
            "Flow IAT Std": 1863101.34,
            "Bwd Packet Length Min": 0,
            "Max Packet Length": 7215,
            "Fwd Packet Length Mean": 7.14,
            "Bwd Header Length": 112,
            "Fwd IAT Mean": 1336039.83,
            "Fwd Header Length.1": 152,
            "Packet Length Variance": 5064817.31,
            "act_data_pkt_fwd": 5,
            "Fwd IAT Std": 2447736.52,
            "Active Min": 1940002,
            "Fwd IAT Min": 165,
            "Bwd IAT Mean": 20756.75,
            "PSH Flag Count": 0,
            "Flow Bytes/s": 1439.40,
            "Bwd Packets/s": 0.62,
            "Min Packet Length": 0,
            "Bwd IAT Total": 83027,
        }
    },
    "dos_hulk": {
        "name": "DoS Hulk Attack",
        "attack_type": "DoS Hulk",
        "features": {
            "Destination Port": 80,
            "Init_Win_bytes_backward": 235,
            "min_seg_size_forward": 32,
            "Fwd Packet Length Max": 382,
            "Bwd Packet Length Mean": 1932.5,
            "Subflow Fwd Bytes": 382,
            "Flow IAT Max": 577,
            "Flow IAT Mean": 234.75,
            "Subflow Bwd Bytes": 11595,
            "Average Packet Size": 1330.78,
            "Init_Win_bytes_forward": 29200,
            "Fwd IAT Total": 975,
            "Flow IAT Std": 229.13,
            "Bwd Packet Length Min": 0,
            "Max Packet Length": 4355,
            "Fwd Packet Length Mean": 127.33,
            "Bwd Header Length": 200,
            "Fwd IAT Mean": 487.5,
            "Fwd Header Length.1": 104,
            "Packet Length Variance": 3558249.79,
            "act_data_pkt_fwd": 1,
            "Fwd IAT Std": 265.17,
            "Active Min": 0,
            "Fwd IAT Min": 300,
            "Bwd IAT Mean": 356.0,
            "PSH Flag Count": 1,
            "Flow Bytes/s": 6377529.29,
            "Bwd Packets/s": 3194.89,
            "Min Packet Length": 0,
            "Bwd IAT Total": 1780,
        }
    },
    "ssh_brute": {
        "name": "SSH Brute Force",
        "attack_type": "SSH-Patator",
        "features": {
            "Destination Port": 22,
            "Init_Win_bytes_backward": 0,
            "min_seg_size_forward": 32,
            "Fwd Packet Length Max": 0,
            "Bwd Packet Length Mean": 0.0,
            "Subflow Fwd Bytes": 0,
            "Flow IAT Max": 404,
            "Flow IAT Mean": 404.0,
            "Subflow Bwd Bytes": 0,
            "Average Packet Size": 0.0,
            "Init_Win_bytes_forward": 259,
            "Fwd IAT Total": 404,
            "Flow IAT Std": 0.0,
            "Bwd Packet Length Min": 0,
            "Max Packet Length": 0,
            "Fwd Packet Length Mean": 0.0,
            "Bwd Header Length": 0,
            "Fwd IAT Mean": 404.0,
            "Fwd Header Length.1": 64,
            "Packet Length Variance": 0.0,
            "act_data_pkt_fwd": 0,
            "Fwd IAT Std": 0.0,
            "Active Min": 0,
            "Fwd IAT Min": 404,
            "Bwd IAT Mean": 0.0,
            "PSH Flag Count": 0,
            "Flow Bytes/s": 0.0,
            "Bwd Packets/s": 0.0,
            "Min Packet Length": 0,
            "Bwd IAT Total": 0,
        }
    },
}

# Keep old ATTACK_PRESETS for backward compatibility
ATTACK_PRESETS = ATTACK_PRESETS_30

# ============================================================
# In-Memory Storage
# ============================================================
EVENTS = deque(maxlen=500)  # Recent detection events
STATS = {
    "total": 0,
    "benign": 0,
    "attacks": 0,
    "by_type": Counter(),
    "online_cm": {}  # (predicted, true) -> count
}


# ============================================================
# Routes
# ============================================================
@app.route("/")
def index():
    """Serve the main dashboard HTML"""
    return render_template("index.html")


@app.route("/api/predict", methods=["POST"])
def api_predict():
    """
    Predict attack type for incoming flow
    
    Input JSON:
        - features: dict of feature_name -> numeric value
        - true_label (optional): ground-truth for performance tracking
        - src_ip (optional): source IP for display
        - dst_ip (optional): destination IP for display
    """
    data = request.get_json()
    flow = data["features"]
    true_label = data.get("true_label")
    src_ip = data.get("src_ip")
    dst_ip = data.get("dst_ip")

    try:
        # Build feature DataFrame with all 70 preprocessor features
        df = pd.DataFrame([flow])
        
        # Ensure all required preprocessor features are present
        for feat in PREPROCESSOR_FEATURES:
            if feat not in df.columns:
                df[feat] = 0
        
        # Reorder to match preprocessor expected order
        df = df[PREPROCESSOR_FEATURES]
        
        # Replace any NaN/inf values
        df = df.replace([np.inf, -np.inf], 0)
        df = df.fillna(0)
        
        # Preprocess all 70 features
        X_processed = PREPROCESSOR.transform(df)
        
        # Extract only the 30 selected features for model
        X_selected = X_processed[:, MODEL_FEATURE_INDICES]
        
        # Predict
        proba = MODEL.predict_proba(X_selected)[0]
        idx = proba.argmax()
        label = CLASSES[idx]
        confidence = float(proba[idx])
        is_attack = (label != "BENIGN")
        
        # Get severity
        severity = get_severity(label, confidence)
        
        # Generate IPs if not provided
        if not src_ip or not dst_ip:
            src_ip, dst_ip = generate_ips(is_attack, label)

        # Create event record
        event = {
            "ts": datetime.utcnow().isoformat(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "label": label,
            "prob": round(confidence, 4),
            "is_attack": is_attack,
            "severity": severity,
            "true_label": true_label,
        }
        EVENTS.appendleft(event)

        # Update statistics
        STATS["total"] += 1
        if is_attack:
            STATS["attacks"] += 1
        else:
            STATS["benign"] += 1
        STATS["by_type"][label] += 1

        # Track accuracy if true label provided
        if true_label is not None:
            key = (label, true_label)
            STATS["online_cm"][key] = STATS["online_cm"].get(key, 0) + 1

        return jsonify(event)

    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/events")
def api_events():
    """Return recent detection events"""
    limit = int(request.args.get("limit", 50))
    return jsonify(list(EVENTS)[:limit])


@app.route("/api/stats")
def api_stats():
    """Return aggregate statistics and performance metrics"""
    by_type = dict(STATS["by_type"])
    cm = {f"{pred}|{true}": count 
          for (pred, true), count in STATS["online_cm"].items()}
    
    # Calculate live accuracy
    total = STATS["total"]
    if total > 0 and STATS["online_cm"]:
        correct = sum(count for (pred, true), count in STATS["online_cm"].items() 
                      if pred == true)
        accuracy = round(correct / total, 4)
    else:
        accuracy = None
    
    # Calculate per-attack recall for key attacks
    recall_by_type = {}
    key_attacks = ["PortScan", "DDoS", "DoS Hulk", "BENIGN"]
    for attack_type in CLASSES:
        tp = STATS["online_cm"].get((attack_type, attack_type), 0)
        fn = sum(count for (pred, true), count in STATS["online_cm"].items() 
                 if true == attack_type and pred != attack_type)
        if tp + fn > 0:
            recall_by_type[attack_type] = round(tp / (tp + fn), 4)
    
    return jsonify({
        "total": total,
        "benign": STATS["benign"],
        "attacks": STATS["attacks"],
        "by_type": by_type,
        "online_cm": cm,
        "accuracy": accuracy,
        "recall_by_type": recall_by_type
    })


@app.route("/api/presets")
def api_presets():
    """Return attack simulation presets"""
    return jsonify({
        name: {"name": preset["name"]} 
        for name, preset in ATTACK_PRESETS.items()
    })


@app.route("/api/preset/<preset_name>")
def api_get_preset(preset_name):
    """Get features for a specific preset"""
    if preset_name in ATTACK_PRESETS:
        return jsonify(ATTACK_PRESETS[preset_name])
    return jsonify({"error": "Preset not found"}), 404


@app.route("/api/features")
def api_features():
    """Return list of expected feature names"""
    return jsonify({
        "preprocessor_features": PREPROCESSOR_FEATURES,
        "model_features": MODEL_FEATURES
    })


@app.route("/api/model_features")
def api_model_features():
    """Return the 30 model features with default values"""
    return jsonify({
        "features": MODEL_FEATURES,
        "count": len(MODEL_FEATURES),
        "defaults": {f: 0 for f in MODEL_FEATURES}
    })


@app.route("/api/predict_direct", methods=["POST"])
def api_predict_direct():
    """
    Prediction using 30 model features with preprocessing.
    Pads to 70 features (zeros for missing), applies preprocessor, then selects 30 for model.
    """
    data = request.json
    if not data:
        return jsonify({"error": "No data provided"}), 400
    
    features = data.get("features", data)
    
    try:
        # Build DataFrame with all 70 preprocessor features (pad missing with 0)
        df = pd.DataFrame(columns=PREPROCESSOR_FEATURES)
        row = {feat: 0 for feat in PREPROCESSOR_FEATURES}
        
        # Fill in provided 30 features
        for feat, val in features.items():
            if feat in PREPROCESSOR_FEATURES:
                if val is None or (isinstance(val, float) and np.isnan(val)):
                    val = 0
                row[feat] = float(val)
        
        df = pd.concat([df, pd.DataFrame([row])], ignore_index=True)
        df = df.fillna(0).replace([np.inf, -np.inf], 0)
        
        # Apply preprocessor to get scaled features
        X_processed = PREPROCESSOR.transform(df)
        
        # Select only the 30 model features
        X_selected = X_processed[:, MODEL_FEATURE_INDICES]
        
        # Predict with model
        proba = MODEL.predict_proba(X_selected)[0]
        idx = proba.argmax()
        label = CLASSES[idx]
        confidence = float(proba[idx])
        is_attack = (label != "BENIGN")
        
        # Get severity
        severity = get_severity(label, confidence)
        
        # Generate IPs
        src_ip, dst_ip = generate_ips(is_attack, label)
        
        # Create event record
        event = {
            "ts": datetime.utcnow().isoformat(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "label": label,
            "prob": round(confidence, 4),
            "is_attack": is_attack,
            "severity": severity,
            "direct_prediction": True
        }
        EVENTS.appendleft(event)
        
        # Update statistics
        STATS["total"] += 1
        if is_attack:
            STATS["attacks"] += 1
        else:
            STATS["benign"] += 1
        STATS["by_type"][label] += 1
        
        return jsonify(event)
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 400


@app.route("/api/sample/<attack_type>")
def api_sample(attack_type):
    """
    Get a complete 70-feature sample from demo_flows.csv.
    This allows the UI to load all features for accurate manual testing.
    """
    type_mapping = {
        "benign": "BENIGN",
        "benign_web": "BENIGN",
        "portscan": "PortScan",
        "ddos": "DDoS",
        "dos_hulk": "DDoS",  # Fallback to DDoS
        "ssh_brute": "PortScan"  # Fallback to PortScan
    }
    
    target_label = type_mapping.get(attack_type.lower())
    if not target_label:
        return jsonify({"error": f"Unknown attack type: {attack_type}"}), 400
    
    # Load demo flows CSV
    demo_path = os.path.join(BASE_DIR, "demo_flows.csv")
    if not os.path.exists(demo_path):
        return jsonify({"error": "Demo flows file not found"}), 500
    
    df = pd.read_csv(demo_path)
    
    # Filter for target label
    samples = df[df["Label"] == target_label]
    if samples.empty:
        return jsonify({"error": f"No samples found for {target_label}"}), 400
    
    # Pick first row (consistent behavior for demo)
    sample = samples.iloc[0]
    
    # Extract features (all columns except Label)
    features = sample.drop("Label").to_dict()
    
    # Clean up NaN/inf values
    features = {k: (0 if pd.isna(v) or np.isinf(v) else float(v)) for k, v in features.items()}
    
    return jsonify({
        "name": f"{target_label} Sample",
        "attack_type": target_label,
        "features": features,
        "feature_count": len(features)
    })


@app.route("/api/reset", methods=["POST"])
def api_reset():
    """Reset all statistics"""
    global STATS, EVENTS
    STATS = {
        "total": 0,
        "benign": 0,
        "attacks": 0,
        "by_type": Counter(),
        "online_cm": {}
    }
    EVENTS.clear()
    return jsonify({"status": "reset"})


@app.route("/api/simulate/<attack_type>", methods=["POST"])
def api_simulate(attack_type):
    """
    Simulate an attack using a complete sample row from demo_flows.csv
    This ensures all 70 features are properly populated.
    """
    type_mapping = {
        "benign": "BENIGN",
        "portscan": "PortScan",
        "ddos": "DDoS",
    }
    
    target_label = type_mapping.get(attack_type.lower())
    if not target_label:
        return jsonify({"error": f"Unknown attack type: {attack_type}"}), 400
    
    # Load demo flows CSV
    demo_path = os.path.join(BASE_DIR, "demo_flows.csv")
    if not os.path.exists(demo_path):
        return jsonify({"error": "Demo flows file not found"}), 500
    
    df = pd.read_csv(demo_path)
    
    # Filter for target label and pick a random sample
    samples = df[df["Label"] == target_label]
    if samples.empty:
        return jsonify({"error": f"No samples found for {target_label}"}), 400
    
    # Pick random row
    sample = samples.sample(n=1).iloc[0]
    
    # Extract features (all columns except Label)
    features = sample.drop("Label").to_dict()
    
    # Clean up NaN/inf values
    features = {k: (0 if pd.isna(v) or np.isinf(v) else float(v)) for k, v in features.items()}
    
    # Generate IPs
    src_ip, dst_ip = generate_ips(target_label != "BENIGN", target_label)
    
    # Create the prediction request internally
    try:
        # Build feature DataFrame with all 70 preprocessor features
        flow_df = pd.DataFrame([features])
        
        # Ensure all required preprocessor features are present
        for feat in PREPROCESSOR_FEATURES:
            if feat not in flow_df.columns:
                flow_df[feat] = 0
        
        # Reorder to match preprocessor expected order
        flow_df = flow_df[PREPROCESSOR_FEATURES]
        
        # Replace any NaN/inf values
        flow_df = flow_df.replace([np.inf, -np.inf], 0)
        flow_df = flow_df.fillna(0)
        
        # Preprocess all 70 features
        X_processed = PREPROCESSOR.transform(flow_df)
        
        # Extract only the 30 selected features for model
        X_selected = X_processed[:, MODEL_FEATURE_INDICES]
        
        # Predict
        proba = MODEL.predict_proba(X_selected)[0]
        idx = proba.argmax()
        label = CLASSES[idx]
        confidence = float(proba[idx])
        is_attack = (label != "BENIGN")
        
        # Get severity
        severity = get_severity(label, confidence)
        
        # Create event record
        event = {
            "ts": datetime.utcnow().isoformat(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "label": label,
            "prob": round(confidence, 4),
            "is_attack": is_attack,
            "severity": severity,
            "true_label": target_label,
            "simulated": True
        }
        EVENTS.appendleft(event)
        
        # Update statistics
        STATS["total"] += 1
        if is_attack:
            STATS["attacks"] += 1
        else:
            STATS["benign"] += 1
        STATS["by_type"][label] += 1
        
        # Track accuracy
        key = (label, target_label)
        STATS["online_cm"][key] = STATS["online_cm"].get(key, 0) + 1
        
        return jsonify(event)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 400


if __name__ == "__main__":
    app.run(debug=True, port=5000)

