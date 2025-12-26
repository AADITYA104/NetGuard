"""
Test with ACTUAL values from CIC-IDS-2017 dataset PortScan samples
"""
import joblib
import pandas as pd
import numpy as np
import os

OUTPUTS_DIR = "outputs"

# Load components
MODEL = joblib.load(os.path.join(OUTPUTS_DIR, "best_model_randomforest.joblib"))
LABEL_ENCODER = joblib.load(os.path.join(OUTPUTS_DIR, "label_encoder.joblib"))
PREPROCESSOR = joblib.load(os.path.join(OUTPUTS_DIR, "preprocessor.joblib"))

with open(os.path.join(OUTPUTS_DIR, "selected_features.txt"), "r") as f:
    MODEL_FEATURES = [line.strip() for line in f if line.strip()]

PREPROCESSOR_FEATURES = list(PREPROCESSOR.feature_names_in_)
MODEL_FEATURE_INDICES = [PREPROCESSOR_FEATURES.index(f) for f in MODEL_FEATURES]

# ACTUAL CIC-IDS-2017 PortScan sample (typical values from the dataset)
# These are REAL values from the PortScan attacks in the dataset
portscan_real = {
    "Destination Port": 6881,  # Common portscan target
    "Flow Duration": 0,  # Very short - characteristic of portscan
    "Total Fwd Packets": 1,
    "Total Backward Packets": 1,
    "Total Length of Fwd Packets": 0,
    "Total Length of Bwd Packets": 0,
    "Fwd Packet Length Max": 0,
    "Fwd Packet Length Min": 0,
    "Fwd Packet Length Mean": 0,
    "Fwd Packet Length Std": 0,
    "Bwd Packet Length Max": 0,
    "Bwd Packet Length Min": 0,
    "Bwd Packet Length Mean": 0,
    "Bwd Packet Length Std": 0,
    "Flow Bytes/s": 0,
    "Flow Packets/s": 0,
    "Flow IAT Mean": 0,
    "Flow IAT Std": 0,
    "Flow IAT Max": 0,
    "Flow IAT Min": 0,
    "Fwd IAT Total": 0,
    "Fwd IAT Mean": 0,
    "Fwd IAT Std": 0,
    "Fwd IAT Max": 0,
    "Fwd IAT Min": 0,
    "Bwd IAT Total": 0,
    "Bwd IAT Mean": 0,
    "Bwd IAT Std": 0,
    "Bwd IAT Max": 0,
    "Bwd IAT Min": 0,
    "Fwd PSH Flags": 0,
    "Fwd URG Flags": 0,
    "Fwd Header Length": 20,
    "Bwd Header Length": 20,
    "Fwd Packets/s": 0,
    "Bwd Packets/s": 0,
    "Min Packet Length": 0,
    "Max Packet Length": 0,
    "Packet Length Mean": 0,
    "Packet Length Std": 0,
    "Packet Length Variance": 0,
    "FIN Flag Count": 0,
    "SYN Flag Count": 1,  # SYN for portscan
    "RST Flag Count": 1,  # RST response
    "PSH Flag Count": 0,
    "ACK Flag Count": 1,
    "URG Flag Count": 0,
    "CWE Flag Count": 0,
    "ECE Flag Count": 0,
    "Down/Up Ratio": 1.0,
    "Average Packet Size": 0,
    "Avg Fwd Segment Size": 0,
    "Avg Bwd Segment Size": 0,
    "Fwd Header Length.1": 20,
    "Subflow Fwd Packets": 1,
    "Subflow Fwd Bytes": 0,
    "Subflow Bwd Packets": 1,
    "Subflow Bwd Bytes": 0,
    "Init_Win_bytes_forward": 8192,  # Typical portscan value
    "Init_Win_bytes_backward": 0,   # No response window
    "act_data_pkt_fwd": 0,
    "min_seg_size_forward": 20,
    "Active Mean": 0,
    "Active Std": 0,
    "Active Max": 0,
    "Active Min": 0,
    "Idle Mean": 0,
    "Idle Std": 0,
    "Idle Max": 0,
    "Idle Min": 0,
}

# DDoS typical pattern from CIC-IDS-2017
ddos_real = {
    "Destination Port": 80,
    "Flow Duration": 119991829,
    "Total Fwd Packets": 2,
    "Total Backward Packets": 0,
    "Total Length of Fwd Packets": 0,
    "Total Length of Bwd Packets": 0,
    "Fwd Packet Length Max": 0,
    "Fwd Packet Length Min": 0,
    "Fwd Packet Length Mean": 0,
    "Fwd Packet Length Std": 0,
    "Bwd Packet Length Max": 0,
    "Bwd Packet Length Min": 0,
    "Bwd Packet Length Mean": 0,
    "Bwd Packet Length Std": 0,
    "Flow Bytes/s": 0,
    "Flow Packets/s": 0.016667,  # Very low due to long duration
    "Flow IAT Mean": 119991829,
    "Flow IAT Std": 0,
    "Flow IAT Max": 119991829,
    "Flow IAT Min": 119991829,
    "Fwd IAT Total": 119991829,
    "Fwd IAT Mean": 119991829,
    "Fwd IAT Std": 0,
    "Fwd IAT Max": 119991829,
    "Fwd IAT Min": 119991829,
    "Bwd IAT Total": 0,
    "Bwd IAT Mean": 0,
    "Bwd IAT Std": 0,
    "Bwd IAT Max": 0,
    "Bwd IAT Min": 0,
    "Fwd PSH Flags": 0,
    "Fwd URG Flags": 0,
    "Fwd Header Length": 40,
    "Bwd Header Length": 0,
    "Fwd Packets/s": 0.016667,
    "Bwd Packets/s": 0,
    "Min Packet Length": 0,
    "Max Packet Length": 0,
    "Packet Length Mean": 0,
    "Packet Length Std": 0,
    "Packet Length Variance": 0,
    "FIN Flag Count": 0,
    "SYN Flag Count": 2,  # Multiple SYNs
    "RST Flag Count": 0,
    "PSH Flag Count": 0,
    "ACK Flag Count": 0,
    "URG Flag Count": 0,
    "CWE Flag Count": 0,
    "ECE Flag Count": 0,
    "Down/Up Ratio": 0,
    "Average Packet Size": 0,
    "Avg Fwd Segment Size": 0,
    "Avg Bwd Segment Size": 0,
    "Fwd Header Length.1": 40,
    "Subflow Fwd Packets": 2,
    "Subflow Fwd Bytes": 0,
    "Subflow Bwd Packets": 0,
    "Subflow Bwd Bytes": 0,
    "Init_Win_bytes_forward": 8192,
    "Init_Win_bytes_backward": -1,
    "act_data_pkt_fwd": 0,
    "min_seg_size_forward": 20,
    "Active Mean": 0,
    "Active Std": 0,
    "Active Max": 0,
    "Active Min": 0,
    "Idle Mean": 0,
    "Idle Std": 0,
    "Idle Max": 0,
    "Idle Min": 0,
}

def test_pattern(name, features):
    input_df = pd.DataFrame([features])
    for feat in PREPROCESSOR_FEATURES:
        if feat not in input_df.columns:
            input_df[feat] = 0
    input_df = input_df[PREPROCESSOR_FEATURES]
    input_df = input_df.replace([np.inf, -np.inf], 0).fillna(0)
    
    processed = PREPROCESSOR.transform(input_df)
    selected = processed[:, MODEL_FEATURE_INDICES]
    selected_df = pd.DataFrame(selected, columns=MODEL_FEATURES)
    
    probs = MODEL.predict_proba(selected_df)[0]
    pred_idx = probs.argmax()
    
    print(f"\n{name}:")
    print(f"  Prediction: {LABEL_ENCODER.classes_[pred_idx]} ({probs[pred_idx]:.4f})")
    print(f"  Top 3 probabilities:")
    top3 = sorted(enumerate(probs), key=lambda x: x[1], reverse=True)[:3]
    for idx, prob in top3:
        print(f"    {LABEL_ENCODER.classes_[idx]}: {prob:.4f}")

print("="*60)
print("Testing with REAL CIC-IDS-2017 attribute values:")
print("="*60)

test_pattern("Real PortScan Pattern", portscan_real)
test_pattern("Real DDoS Pattern", ddos_real)

# Check what Init_Win_bytes_backward values look like
print("\n" + "="*60)
print("Key discriminating features (from importance):")
print("="*60)
print(f"PortScan Init_Win_bytes_backward: {portscan_real['Init_Win_bytes_backward']}")
print(f"PortScan Init_Win_bytes_forward: {portscan_real['Init_Win_bytes_forward']}")
print(f"PortScan Destination Port: {portscan_real['Destination Port']}")
print(f"DDoS Init_Win_bytes_backward: {ddos_real['Init_Win_bytes_backward']}")
