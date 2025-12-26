"""
Deep diagnostic to understand why the model always predicts BENIGN
"""
import joblib
import pandas as pd
import numpy as np
import os

OUTPUTS_DIR = "outputs"

# Load components
print("Loading model components...")
MODEL = joblib.load(os.path.join(OUTPUTS_DIR, "best_model_randomforest.joblib"))
LABEL_ENCODER = joblib.load(os.path.join(OUTPUTS_DIR, "label_encoder.joblib"))
PREPROCESSOR = joblib.load(os.path.join(OUTPUTS_DIR, "preprocessor.joblib"))

with open(os.path.join(OUTPUTS_DIR, "selected_features.txt"), "r") as f:
    MODEL_FEATURES = [line.strip() for line in f if line.strip()]

PREPROCESSOR_FEATURES = list(PREPROCESSOR.feature_names_in_)
MODEL_FEATURE_INDICES = [PREPROCESSOR_FEATURES.index(f) for f in MODEL_FEATURES]

print(f"Model classes: {LABEL_ENCODER.classes_}")
print(f"Total preprocessor features: {len(PREPROCESSOR_FEATURES)}")
print(f"Selected model features: {len(MODEL_FEATURES)}")

# Check if model has feature_importances_ 
if hasattr(MODEL, 'feature_importances_'):
    importances = MODEL.feature_importances_
    print("\n" + "="*60)
    print("Top 10 Most Important Features:")
    print("="*60)
    feature_imp = list(zip(MODEL_FEATURES, importances))
    feature_imp.sort(key=lambda x: x[1], reverse=True)
    for fname, imp in feature_imp[:10]:
        print(f"  {fname}: {imp:.4f}")

# Check class distribution in training (via class_weight if available)
print("\n" + "="*60)
print("Model Details:")
print("="*60)
print(f"Model type: {type(MODEL).__name__}")
print(f"Number of estimators: {MODEL.n_estimators}")
print(f"Max depth: {MODEL.max_depth}")

# Create a PortScan-like pattern and trace through preprocessing
print("\n" + "="*60)
print("Tracing PortScan Pattern Through Pipeline:")
print("="*60)

# Features typical of PortScan from CIC-IDS-2017 dataset analysis
portscan_features = {
    "Destination Port": 22,
    "Flow Duration": 50000,
    "Total Fwd Packets": 2,
    "Total Backward Packets": 1,
    "Total Length of Fwd Packets": 120,
    "Total Length of Bwd Packets": 60,
    "Fwd Packet Length Max": 60,
    "Fwd Packet Length Min": 60,
    "Fwd Packet Length Mean": 60,
    "Fwd Packet Length Std": 0,
    "Bwd Packet Length Max": 60,
    "Bwd Packet Length Min": 60,
    "Bwd Packet Length Mean": 60,
    "Bwd Packet Length Std": 0,
    "Flow Bytes/s": 3600000,
    "Flow Packets/s": 60000,
    "Flow IAT Mean": 25000,
    "Flow IAT Std": 10000,
    "Flow IAT Max": 50000,
    "Flow IAT Min": 1000,
    "Fwd IAT Total": 25000,
    "Fwd IAT Mean": 25000,
    "Fwd IAT Std": 0,
    "Fwd IAT Max": 25000,
    "Fwd IAT Min": 25000,
    "Bwd IAT Total": 0,
    "Bwd IAT Mean": 0,
    "Bwd IAT Std": 0,
    "Bwd IAT Max": 0,
    "Bwd IAT Min": 0,
    "Fwd PSH Flags": 0,
    "Fwd URG Flags": 0,
    "Fwd Header Length": 40,
    "Bwd Header Length": 20,
    "Fwd Packets/s": 40000,
    "Bwd Packets/s": 20000,
    "Min Packet Length": 60,
    "Max Packet Length": 60,
    "Packet Length Mean": 60,
    "Packet Length Std": 0,
    "Packet Length Variance": 0,
    "FIN Flag Count": 0,
    "SYN Flag Count": 1,
    "RST Flag Count": 1,
    "PSH Flag Count": 0,
    "ACK Flag Count": 1,
    "URG Flag Count": 0,
    "CWE Flag Count": 0,
    "ECE Flag Count": 0,
    "Down/Up Ratio": 0.5,
    "Average Packet Size": 60,
    "Avg Fwd Segment Size": 60,
    "Avg Bwd Segment Size": 60,
    "Fwd Header Length.1": 40,
    "Subflow Fwd Packets": 2,
    "Subflow Fwd Bytes": 120,
    "Subflow Bwd Packets": 1,
    "Subflow Bwd Bytes": 60,
    "Init_Win_bytes_forward": 1024,
    "Init_Win_bytes_backward": 0,
    "act_data_pkt_fwd": 1,
    "min_seg_size_forward": 60,
    "Active Mean": 0,
    "Active Std": 0,
    "Active Max": 0,
    "Active Min": 0,
    "Idle Mean": 0,
    "Idle Std": 0,
    "Idle Max": 0,
    "Idle Min": 0,
}

# Create DataFrame
input_df = pd.DataFrame([portscan_features])
for feat in PREPROCESSOR_FEATURES:
    if feat not in input_df.columns:
        input_df[feat] = 0
input_df = input_df[PREPROCESSOR_FEATURES]
input_df = input_df.replace([np.inf, -np.inf], 0).fillna(0)

print(f"\nInput shape: {input_df.shape}")

# Preprocess
processed = PREPROCESSOR.transform(input_df)
print(f"Processed shape: {processed.shape}")

# Select features
selected = processed[:, MODEL_FEATURE_INDICES]
selected_df = pd.DataFrame(selected, columns=MODEL_FEATURES)

print("\nSelected features for model (first 5):")
for fname in MODEL_FEATURES[:5]:
    print(f"  {fname}: {selected_df[fname].values[0]:.4f}")

# Get prediction probabilities for each class
probs = MODEL.predict_proba(selected_df)[0]
print("\n" + "="*60)
print("Prediction Probabilities for PortScan Pattern:")
print("="*60)
for i, cls in enumerate(LABEL_ENCODER.classes_):
    print(f"  {cls}: {probs[i]:.4f}")

# Check what values the model expects for attacks
print("\n" + "="*60)
print("Checking Decision Path:")
print("="*60)

# Get sample tree from the forest
tree = MODEL.estimators_[0]
print(f"Tree 0 - max depth: {tree.max_depth}, n_leaves: {tree.get_n_leaves()}")

# Look at actual training data ranges if available
print("\n" + "="*60)
print("Preprocessor Statistics (for key features):")
print("="*60)
if hasattr(PREPROCESSOR, 'named_transformers_'):
    print("Preprocessor has named transformers")
    for name, transformer in PREPROCESSOR.named_transformers_.items():
        print(f"  {name}: {type(transformer).__name__}")
elif hasattr(PREPROCESSOR, 'scale_') and hasattr(PREPROCESSOR, 'mean_'):
    print("StandardScaler detected")
    for i, fname in enumerate(MODEL_FEATURES[:5]):
        idx = PREPROCESSOR_FEATURES.index(fname)
        print(f"  {fname}: mean={PREPROCESSOR.mean_[idx]:.4f}, scale={PREPROCESSOR.scale_[idx]:.4f}")
