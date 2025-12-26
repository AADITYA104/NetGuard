"""
Test with REAL attack patterns from demo_flows.csv
"""
import requests
import pandas as pd

IDS_API_URL = "http://localhost:8000/predict"

# Load demo flows
df = pd.read_csv("ids_demo/demo_flows.csv")

print("\n" + "="*60)
print("   TESTING WITH REAL CIC-IDS-2017 PATTERNS")
print("="*60)

# Get one of each label type
labels_to_test = ["BENIGN", "PortScan", "DDoS", "SSH-Patator", "DoS Hulk"]

for label in labels_to_test:
    sample = df[df["Label"] == label].iloc[0]
    features = sample.drop("Label").to_dict()
    
    print(f"\n{'='*50}")
    print(f"Testing REAL {label} pattern from dataset")
    print(f"{'='*50}")
    
    try:
        resp = requests.post(IDS_API_URL, json={"features": features}, timeout=5)
        if resp.status_code == 200:
            result = resp.json()
            match = "MATCH" if result["label"] == label else "MISMATCH"
            print(f"  Expected: {label}")
            print(f"  Got:      {result['label']} ({result['confidence']:.4f}) [{match}]")
        else:
            print(f"  ERROR: {resp.status_code}")
    except Exception as e:
        print(f"  ERROR: {e}")

print("\n" + "="*60)
