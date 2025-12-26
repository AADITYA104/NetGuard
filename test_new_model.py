"""
Test the new high-accuracy (99.28%) model for attack detection
"""
import requests

API_URL = "http://localhost:8000"

print("="*70)
print("TESTING NEW 99.28% ACCURATE MODEL (Random Forest)")
print("="*70)

# Test 1: API Health
print("\n[Test 1] API Health Check")
print("-"*50)
try:
    resp = requests.get(f"{API_URL}/", timeout=5)
    data = resp.json()
    print(f"Status: {data['status']}")
    print(f"Version: {data['version']}")
    print(f"Model: {data['model']}")
    print(f"Classes: {data['classes']}")
    print(f"Features: {data['features']}")
except Exception as e:
    print(f"ERROR: {e}")
    exit(1)

# Test 2: DDoS Attack Pattern
print("\n[Test 2] DDoS Attack Pattern")
print("-"*50)
ddos_features = {
    "src_ip": "192.168.56.100",
    "dst_ip": "192.168.56.1",
    "Destination Port": 80,
    "Flow Duration": 1000000,  # 1 second
    "Total Fwd Packets": 1000,  # High packet count
    "Total Backward Packets": 10,  # Low response
    "Total Length of Fwd Packets": 500000,
    "Total Length of Bwd Packets": 5000,
    "Fwd Packet Length Max": 1500,
    "Fwd Packet Length Min": 100,
    "Fwd Packet Length Mean": 500,
    "Fwd Packet Length Std": 200,
    "Bwd Packet Length Max": 500,
    "Bwd Packet Length Min": 100,
    "Bwd Packet Length Mean": 500,
    "Bwd Packet Length Std": 100,
    "Flow Bytes/s": 505000,
    "Flow Packets/s": 1010,
    "Flow IAT Mean": 1000,
    "Flow IAT Std": 500,
    "Flow IAT Max": 5000,
    "Flow IAT Min": 100,
    "Fwd IAT Total": 990000,
    "Fwd IAT Mean": 990,
    "Fwd IAT Std": 300,
    "Fwd IAT Max": 5000,
    "Fwd IAT Min": 100,
    "Bwd IAT Total": 10000,
    "Bwd IAT Mean": 1000,
    "Bwd IAT Std": 500,
    "Bwd IAT Max": 5000,
    "Bwd IAT Min": 100,
    "Fwd PSH Flags": 500,
    "Fwd URG Flags": 0,
    "Fwd Header Length": 20000,
    "Bwd Header Length": 200,
    "Fwd Packets/s": 1000,
    "Bwd Packets/s": 10,
    "Min Packet Length": 100,
    "Max Packet Length": 1500,
    "Packet Length Mean": 500,
    "Packet Length Std": 200,
    "Packet Length Variance": 40000,
    "FIN Flag Count": 0,
    "SYN Flag Count": 500,
    "RST Flag Count": 0,
    "PSH Flag Count": 500,
    "ACK Flag Count": 10,
    "URG Flag Count": 0,
    "CWE Flag Count": 0,
    "ECE Flag Count": 0,
    "Down/Up Ratio": 0.01,
    "Average Packet Size": 500,
    "Avg Fwd Segment Size": 500,
    "Avg Bwd Segment Size": 500,
    "Subflow Fwd Packets": 1000,
    "Subflow Fwd Bytes": 500000,
    "Subflow Bwd Packets": 10,
    "Subflow Bwd Bytes": 5000,
    "Init_Win_bytes_forward": 65535,
    "Init_Win_bytes_backward": 0,
    "act_data_pkt_fwd": 1000,
    "min_seg_size_forward": 100,
    "Active Mean": 100000,
    "Active Std": 50000,
    "Active Max": 200000,
    "Active Min": 10000,
    "Idle Mean": 0,
    "Idle Std": 0,
    "Idle Max": 0,
    "Idle Min": 0,
}

try:
    resp = requests.post(f"{API_URL}/predict", json={"features": ddos_features}, timeout=5)
    result = resp.json()
    print(f"Prediction: {result['label']}")
    print(f"Confidence: {result['confidence']:.4f}")
    print(f"Is Attack: {result['is_malicious']}")
    print(f"Probabilities: {result.get('probabilities', 'N/A')}")
except Exception as e:
    print(f"ERROR: {e}")

# Test 3: PortScan Pattern  
print("\n[Test 3] PortScan Pattern")
print("-"*50)
portscan_features = {
    "src_ip": "192.168.56.100",
    "dst_ip": "192.168.56.1",
    "Destination Port": 22,
    "Flow Duration": 50000,  # Very short
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

try:
    resp = requests.post(f"{API_URL}/predict", json={"features": portscan_features}, timeout=5)
    result = resp.json()
    print(f"Prediction: {result['label']}")
    print(f"Confidence: {result['confidence']:.4f}")
    print(f"Is Attack: {result['is_malicious']}")
except Exception as e:
    print(f"ERROR: {e}")

# Test 4: Normal HTTPS Traffic
print("\n[Test 4] Normal HTTPS Traffic (should be BENIGN)")
print("-"*50)
normal_features = {
    "src_ip": "192.168.56.1",
    "dst_ip": "192.168.56.100",
    "Destination Port": 443,
    "Flow Duration": 5000000,  # 5 seconds
    "Total Fwd Packets": 10,
    "Total Backward Packets": 12,
    "Total Length of Fwd Packets": 2000,
    "Total Length of Bwd Packets": 15000,
    "Fwd Packet Length Max": 500,
    "Fwd Packet Length Min": 100,
    "Fwd Packet Length Mean": 200,
    "Fwd Packet Length Std": 100,
    "Bwd Packet Length Max": 1460,
    "Bwd Packet Length Min": 100,
    "Bwd Packet Length Mean": 1250,
    "Bwd Packet Length Std": 500,
    "Flow Bytes/s": 3400,
    "Flow Packets/s": 4.4,
    "Flow IAT Mean": 227272,
    "Flow IAT Std": 100000,
    "Flow IAT Max": 500000,
    "Flow IAT Min": 50000,
    "Fwd IAT Total": 2000000,
    "Fwd IAT Mean": 222222,
    "Fwd IAT Std": 100000,
    "Fwd IAT Max": 500000,
    "Fwd IAT Min": 50000,
    "Bwd IAT Total": 2200000,
    "Bwd IAT Mean": 200000,
    "Bwd IAT Std": 100000,
    "Bwd IAT Max": 500000,
    "Bwd IAT Min": 50000,
    "Fwd PSH Flags": 5,
    "Fwd URG Flags": 0,
    "Fwd Header Length": 200,
    "Bwd Header Length": 240,
    "Fwd Packets/s": 2,
    "Bwd Packets/s": 2.4,
    "Min Packet Length": 100,
    "Max Packet Length": 1460,
    "Packet Length Mean": 772,
    "Packet Length Std": 500,
    "Packet Length Variance": 250000,
    "FIN Flag Count": 2,
    "SYN Flag Count": 1,
    "RST Flag Count": 0,
    "PSH Flag Count": 10,
    "ACK Flag Count": 22,
    "URG Flag Count": 0,
    "CWE Flag Count": 0,
    "ECE Flag Count": 0,
    "Down/Up Ratio": 1.2,
    "Average Packet Size": 772,
    "Avg Fwd Segment Size": 200,
    "Avg Bwd Segment Size": 1250,
    "Subflow Fwd Packets": 10,
    "Subflow Fwd Bytes": 2000,
    "Subflow Bwd Packets": 12,
    "Subflow Bwd Bytes": 15000,
    "Init_Win_bytes_forward": 65535,
    "Init_Win_bytes_backward": 65535,
    "act_data_pkt_fwd": 8,
    "min_seg_size_forward": 100,
    "Active Mean": 2500000,
    "Active Std": 1000000,
    "Active Max": 4000000,
    "Active Min": 1000000,
    "Idle Mean": 0,
    "Idle Std": 0,
    "Idle Max": 0,
    "Idle Min": 0,
}

try:
    resp = requests.post(f"{API_URL}/predict", json={"features": normal_features}, timeout=5)
    result = resp.json()
    print(f"Prediction: {result['label']}")
    print(f"Confidence: {result['confidence']:.4f}")
    print(f"Is Attack: {result['is_malicious']}")
except Exception as e:
    print(f"ERROR: {e}")

# Test 5: Stats
print("\n[Test 5] Detection Statistics")
print("-"*50)
try:
    resp = requests.get(f"{API_URL}/stats", timeout=5)
    stats = resp.json()
    print(f"Total Events: {stats['total']}")
    print(f"Attacks: {stats['attacks']}")
    print(f"Benign: {stats['benign']}")
    print(f"Attack Rate: {stats.get('attack_percentage', 0):.1f}%")
except Exception as e:
    print(f"ERROR: {e}")

print("\n" + "="*70)
print("TEST COMPLETE!")
print("="*70)
