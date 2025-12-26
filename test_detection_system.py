"""
Test script to verify hybrid attack detection is working
"""
import requests
import json

API_URL = "http://localhost:8000"

print("="*70)
print("HYBRID IDS DETECTION TEST")
print("="*70)

# Test 1: API Health
print("\n[Test 1] API Health Check")
print("-"*50)
try:
    resp = requests.get(f"{API_URL}/", timeout=5)
    print(f"Status: {resp.status_code}")
    data = resp.json()
    print(f"Detection Mode: {data.get('detection_mode', 'unknown')}")
    print(f"Attack Classes: {len(data['classes'])} types")
except Exception as e:
    print(f"ERROR: {e}")
    print("Make sure to restart the IDS server!")
    exit(1)

# Test 2: PortScan pattern (should trigger rule-based detection)
print("\n[Test 2] PortScan Pattern (Rule-based)")
print("-"*50)
portscan = {
    "src_ip": "192.168.56.100",
    "dst_ip": "192.168.56.1",
    "Destination Port": 22,
    "Flow Duration": 50000,  # 50ms - very short
    "Total Fwd Packets": 2,
    "Total Backward Packets": 1,
    "SYN Flag Count": 1,
    "RST Flag Count": 1,
    "ACK Flag Count": 1,
    "Init_Win_bytes_forward": 1024,
    "Init_Win_bytes_backward": 0,
    "Fwd Packets/s": 40000,
    "Bwd Packets/s": 20000,
}
try:
    resp = requests.post(f"{API_URL}/predict", json={"features": portscan}, timeout=5)
    result = resp.json()
    print(f"Label: {result['label']}")
    print(f"Confidence: {result['confidence']:.4f}")
    print(f"Is Malicious: {result['is_malicious']}")
    print(f"Detection Method: {result.get('detection_method', 'N/A')}")
    print(f"Attack Probability: {result.get('attack_probability', 'N/A')}")
except Exception as e:
    print(f"ERROR: {e}")

# Test 3: SYN Scan (no response)
print("\n[Test 3] SYN Scan Pattern (No Response)")
print("-"*50)
syn_scan = {
    "src_ip": "192.168.56.100",
    "dst_ip": "192.168.56.1",
    "Destination Port": 80,
    "Flow Duration": 10000,
    "Total Fwd Packets": 1,
    "Total Backward Packets": 0,
    "SYN Flag Count": 1,
    "RST Flag Count": 0,
    "ACK Flag Count": 0,
    "Init_Win_bytes_forward": 1024,
    "Init_Win_bytes_backward": -1,
}
try:
    resp = requests.post(f"{API_URL}/predict", json={"features": syn_scan}, timeout=5)
    result = resp.json()
    print(f"Label: {result['label']}")
    print(f"Confidence: {result['confidence']:.4f}")
    print(f"Is Malicious: {result['is_malicious']}")
    print(f"Detection Method: {result.get('detection_method', 'N/A')}")
except Exception as e:
    print(f"ERROR: {e}")

# Test 4: DDoS pattern
print("\n[Test 4] DDoS/SYN Flood Pattern")
print("-"*50)
ddos = {
    "src_ip": "192.168.56.100",
    "dst_ip": "192.168.56.1",
    "Destination Port": 80,
    "Flow Duration": 1000000,
    "Total Fwd Packets": 1000,
    "Total Backward Packets": 10,
    "SYN Flag Count": 800,
    "RST Flag Count": 0,
    "ACK Flag Count": 10,
    "PSH Flag Count": 0,
    "Init_Win_bytes_forward": 1024,
    "Init_Win_bytes_backward": 0,
    "Fwd Packets/s": 1000,
    "Bwd Packets/s": 10,
    "Flow Packets/s": 1010,
}
try:
    resp = requests.post(f"{API_URL}/predict", json={"features": ddos}, timeout=5)
    result = resp.json()
    print(f"Label: {result['label']}")
    print(f"Confidence: {result['confidence']:.4f}")
    print(f"Is Malicious: {result['is_malicious']}")
    print(f"Detection Method: {result.get('detection_method', 'N/A')}")
except Exception as e:
    print(f"ERROR: {e}")

# Test 5: SSH Brute Force
print("\n[Test 5] SSH Brute Force Pattern")
print("-"*50)
ssh_brute = {
    "src_ip": "192.168.56.100",
    "dst_ip": "192.168.56.1",
    "Destination Port": 22,
    "Flow Duration": 5000000,
    "Total Fwd Packets": 50,
    "Total Backward Packets": 40,
    "SYN Flag Count": 10,
    "RST Flag Count": 5,
    "ACK Flag Count": 40,
    "PSH Flag Count": 30,
}
try:
    resp = requests.post(f"{API_URL}/predict", json={"features": ssh_brute}, timeout=5)
    result = resp.json()
    print(f"Label: {result['label']}")
    print(f"Confidence: {result['confidence']:.4f}")
    print(f"Is Malicious: {result['is_malicious']}")
    print(f"Detection Method: {result.get('detection_method', 'N/A')}")
except Exception as e:
    print(f"ERROR: {e}")

# Test 6: Normal Traffic (should be BENIGN)
print("\n[Test 6] Normal HTTPS Traffic (Should be BENIGN)")
print("-"*50)
normal = {
    "src_ip": "192.168.56.1",
    "dst_ip": "192.168.56.100",
    "Destination Port": 443,
    "Flow Duration": 5000000,
    "Total Fwd Packets": 10,
    "Total Backward Packets": 12,
    "Total Length of Fwd Packets": 2000,
    "Total Length of Bwd Packets": 15000,
    "SYN Flag Count": 1,
    "RST Flag Count": 0,
    "ACK Flag Count": 22,
    "PSH Flag Count": 15,
    "FIN Flag Count": 2,
    "Init_Win_bytes_forward": 65535,
    "Init_Win_bytes_backward": 65535,
    "Fwd Packets/s": 2,
    "Bwd Packets/s": 2.4,
}
try:
    resp = requests.post(f"{API_URL}/predict", json={"features": normal}, timeout=5)
    result = resp.json()
    print(f"Label: {result['label']}")
    print(f"Confidence: {result['confidence']:.4f}")
    print(f"Is Malicious: {result['is_malicious']}")
    print(f"Detection Method: {result.get('detection_method', 'N/A')}")
except Exception as e:
    print(f"ERROR: {e}")

# Test 7: Get Stats
print("\n[Test 7] Detection Statistics")
print("-"*50)
try:
    resp = requests.get(f"{API_URL}/stats", timeout=5)
    stats = resp.json()
    print(f"Total Events: {stats['total']}")
    print(f"Attacks Detected: {stats['attacks']}")
    print(f"Benign Traffic: {stats['benign']}")
    if stats.get('attack_types'):
        print(f"Attack Types: {stats['attack_types']}")
    if stats.get('detection_methods'):
        print(f"Detection Methods: {stats['detection_methods']}")
except Exception as e:
    print(f"ERROR: {e}")

print("\n" + "="*70)
print("TEST COMPLETE!")
print("="*70)
print("\nIf attacks are detected, the hybrid detection is working.")
print("Restart the IDS server with: python virtual_soc/ids_engine.py")
