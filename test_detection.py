"""
Test script to verify the IDS model can detect attacks.
Sends synthetic attack patterns directly to the API.
"""
import requests

IDS_API_URL = "http://localhost:8000/predict"

# Test 1: PortScan pattern (many different destination ports, low packet counts)
portscan_flow = {
    "features": {
        "Destination Port": 22,
        "Flow Duration": 100000,  # Short duration
        "Total Fwd Packets": 2,
        "Total Backward Packets": 1,
        "Total Length of Fwd Packets": 120,
        "Total Length of Bwd Packets": 60,
        "Fwd Packet Length Max": 60,
        "Fwd Packet Length Min": 60,
        "Fwd Packet Length Mean": 60,
        "Fwd Packet Length Std": 0,
        "Flow Bytes/s": 1800000,  # High bytes/s
        "Flow Packets/s": 30000,  # High packets/s
        "Flow IAT Mean": 50000,
        "Flow IAT Std": 10000,
        "Flow IAT Max": 60000,
        "Flow IAT Min": 40000,
        "Fwd IAT Total": 100000,
        "Fwd IAT Mean": 50000,
        "Fwd IAT Std": 0,
        "Fwd IAT Max": 50000,
        "Fwd IAT Min": 50000,
        "Bwd IAT Total": 0,
        "Bwd IAT Mean": 0,
        "Bwd IAT Std": 0,
        "Bwd IAT Max": 0,
        "Bwd IAT Min": 0,
        "Fwd Header Length": 40,
        "Bwd Header Length": 20,
        "Max Packet Length": 60,
        "Min Packet Length": 60,
        "Packet Length Mean": 60,
        "Packet Length Std": 0,
        "Packet Length Variance": 0,
        "Average Packet Size": 60,
        "Subflow Fwd Packets": 2,
        "Subflow Fwd Bytes": 120,
        "Subflow Bwd Packets": 1,
        "Subflow Bwd Bytes": 60,
        "Init_Win_bytes_forward": 8192,
        "Init_Win_bytes_backward": 0,
        "act_data_pkt_fwd": 2,
        "min_seg_size_forward": 20,
        "Active Mean": 0,
        "Active Std": 0,
        "Active Max": 0,
        "Active Min": 0,
        "Idle Mean": 0,
        "Idle Std": 0,
        "Idle Max": 0,
        "Idle Min": 0,
        "PSH Flag Count": 0,
        "Fwd Header Length.1": 40,
        "Bwd Packet Length Mean": 60,
        "Bwd Packet Length Min": 60,
        "Bwd Packets/s": 10000,
    }
}

# Test 2: DDoS pattern (high packet rate, many packets)
ddos_flow = {
    "features": {
        "Destination Port": 80,
        "Flow Duration": 1000000,
        "Total Fwd Packets": 1000,
        "Total Backward Packets": 500,
        "Total Length of Fwd Packets": 60000,
        "Total Length of Bwd Packets": 30000,
        "Fwd Packet Length Max": 60,
        "Fwd Packet Length Min": 60,
        "Fwd Packet Length Mean": 60,
        "Fwd Packet Length Std": 0,
        "Flow Bytes/s": 90000000,  # Very high
        "Flow Packets/s": 1500000,  # Very high
        "Flow IAT Mean": 667,  # Very low IAT
        "Flow IAT Std": 100,
        "Flow IAT Max": 1000,
        "Flow IAT Min": 500,
        "Fwd IAT Total": 666667,
        "Fwd IAT Mean": 667,
        "Fwd IAT Std": 100,
        "Fwd IAT Max": 1000,
        "Fwd IAT Min": 500,
        "Bwd IAT Total": 500000,
        "Bwd IAT Mean": 1000,
        "Bwd IAT Std": 100,
        "Bwd IAT Max": 1200,
        "Bwd IAT Min": 800,
        "Fwd Header Length": 20000,
        "Bwd Header Length": 10000,
        "Max Packet Length": 60,
        "Min Packet Length": 60,
        "Packet Length Mean": 60,
        "Packet Length Std": 0,
        "Packet Length Variance": 0,
        "Average Packet Size": 60,
        "Subflow Fwd Packets": 1000,
        "Subflow Fwd Bytes": 60000,
        "Subflow Bwd Packets": 500,
        "Subflow Bwd Bytes": 30000,
        "Init_Win_bytes_forward": 8192,
        "Init_Win_bytes_backward": 8192,
        "act_data_pkt_fwd": 1000,
        "min_seg_size_forward": 20,
        "Active Mean": 0,
        "Active Std": 0,
        "Active Max": 0,
        "Active Min": 0,
        "Idle Mean": 0,
        "Idle Std": 0,
        "Idle Max": 0,
        "Idle Min": 0,
        "PSH Flag Count": 500,
        "Fwd Header Length.1": 20000,
        "Bwd Packet Length Mean": 60,
        "Bwd Packet Length Min": 60,
        "Bwd Packets/s": 500000,
    }
}

# Test 3: Normal BENIGN traffic
benign_flow = {
    "features": {
        "Destination Port": 443,
        "Flow Duration": 5000000,  # Long duration
        "Total Fwd Packets": 10,
        "Total Backward Packets": 8,
        "Total Length of Fwd Packets": 1500,
        "Total Length of Bwd Packets": 12000,
        "Fwd Packet Length Max": 200,
        "Fwd Packet Length Min": 100,
        "Fwd Packet Length Mean": 150,
        "Fwd Packet Length Std": 30,
        "Flow Bytes/s": 2700,  # Normal rate
        "Flow Packets/s": 3.6,  # Normal rate
        "Flow IAT Mean": 300000,  # Normal IAT
        "Flow IAT Std": 50000,
        "Flow IAT Max": 400000,
        "Flow IAT Min": 200000,
        "Fwd IAT Total": 2700000,
        "Fwd IAT Mean": 300000,
        "Fwd IAT Std": 50000,
        "Fwd IAT Max": 400000,
        "Fwd IAT Min": 200000,
        "Bwd IAT Total": 2100000,
        "Bwd IAT Mean": 300000,
        "Bwd IAT Std": 50000,
        "Bwd IAT Max": 400000,
        "Bwd IAT Min": 200000,
        "Fwd Header Length": 200,
        "Bwd Header Length": 160,
        "Max Packet Length": 1500,
        "Min Packet Length": 100,
        "Packet Length Mean": 750,
        "Packet Length Std": 500,
        "Packet Length Variance": 250000,
        "Average Packet Size": 750,
        "Subflow Fwd Packets": 10,
        "Subflow Fwd Bytes": 1500,
        "Subflow Bwd Packets": 8,
        "Subflow Bwd Bytes": 12000,
        "Init_Win_bytes_forward": 65535,
        "Init_Win_bytes_backward": 65535,
        "act_data_pkt_fwd": 10,
        "min_seg_size_forward": 20,
        "Active Mean": 100000,
        "Active Std": 10000,
        "Active Max": 120000,
        "Active Min": 80000,
        "Idle Mean": 200000,
        "Idle Std": 20000,
        "Idle Max": 250000,
        "Idle Min": 150000,
        "PSH Flag Count": 5,
        "Fwd Header Length.1": 200,
        "Bwd Packet Length Mean": 1500,
        "Bwd Packet Length Min": 1000,
        "Bwd Packets/s": 1.6,
    }
}

def test_flow(name, flow_data):
    print(f"\n{'='*50}")
    print(f"Testing: {name}")
    print(f"{'='*50}")
    try:
        resp = requests.post(IDS_API_URL, json=flow_data, timeout=5)
        if resp.status_code == 200:
            result = resp.json()
            print(f"  Label: {result['label']}")
            print(f"  Confidence: {result['confidence']:.4f}")
            print(f"  Is Malicious: {result['is_malicious']}")
            return result
        else:
            print(f"  ERROR: Status code {resp.status_code}")
            print(f"  Response: {resp.text}")
    except Exception as e:
        print(f"  ERROR: {e}")
    return None

if __name__ == "__main__":
    print("\n" + "="*60)
    print("   IDS MODEL DETECTION TEST")
    print("="*60)
    print("\nMake sure ids_engine.py is running on port 8000!")
    
    # First check if API is up
    try:
        resp = requests.get("http://localhost:8000/", timeout=2)
        print(f"\nAPI Status: {resp.json()}")
    except:
        print("\n[ERROR] Cannot connect to API! Is ids_engine.py running?")
        exit(1)
    
    # Run tests
    test_flow("PortScan Pattern", portscan_flow)
    test_flow("DDoS Pattern", ddos_flow)
    test_flow("Benign Traffic", benign_flow)
    
    print("\n" + "="*60)
    print("Test complete. If all show BENIGN, there may be a model issue.")
    print("="*60)
