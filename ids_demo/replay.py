"""
Traffic Replay Script for IDS Demo
===================================
Replays sample network flows with narration for demo presentations
"""

import pandas as pd
import requests
import time
import sys
import os
import random

# Configuration
API_URL = "http://127.0.0.1:5000/api/predict"
RESET_URL = "http://127.0.0.1:5000/api/reset"
DEMO_FLOWS_FILE = os.path.join(os.path.dirname(__file__), "demo_flows.csv")
DELAY_BETWEEN_FLOWS = 0.15  # 150ms between flows

# Simulated IP pools
INTERNAL_IPS = ["192.168.1.10", "192.168.1.15", "192.168.1.20", "192.168.1.25", "10.0.0.5"]
EXTERNAL_IPS = ["45.33.32.156", "185.199.108.153", "93.184.216.34", "104.21.56.70"]
ATTACKER_IPS = ["45.227.255.206", "185.220.101.33", "91.121.87.18", "193.27.228.63"]


def print_banner(text, char="="):
    """Print a formatted banner"""
    print()
    print(char * 60)
    print(f"  {text}")
    print(char * 60)


def print_phase(phase_num, title, description):
    """Print phase information with narration"""
    print()
    print(f"{'─' * 60}")
    print(f"📍 PHASE {phase_num}: {title}")
    print(f"{'─' * 60}")
    print(f"   {description}")
    print()
    input("   Press ENTER to start this phase...")
    print()


def get_ips_for_label(label):
    """Generate appropriate IPs based on attack type"""
    if label == "BENIGN":
        return random.choice(INTERNAL_IPS), random.choice(EXTERNAL_IPS)
    else:
        return random.choice(ATTACKER_IPS), random.choice(INTERNAL_IPS)


def replay_flows(filepath=DEMO_FLOWS_FILE, delay=DELAY_BETWEEN_FLOWS, narrated=True):
    """
    Replay flows from CSV file to the IDS API
    
    Args:
        filepath: Path to CSV file with flows
        delay: Seconds to wait between flows
        narrated: Whether to include phase narration
    """
    print_banner("🛡️  REAL-TIME IDS DEMONSTRATION")
    
    # Load demo flows
    if not os.path.exists(filepath):
        print(f"❌ Error: Demo flows file not found: {filepath}")
        sys.exit(1)
    
    df = pd.read_csv(filepath)
    total_flows = len(df)
    
    print(f"\n📁 Loaded {total_flows} flows from {os.path.basename(filepath)}")
    print(f"⏱️  Delay between flows: {delay * 1000:.0f}ms")
    
    # Check if server is running
    try:
        requests.get("http://127.0.0.1:5000/api/stats", timeout=2)
    except requests.exceptions.ConnectionError:
        print("\n❌ Error: Cannot connect to Flask server")
        print("   Please start the server first: python app.py")
        sys.exit(1)
    
    print("✅ Connected to IDS server\n")
    
    # Reset stats for clean demo
    if narrated:
        reset = input("🔄 Reset stats before demo? (y/n): ").lower().strip()
        if reset == 'y':
            requests.post(RESET_URL)
            print("   Stats reset!\n")
    
    # Identify phases in the data
    labels = df['Label'].tolist()
    
    # Find phase boundaries
    phases = []
    current_label = labels[0]
    start_idx = 0
    
    for i, label in enumerate(labels):
        if label != current_label:
            phases.append({
                'start': start_idx,
                'end': i - 1,
                'label': current_label,
                'count': i - start_idx
            })
            current_label = label
            start_idx = i
    
    # Add final phase
    phases.append({
        'start': start_idx,
        'end': len(labels) - 1,
        'label': current_label,
        'count': len(labels) - start_idx
    })
    
    # Phase descriptions
    phase_descriptions = {
        'BENIGN': "Normal network traffic - web browsing, file transfers, routine operations.",
        'PortScan': "🔍 RECONNAISSANCE PHASE: Attacker scanning for open ports and services.",
        'DDoS': "💥 ATTACK PHASE: Distributed Denial of Service flood targeting servers.",
        'DoS Hulk': "🦠 ATTACK PHASE: DoS Hulk generating high-volume HTTP requests.",
        'DoS GoldenEye': "⚡ ATTACK PHASE: GoldenEye HTTP DoS attack in progress.",
    }
    
    # Tracking
    correct = 0
    total = 0
    errors = 0
    
    # Process each phase
    for phase_idx, phase in enumerate(phases):
        label = phase['label']
        count = phase['count']
        
        if narrated:
            desc = phase_descriptions.get(label, f"Traffic type: {label}")
            phase_title = "NORMAL TRAFFIC" if label == "BENIGN" else f"{label.upper()} ATTACK"
            print_phase(phase_idx + 1, phase_title, desc)
        
        # Replay flows in this phase
        for i in range(phase['start'], phase['end'] + 1):
            row = df.iloc[i]
            features = row.drop("Label").to_dict()
            true_label = row["Label"]
            
            # Convert any NaN values
            features = {k: (0 if pd.isna(v) else v) for k, v in features.items()}
            
            # Generate IPs
            src_ip, dst_ip = get_ips_for_label(true_label)
            
            # Send to prediction API
            payload = {
                "features": features,
                "true_label": true_label,
                "src_ip": src_ip,
                "dst_ip": dst_ip
            }
            
            try:
                response = requests.post(API_URL, json=payload, timeout=5)
                result = response.json()
                
                if "error" in result:
                    print(f"  ⚠️  Error: {result['error'][:40]}")
                    errors += 1
                else:
                    total += 1
                    is_attack = result.get("is_attack", False)
                    pred_label = result.get("label", "?")
                    confidence = result.get("prob", 0)
                    severity = result.get("severity", "?")
                    
                    is_correct = pred_label == true_label
                    if is_correct:
                        correct += 1
                    
                    symbol = "🚨" if is_attack else "✅"
                    severity_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "none": "⚪"}.get(severity, "⚫")
                    
                    # Compact output
                    flow_num = i + 1
                    acc = (correct / total * 100) if total > 0 else 0
                    print(f"  [{flow_num:3}/{total_flows}] {symbol} {pred_label:15} {severity_icon} {severity:8} | {confidence*100:5.1f}% | Acc: {acc:5.1f}%")
                    
            except requests.exceptions.RequestException as e:
                print(f"  ⚠️  Network error: {str(e)[:30]}")
                errors += 1
            
            time.sleep(delay)
        
        if narrated and phase_idx < len(phases) - 1:
            print(f"\n  ✓ Phase complete: {count} flows processed")
    
    # Summary
    print_banner("📊 DEMONSTRATION COMPLETE")
    print(f"\n   📈 Statistics:")
    print(f"   {'─' * 40}")
    print(f"   Total Flows Processed:  {total}")
    print(f"   Correct Predictions:    {correct}")
    print(f"   Overall Accuracy:       {(correct/total*100):.1f}%" if total > 0 else "N/A")
    if errors > 0:
        print(f"   ⚠️  Errors:              {errors}")
    print(f"   {'─' * 40}")
    
    # Per-phase summary
    print(f"\n   📋 Detection Summary:")
    for phase in phases:
        icon = "🚨" if phase['label'] != "BENIGN" else "✅"
        print(f"   {icon} {phase['label']}: {phase['count']} flows")
    
    print_banner("END OF DEMO")


def quick_replay(filepath=DEMO_FLOWS_FILE, delay=0.1):
    """Quick replay without narration for testing"""
    replay_flows(filepath, delay, narrated=False)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "--quick":
            quick_replay()
        else:
            replay_flows(sys.argv[1])
    else:
        replay_flows()
