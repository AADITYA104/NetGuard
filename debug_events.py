"""Debug script to see what events are being captured"""
import requests
import json

events = requests.get('http://localhost:8000/events').json()
print(f"Total events: {len(events)}")
print()

for e in events[-10:]:
    label = e.get('label', '?')
    method = e.get('detection_method', '?')
    attack_prob = e.get('ml_attack_prob', 0)
    benign_prob = e.get('ml_benign_prob', 0)
    port = e.get('dst_port', 0)
    src = e.get('src_ip', '?')
    attack_type = e.get('attack_type', '')
    
    print(f"[{label}] Port:{port} | ML: ATTACK={attack_prob:.2%} BENIGN={benign_prob:.2%} | {method} | {src}")
    if attack_type:
        print(f"         Attack Type: {attack_type}")

print()
print("Stats:", requests.get('http://localhost:8000/stats').json())
