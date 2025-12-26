"""Debug script to see actual feature values being captured"""
import requests

# Get the last few events with full details
events = requests.get('http://localhost:8000/events').json()

if not events:
    print("No events found!")
else:
    # Get full flow details from the last event
    print(f"Total events: {len(events)}")
    print("\nLast 3 events with key features:")
    print("="*80)
    
    for e in events[-3:]:
        print(f"\nEvent at {e.get('timestamp', 'N/A')}")
        print(f"  Label: {e.get('label')} | Attack Type: {e.get('attack_type')}")
        print(f"  Source: {e.get('src_ip')} -> {e.get('dst_ip')}:{e.get('dst_port')}")
        print(f"  ML Attack Prob: {e.get('ml_attack_prob', 0):.2%}")
        print(f"  Detection Method: {e.get('detection_method')}")

# Let's also see the API health to understand model state
print("\n" + "="*80)
print("API Status:")
health = requests.get('http://localhost:8000/').json()
for k, v in health.items():
    print(f"  {k}: {v}")
