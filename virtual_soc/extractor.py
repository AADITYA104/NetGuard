"""
Real-Time Network Feature Extractor for CIC-IDS-2017 Compatible Detection
Extracts all 70+ features matching the CIC-IDS-2017 dataset format
"""
import sys
import time
import requests
import numpy as np
import threading
from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict

# Configuration
IDS_API_URL = "http://localhost:8000/predict"
INTERFACE = "Ethernet 2"  # Windows VirtualBox Host-Only Adapter
FLOW_TIMEOUT = 2.0  # Send flow after 2 seconds of inactivity
MIN_PACKETS = 2  # Minimum packets before sending
DEBUG = True
PACKET_COUNT = 0  # Global packet counter for debugging

class CICFlow:
    """CIC-IDS-2017 compatible flow feature extractor."""
    
    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        
        # Timing
        self.start_time = time.time()
        self.last_seen = time.time()
        
        # Packet counts
        self.fwd_packets = 0
        self.bwd_packets = 0
        
        # Byte counts
        self.fwd_bytes = 0
        self.bwd_bytes = 0
        
        # Packet lengths
        self.fwd_pkt_lengths = []
        self.bwd_pkt_lengths = []
        self.all_pkt_lengths = []
        
        # Inter-arrival times (microseconds)
        self.flow_iat = []
        self.fwd_iat = []
        self.bwd_iat = []
        
        # Last packet times
        self.last_fwd_time = None
        self.last_bwd_time = None
        self.last_pkt_time = None
        
        # TCP Flags
        self.fin_count = 0
        self.syn_count = 0
        self.rst_count = 0
        self.psh_count = 0
        self.ack_count = 0
        self.urg_count = 0
        self.cwe_count = 0
        self.ece_count = 0
        self.fwd_psh_count = 0
        self.fwd_urg_count = 0
        
        # TCP Window sizes
        self.init_win_fwd = -1
        self.init_win_bwd = -1
        
        # Header lengths
        self.fwd_header_len = 0
        self.bwd_header_len = 0
        
        # Active/Idle times
        self.active_times = []
        self.idle_times = []
        self.current_active_start = None
        
        # Data packets
        self.fwd_data_pkts = 0
        self.min_seg_size_fwd = 0

    def add_packet(self, packet, direction, pkt_time):
        """Add a packet to the flow."""
        current_time = pkt_time
        pkt_len = len(packet)
        self.last_seen = time.time()
        
        # Flow IAT
        if self.last_pkt_time is not None:
            iat = (current_time - self.last_pkt_time) * 1_000_000
            self.flow_iat.append(iat)
            
            if iat > 1_000_000:  # Idle threshold
                if self.current_active_start is not None:
                    self.active_times.append((current_time - self.current_active_start) * 1_000_000)
                self.idle_times.append(iat)
                self.current_active_start = current_time
            else:
                if self.current_active_start is None:
                    self.current_active_start = self.last_pkt_time
        else:
            self.current_active_start = current_time
            
        self.last_pkt_time = current_time
        self.all_pkt_lengths.append(pkt_len)
        
        if direction == "fwd":
            self.fwd_packets += 1
            self.fwd_bytes += pkt_len
            self.fwd_pkt_lengths.append(pkt_len)
            
            if self.last_fwd_time is not None:
                self.fwd_iat.append((current_time - self.last_fwd_time) * 1_000_000)
            self.last_fwd_time = current_time
            
            if pkt_len > 0:
                self.fwd_data_pkts += 1
                if self.min_seg_size_fwd == 0 or pkt_len < self.min_seg_size_fwd:
                    self.min_seg_size_fwd = pkt_len
        else:
            self.bwd_packets += 1
            self.bwd_bytes += pkt_len
            self.bwd_pkt_lengths.append(pkt_len)
            
            if self.last_bwd_time is not None:
                self.bwd_iat.append((current_time - self.last_bwd_time) * 1_000_000)
            self.last_bwd_time = current_time
        
        # TCP features
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            flags = str(tcp.flags)
            
            if 'F' in flags: self.fin_count += 1
            if 'S' in flags: self.syn_count += 1
            if 'R' in flags: self.rst_count += 1
            if 'P' in flags: 
                self.psh_count += 1
                if direction == "fwd": self.fwd_psh_count += 1
            if 'A' in flags: self.ack_count += 1
            if 'U' in flags: 
                self.urg_count += 1
                if direction == "fwd": self.fwd_urg_count += 1
            if 'C' in flags: self.cwe_count += 1
            if 'E' in flags: self.ece_count += 1
            
            if direction == "fwd" and self.init_win_fwd == -1:
                self.init_win_fwd = tcp.window
            elif direction == "bwd" and self.init_win_bwd == -1:
                self.init_win_bwd = tcp.window
            
            header_len = tcp.dataofs * 4 if tcp.dataofs else 20
            if direction == "fwd":
                self.fwd_header_len += header_len
            else:
                self.bwd_header_len += header_len

    def _safe(self, arr, func, default=0):
        return func(arr) if len(arr) > 0 else default

    def get_features(self):
        """Extract ALL 70+ CIC-IDS-2017 features."""
        duration = (self.last_seen - self.start_time) * 1_000_000
        if duration == 0: duration = 1
        
        total_pkts = self.fwd_packets + self.bwd_packets
        total_bytes = self.fwd_bytes + self.bwd_bytes
        
        return {
            "Destination Port": self.dst_port,
            "Flow Duration": duration,
            "Total Fwd Packets": self.fwd_packets,
            "Total Backward Packets": self.bwd_packets,
            "Total Length of Fwd Packets": self.fwd_bytes,
            "Total Length of Bwd Packets": self.bwd_bytes,
            "Fwd Packet Length Max": self._safe(self.fwd_pkt_lengths, max),
            "Fwd Packet Length Min": self._safe(self.fwd_pkt_lengths, min),
            "Fwd Packet Length Mean": self._safe(self.fwd_pkt_lengths, np.mean),
            "Fwd Packet Length Std": self._safe(self.fwd_pkt_lengths, np.std),
            "Bwd Packet Length Max": self._safe(self.bwd_pkt_lengths, max),
            "Bwd Packet Length Min": self._safe(self.bwd_pkt_lengths, min),
            "Bwd Packet Length Mean": self._safe(self.bwd_pkt_lengths, np.mean),
            "Bwd Packet Length Std": self._safe(self.bwd_pkt_lengths, np.std),
            "Flow Bytes/s": total_bytes / (duration / 1_000_000) if duration > 0 else 0,
            "Flow Packets/s": total_pkts / (duration / 1_000_000) if duration > 0 else 0,
            "Flow IAT Mean": self._safe(self.flow_iat, np.mean),
            "Flow IAT Std": self._safe(self.flow_iat, np.std),
            "Flow IAT Max": self._safe(self.flow_iat, max),
            "Flow IAT Min": self._safe(self.flow_iat, min),
            "Fwd IAT Total": sum(self.fwd_iat) if self.fwd_iat else 0,
            "Fwd IAT Mean": self._safe(self.fwd_iat, np.mean),
            "Fwd IAT Std": self._safe(self.fwd_iat, np.std),
            "Fwd IAT Max": self._safe(self.fwd_iat, max),
            "Fwd IAT Min": self._safe(self.fwd_iat, min),
            "Bwd IAT Total": sum(self.bwd_iat) if self.bwd_iat else 0,
            "Bwd IAT Mean": self._safe(self.bwd_iat, np.mean),
            "Bwd IAT Std": self._safe(self.bwd_iat, np.std),
            "Bwd IAT Max": self._safe(self.bwd_iat, max),
            "Bwd IAT Min": self._safe(self.bwd_iat, min),
            "Fwd PSH Flags": self.fwd_psh_count,
            "Fwd URG Flags": self.fwd_urg_count,
            "Fwd Header Length": self.fwd_header_len,
            "Bwd Header Length": self.bwd_header_len,
            "Fwd Packets/s": self.fwd_packets / (duration / 1_000_000) if duration > 0 else 0,
            "Bwd Packets/s": self.bwd_packets / (duration / 1_000_000) if duration > 0 else 0,
            "Min Packet Length": self._safe(self.all_pkt_lengths, min),
            "Max Packet Length": self._safe(self.all_pkt_lengths, max),
            "Packet Length Mean": self._safe(self.all_pkt_lengths, np.mean),
            "Packet Length Std": self._safe(self.all_pkt_lengths, np.std),
            "Packet Length Variance": self._safe(self.all_pkt_lengths, np.var),
            "FIN Flag Count": self.fin_count,
            "SYN Flag Count": self.syn_count,
            "RST Flag Count": self.rst_count,
            "PSH Flag Count": self.psh_count,
            "ACK Flag Count": self.ack_count,
            "URG Flag Count": self.urg_count,
            "CWE Flag Count": self.cwe_count,
            "ECE Flag Count": self.ece_count,
            "Down/Up Ratio": self.bwd_packets / self.fwd_packets if self.fwd_packets > 0 else 0,
            "Average Packet Size": total_bytes / total_pkts if total_pkts > 0 else 0,
            "Avg Fwd Segment Size": self._safe(self.fwd_pkt_lengths, np.mean),
            "Avg Bwd Segment Size": self._safe(self.bwd_pkt_lengths, np.mean),
            "Fwd Header Length.1": self.fwd_header_len,
            "Subflow Fwd Packets": self.fwd_packets,
            "Subflow Fwd Bytes": self.fwd_bytes,
            "Subflow Bwd Packets": self.bwd_packets,
            "Subflow Bwd Bytes": self.bwd_bytes,
            "Init_Win_bytes_forward": self.init_win_fwd,
            "Init_Win_bytes_backward": self.init_win_bwd,
            "act_data_pkt_fwd": self.fwd_data_pkts,
            "min_seg_size_forward": self.min_seg_size_fwd if self.min_seg_size_fwd > 0 else 20,
            "Active Mean": self._safe(self.active_times, np.mean),
            "Active Std": self._safe(self.active_times, np.std),
            "Active Max": self._safe(self.active_times, max),
            "Active Min": self._safe(self.active_times, min),
            "Idle Mean": self._safe(self.idle_times, np.mean),
            "Idle Std": self._safe(self.idle_times, np.std),
            "Idle Max": self._safe(self.idle_times, max),
            "Idle Min": self._safe(self.idle_times, min),
        }


active_flows = {}

def get_flow_key(src_ip, src_port, dst_ip, dst_port):
    return tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)]))

def send_flow_to_api(flow_key):
    flow = active_flows.pop(flow_key, None)
    if not flow or flow.fwd_packets + flow.bwd_packets < MIN_PACKETS:
        return
    
    features = flow.get_features()
    # Add IP addresses for the API to use in logging/response
    features["src_ip"] = flow.src_ip
    features["dst_ip"] = flow.dst_ip
    
    duration = features['Flow Duration']
    
    if DEBUG:
        print(f"[SEND] {flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port}")
        print(f"       {flow.fwd_packets} fwd, {flow.bwd_packets} bwd, {duration:.0f}us")
        print(f"       SYN:{features['SYN Flag Count']} RST:{features['RST Flag Count']} ACK:{features['ACK Flag Count']}")
    
    try:
        resp = requests.post(IDS_API_URL, json={"features": features}, timeout=2)
        if resp.status_code == 200:
            result = resp.json()
            method = result.get('detection_method', 'unknown')
            if result['is_malicious']:
                print(f"\n{'='*60}")
                print(f"[!!!ALERT!!!] {result['label']} DETECTED!")
                print(f"  Source: {flow.src_ip}:{flow.src_port}")
                print(f"  Target: {flow.dst_ip}:{flow.dst_port}")
                print(f"  Confidence: {result['confidence']:.2f}")
                print(f"  Detection: {method}")
                print(f"{'='*60}\n")
            else:
                print(f"[OK] BENIGN ({result['confidence']:.2f}) [{method}]")
        else:
            print(f"[ERR] API status {resp.status_code}")
    except Exception as e:
        print(f"[ERR] {e}")

def flow_timeout_checker():
    while True:
        time.sleep(1)
        now = time.time()
        expired = [k for k, f in list(active_flows.items()) if now - f.last_seen > FLOW_TIMEOUT]
        for key in expired:
            send_flow_to_api(key)

def packet_handler(packet):
    global PACKET_COUNT
    
    if not packet.haslayer(IP):
        return
    
    PACKET_COUNT += 1
    
    ip = packet[IP]
    src_ip, dst_ip = ip.src, ip.dst
    pkt_time = float(packet.time)
    
    if packet.haslayer(TCP):
        src_port, dst_port = packet[TCP].sport, packet[TCP].dport
        proto = "TCP"
    elif packet.haslayer(UDP):
        src_port, dst_port = packet[UDP].sport, packet[UDP].dport
        proto = "UDP"
    else:
        return
    
    # Debug: show every 10th packet
    if DEBUG and PACKET_COUNT % 10 == 0:
        print(f"[PKT #{PACKET_COUNT}] {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({proto})")
    
    flow_key = get_flow_key(src_ip, src_port, dst_ip, dst_port)
    
    if flow_key not in active_flows:
        active_flows[flow_key] = CICFlow(src_ip, dst_ip, src_port, dst_port, proto)
        if DEBUG:
            print(f"[NEW FLOW] {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
    
    flow = active_flows[flow_key]
    direction = "fwd" if (src_ip, src_port) == (flow.src_ip, flow.src_port) else "bwd"
    flow.add_packet(packet, direction, pkt_time)
    
    # PortScan detection: send after 2 packets with SYN
    if flow.fwd_packets + flow.bwd_packets == 2 and flow.syn_count >= 1:
        send_flow_to_api(flow_key)

def main():
    global PACKET_COUNT
    
    iface = sys.argv[1] if len(sys.argv) > 1 else INTERFACE
    
    print("="*60)
    print("  CIC-IDS-2017 Real-Time Feature Extractor (70+ Features)")
    print("="*60)
    print(f"[*] Interface: {iface}")
    print(f"[*] API: {IDS_API_URL}")
    print(f"[*] Timeout: {FLOW_TIMEOUT}s | Min Packets: {MIN_PACKETS}")
    print("="*60)
    
    # Start timeout thread
    threading.Thread(target=flow_timeout_checker, daemon=True).start()
    print("[*] Timeout checker started")
    print("[*] Capturing packets... (Ctrl+C to stop)")
    print("[*] Waiting for traffic...\n")
    
    try:
        sniff(iface=iface, prn=packet_handler, store=0, filter="tcp or udp")
    except KeyboardInterrupt:
        print(f"\n[*] Stopped. Total packets: {PACKET_COUNT}")
        for key in list(active_flows.keys()):
            send_flow_to_api(key)
    except Exception as e:
        print(f"[FATAL] {e}")
        print("[TIP] Run as Administrator and check Npcap is installed")

if __name__ == "__main__":
    main()
