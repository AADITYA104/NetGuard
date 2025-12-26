# Virtual SOC Lab - Setup Guide

This guide details how to set up the Virtual Network Lab and run the SOC components.

## 1. Network Architecture (Hybrid Setup)

The lab consists of 2 Virtual Machines (VMs) running on your **MacBook Air (Host)**. The SOC components run native on macOS.

| Role | Device | IP Address | Software |
|------|--------|------------|----------|
| **Attacker** | VM: Kali Linux | `192.168.56.10` | Nmap, Hydra, Hping3 |
| **Victim** | VM: Ubuntu Server | `192.168.56.20` | Apache, FTP, SSH |
| **IDS / SOC** | **Host: MacBook Air** | `192.168.56.1` | **FastAPI Engine**, **Streamlit Dashboard**, **Extractor** |

**Traffic Flow:**
1.  Attacker sends packets to Victim.
2.  **Extractor** (running on Mac) listens on the `vboxnet0` interface to capture this traffic.
    *   *Note: Ensure VirtualBox network is set to "Host-Only Adapter".*
3.  **Extractor** sends features to **IDS Engine** (localhost:8000).
4.  **Dashboard** (localhost:8501) visualizes the alerts.


## 2. VirtualBox Setup

For the **Attacker** and **Victim** VMs:

1.  **Network Adapter**:
    *   Attached to: **Host-Only Adapter** (check name, usually `vboxnet0` on Mac).
    *   **Promiscuous Mode**: **Allow All** (Essential for sniffing).
2.  **IP Configuration**:
    *   Configure static IPs (`.10` and `.20`) inside the VMs.
    *   Gateway: `192.168.56.1` (Your Mac).

## 3. Deployment - Step by Step

### Step 1: Start the IDS Engine (on Mac)
Open a terminal on your Mac in the project folder:
```bash
python3 virtual_soc/ids_engine.py
```

### Step 2: Start the Dashboard (on Mac)
Open a new terminal tab:
```bash
streamlit run virtual_soc/dashboard.py
```

### Step 3: Start Traffic Sniffer (on Mac)
You need to identify your Host-Only interface (usually `vboxnet0`).
```bash
ifconfig | grep vboxnet
# Run sniffer on that interface (sudo required for packet capture)
sudo python3 virtual_soc/extractor.py vboxnet0
```
*Note: If `vboxnet0` doesn't see traffic, try using "Bridged Adapter" for VMs and sniffing your main Wi-Fi adapter (`en0`), but Host-Only is safer/cleaner.*

## 4. Attack Scenarios

Run these commands from the **Attacker VM (192.168.56.10)** against the **Victim (192.168.56.20)**.

### Scenario A: Port Scanning (Reconnaissance)
```bash
# Stealth SYN Scan
nmap -sS -p 1-1000 192.168.56.20
```
**Expected Result**: Dashboard shows `PortScan` alerts (Destination Port varying, high IAT).

### Scenario B: Denial of Service (DoS Hulk)
```bash
# Flood port 80 (HTTP)
sudo hping3 -S -p 80 --flood 192.168.56.20
```
**Expected Result**: Dashboard shows `DoS Hulk` or `DDoS` alerts (High packet rate, low IAT).

### Scenario C: SSH Brute Force
```bash
# Attempt to brute force SSH login
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.56.20
```
**Expected Result**: Dashboard shows `SSH-Patator` or `Brute Force` alerts (Port 22, varying IAT).
