# 🛡️ Virtual SOC Setup Guide (Windows Edition)

This guide takes you from zero to a fully functional Threat Detection Lab on Windows using VirtualBox.

## 🏗️ Architecture Overview

The lab consists of three parts:
1.  **VirtualBox Host-Only Network**: A private network connecting your PC and the VMs.
2.  **The VMs**:
    *   **Attacker**: Kali Linux (IP: `192.168.56.10`)
    *   **Victim**: Ubuntu/Metasploitable (IP: `192.168.56.20`)
3.  **The SOC (Your PC)**:
    *   **IDS Engine**: Analyzes traffic.
    *   **Dashboard**: Displays alerts.
    *   **Sniffer**: Captures traffic from the "Host-Only Adapter".

---

## 🚀 Phase 1: VirtualBox Installation & Networking

### 1. Install VirtualBox
Download and install [Oracle VirtualBox](https://www.virtualbox.org/wiki/Downloads) for Windows.

### 2. Configure Host-Only Network
This allows your Windows PC to see the traffic between VMs.
1.  Open VirtualBox.
2.  Go to **File** -> **Tools** -> **Network Manager**.
3.  Click **Create** (or edit existing) to make a Host-Only Adapter.
    *   **Name**: It will likely be `VirtualBox Host-Only Ethernet Adapter`.
    *   **IPv4 Address**: `192.168.56.1`
    *   **IPv4 Network Mask**: `255.255.255.0`
    *   **DHCP Server**: *Disabled* (We will use static IPs).

---

## 💻 Phase 2: Virtual Machine Setup

You need two VMs. You can use standard ISOs to install them.

### VM 1: Attacker (Kali Linux)
1.  **Create New VM**: Type "Linux", Version "Debian (64-bit)".
2.  **Network Settings** (Crucial!):
    *   Go to **Settings** -> **Network** -> **Adapter 1**.
    *   Attached to: **Host-only Adapter**.
    *   Name: `VirtualBox Host-Only Ethernet Adapter`.
    *   **Promiscuous Mode**: **Allow All** (REQUIRED for the sniffer to work).
3.  **Boot & Configure IP**:
    *   Inside Kali, set a Static IP:
        ```bash
        # Edit /etc/network/interfaces or use UI
        address 192.168.56.10
        netmask 255.255.255.0
        gateway 192.168.56.1
        ```

### VM 2: Victim (Ubuntu / Metasploitable)
1.  **Create New VM**: Type "Linux", Version "Ubuntu (64-bit)".
2.  **Network Settings**:
    *   Attached to: **Host-only Adapter**.
    *   **Promiscuous Mode**: **Allow All**.
3.  **Boot & Configure IP**:
    *   Set Static IP: `192.168.56.20`.

---

## 🐍 Phase 3: Project Setup (Your Windows PC)

### 1. Install Dependencies
Open a terminal in the project folder and run:
```powershell
pip install -r requirements_soc.txt
```

### 2. Verify Network Interface
Run `ipconfig` in PowerShell and look for:
`Ethernet adapter VirtualBox Host-Only Ethernet Adapter`
Make sure the IPv4 Address is `192.168.56.1`.

---

## ▶️ Phase 4: Running the SOC (The "Matrix" Mode)

You need **3 separate PowerShell terminals** running as Administrator (for packet sniffing).

### Terminal 1: IDS Engine (The Brain)
Loads the AI model and provides the analysis API.
```powershell
python virtual_soc/ids_engine.py
```
*Wait for: "Model loaded successfully"*

### Terminal 2: Dashboard (The Eyes)
Visualizes threat data in real-time.
```powershell
streamlit run virtual_soc/dashboard.py
```
*Your browser will open to the dashboard.*

### Terminal 3: Traffic Sniffer (The Ears)
Captures packets from the VirtualBox network and sends them to the engine.
```powershell
# Make sure to use quotes for the adapter name
python virtual_soc/extractor.py "VirtualBox Host-Only Ethernet Adapter"
```

---

## ⚔️ Phase 5: Run an Attack!
Go to your **Kali Linux VM** and launch an attack against the Victim (`192.168.56.20`).

**1. Port Scan (Nmap)**
```bash
nmap -sS -p 1-1000 192.168.56.20
```
*Check Dashboard: You should see "PortScan" alerts.*

**2. Brute Force (Hydra)**
```bash
hydra -l user -P rockyou.txt ssh://192.168.56.20
```
*Check Dashboard: You should see "Brute Force" or "Patator" alerts.*
