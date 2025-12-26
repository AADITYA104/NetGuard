# 🛡️ NetGuard: AI-Powered Threat Detection System

**NetGuard** is a production-ready Intrusion Detection System (IDS) that leverages Machine Learning (Random Forest) and a hybrid rule-based engine to detect network attacks in real-time. Built on the CIC-IDS-2017 dataset, it is capable of identifying **14 specific attack types** (DDoS, PortScan, Botnet, Infiltration, etc.) with high accuracy.

---

## 🚀 Key Features

*   **🧠 Hybrid Detection Engine**: Combines a binary ML model (Attack vs. Benign) with a multi-class classifier and heuristic rules for 99%+ accuracy.
*   **📊 Real-Time Dashboard**: A stunning Streamlit-based interface ("The Eyes") to visualize network traffic, threats, and alerts live.
*   **🔍 Live Packet Sniffer**: Captures raw network packets from VirtualBox or physical interfaces and extracts valid CIC-IDS-2017 features on the fly.
*   **⚡ High Performance**: optimized feature selection (30 key features) ensures low-latency inference suitable for edge deployment.
*   **🛡️ Attack Support**: Detects DDoS (Hulk, Slowloris), Port Scans, Brute Force (SSH, FTP, Web), Botnets, and more.

---

## 📂 Project Structure

| File/Directory | Description |
| :--- | :--- |
| `virtual_soc/` | **Core System**. Contains the Engine, Dashboard, and Sniffer. |
| ├── `ids_engine.py` | **The Brain**: FastAPI backend that loads models and processes features. |
| ├── `dashboard.py` | **The Eyes**: Streamlit dashboard for real-time visualization. |
| ├── `extractor.py` | **The Ears**: Packet sniffer that extracts features and sends them to the engine. |
| `ids_demo/` | Legacy web demo (Flask-based) for simple testing. |
| `models/` & `outputs/` | Stores trained Random Forest models (`.joblib`, `.pkl`) and scalers. |
| `CIC_IDS_2017_*.ipynb` | Jupyter Notebooks for training, preprocessing, and feature selection. |
| `WINDOWS_SETUP_GUIDE.md` | Detailed setup instructions for Windows users. |

---

## 🛠️ Installation

### Prerequisites
*   Python 3.8+
*   [Npcap](https://npcap.com/) (Required for packet sniffing on Windows)
*   Visual C++ Build Tools (if needed for some Python packages)

### 1. Clone & Install
```bash
git clone https://github.com/AADITYA104/NetGuard.git
cd NetGuard
pip install -r requirements_soc.txt
```

---

## 🖥️ Running the Virtual SOC (The "Matrix" Mode)

The system consists of three components running simultaneously. Open **3 separate terminals** (PowerShell as Administrator is recommended).

### Terminal 1: The Engine (Backend)
This starts the AI engine which loads the models and serves the API.
```powershell
python virtual_soc/ids_engine.py
```
*Wait until you see: `Uvicorn running on http://0.0.0.0:8000`*

### Terminal 2: The Dashboard (Frontend)
This launches the visual interface.
```powershell
streamlit run virtual_soc/dashboard.py
```
*Your browser will automatically open to `http://localhost:8501`.*

### Terminal 3: The Sniffer (Data Collector)
This captures traffic from your network adapter.
**Note:** You must specify your network adapter name. If using VirtualBox, it's usually "VirtualBox Host-Only Ethernet Adapter". If testing on your home Wi-Fi, use "Wi-Fi".
```powershell
# List adapters to find the correct name
python virtual_soc/extractor.py --list

# Run the sniffer (Replace "Your Adapter Name" with the actual name)
python virtual_soc/extractor.py "VirtualBox Host-Only Ethernet Adapter"
```

---

## ⚔️ Testing with Attacks (Kali Linux)

To verify the system, you can simulate attacks from a Kali Linux VM (Attacker) against a Victim VM. Ensure your Sniffer is listening on the correct interface!

### 1. Port Scan (Reconnaissance)
*Detects rapid scanning of open ports.*
```bash
# Stealth Syn Scan
nmap -sS -p 1-1000 <VICTIM_IP>
```
**Expected Result**: Dashboard shows **"PortScan"** alert.

### 2. DDoS Attack (Hulk)
*Floods the web server to exhaust resources.*
```bash
# Flood port 80
sudo hping3 -S -p 80 --flood <VICTIM_IP>
```
**Expected Result**: Dashboard shows **"DDoS"** or **"DoS Hulk"** alert.

### 3. SSH Brute Force
*Attempts multiple login combinations.*
```bash
# Run Hydra against SSH
hydra -l user -P rockyou.txt ssh://<VICTIM_IP>
```
**Expected Result**: Dashboard shows **"SSH-Patator"** or **"Brute Force"** alert.

### 4. Web Attack
*Simulate a generic web attack.*
```bash
# Simple flood with data
sudo hping3 -S -p 80 --flood --data 120 <VICTIM_IP>
```

---

## 🧪 Training the Model (Optional)

If you want to retrain the AI from scratch using the CIC-IDS-2017 dataset:

1.  Download the CSVs from the [CIC-IDS-2017 Dataset](https://www.unb.ca/cic/datasets/ids-2017.html).
2.  Place them in the `dataset/` folder.
3.  Run the pipeline notebook:
    ```bash
    jupyter notebook CIC_IDS_2017_Unified_Pipeline.ipynb
    ```
4.  The new models will be saved in `outputs/`.

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
