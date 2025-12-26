# Threat Detection in Cyber Security Using AI

A unified, production-ready Intrusion Detection System (IDS) using Machine Learning (Random Forest) on the CIC-IDS-2017 dataset. This project features a robust multi-class classification pipeline and a real-time Flask-based web demonstration.

## Key Features

- **Multi-Class Classification**: Unified Random Forest model capable of detecting BENIGN traffic and 14 specific attack types (DDoS, PortScan, Bot, Infiltration, etc.).
- **Robust Pipeline**: Handles data preprocessing, missing values, infinite values, and feature scaling automatically.
- **Real-Time Detection Demo**: A Flask web application that serves the trained model to predict threats on live or simulated traffic.
- **Traffic Replay**: A utility script to replay network flow data to the IDS for demonstration and testing purposes.
- **Feature Optimization**: Uses a selected subset of 30 high-impact features for efficient real-time inference.

## Project Structure

- `CIC_IDS_2017_Unified_Pipeline.ipynb`: The main notebook containing the end-to-end pipeline:
    - Data Loading & Cleaning
    - Preprocessing (Imputation, Scaling)
    - Feature Selection (Random Forest Importance)
    - Model Training (Weighted Random Forest)
    - Evaluation (Confusion Matrix, Precision/Recall)
- `ids_demo/`: Directory containing the real-time demo application.
    - `app.py`: Flask backend API and serving logic.
    - `replay.py`: Script to simulate network traffic by sending flows to the API.
    - `static/` & `templates/`: Frontend assets for the dashboard.
- `outputs/`: Stores trained models (`best_model_randomforest.joblib`), encoders, and scalar objects. (Note: These are large files).
- `dataset/`: Directory for CIC-IDS-2017 CSV files (not included in repo, must be downloaded).

## Getting Started

### Prerequisites

- Python 3.8+
- Required libraries: `pandas`, `numpy`, `scikit-learn`, `matplotlib`, `seaborn`, `joblib`, `flask`, `requests`

Install dependencies:
```bash
pip install pandas numpy scikit-learn matplotlib seaborn joblib flask requests
```

### 1. Training the Model (Optional)

If you want to retrain the model from scratch:
1.  Download the **CIC-IDS-2017** dataset (CSV version).
2.  Place the CSV files in the `dataset/` directory.
3.  Open and run `CIC_IDS_2017_Unified_Pipeline.ipynb` in Jupyter.
4.  The trained artifacts will be saved to the `outputs/` folder.

### 2. Running the Real-Time Demo

The demo allows you to visualize the IDS in action using a web dashboard.

**Step 1: Start the Backend Server**
```bash
python ids_demo/app.py
```
*The server will start on `http://localhost:5000`.*

**Step 2: Access the Dashboard**
Open your web browser and navigate to `http://localhost:5000`. You will see the main dashboard waiting for data.

**Step 3: Start Traffic Simulation**
In a separate terminal, run the replay script to feed data to the IDS:
```bash
python ids_demo/replay.py
```
*This script reads sample flows from `ids_demo/demo_flows.csv` and sends them to the API, simulating live network traffic.*

## System Architecture

- **Model**: Random Forest Classifier with `class_weight='balanced'` to handle the severe class imbalance in network traffic data.
- **Preprocessing**: 
  - Drops non-predictive columns (IPs, Timestamps).
  - Imputes missing values with median statistics.
  - Standard scaling for numerical stability.
- **Feature Selection**: Reduced from 70+ raw features to **30 top features** to optimize performance without sacrificing accuracy. Key features include `Destination Port`, `Packet Length`, and `Flow IAT`.

## License

[MIT](LICENSE)
