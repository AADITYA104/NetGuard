import streamlit as st
import pandas as pd
import requests
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime

# Configuration
IDS_API_URL = "http://localhost:8000/events"
STATS_API_URL = "http://localhost:8000/stats"

st.set_page_config(
    page_title="SOC Dashboard | AI-Powered IDS",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for dark theme
st.markdown("""
<style>
    .reportview-container {
        background: #0e1117;
    }
    .metric-card {
        background-color: #262730;
        padding: 15px;
        border-radius: 5px;
        border: 1px solid #41444b;
    }
    .attack-alert {
        background: linear-gradient(135deg, #ff4444 0%, #cc0000 100%);
        padding: 20px;
        border-radius: 10px;
        margin: 10px 0;
        color: white;
        font-weight: bold;
    }
    .benign-status {
        background: linear-gradient(135deg, #00c851 0%, #007e33 100%);
        padding: 15px;
        border-radius: 10px;
        color: white;
    }
    .attack-type-badge {
        display: inline-block;
        padding: 5px 12px;
        border-radius: 15px;
        margin: 3px;
        font-size: 14px;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ Virtual SOC: AI-Powered Threat Intelligence")
st.markdown("Real-time network intrusion detection using **ML (99.28% accuracy)** + **Rule-Based Detection**")

# Sidebar
st.sidebar.header("🎛️ SOC Controls")
refresh_rate = st.sidebar.slider("Refresh Rate (seconds)", 1, 10, 3)

if st.sidebar.button("🔄 Refresh Now"):
    st.rerun()

st.sidebar.markdown(f"*Auto-refreshing every {refresh_rate}s*")
st.sidebar.markdown("---")
st.sidebar.markdown("### 📡 System Status")

def fetch_data():
    try:
        resp = requests.get(IDS_API_URL, timeout=2)
        if resp.status_code == 200:
            return resp.json()
    except:
        pass
    return []

def fetch_stats():
    try:
        resp = requests.get(STATS_API_URL, timeout=2)
        if resp.status_code == 200:
            return resp.json()
    except:
        pass
    return {}

# Fetch data
data = fetch_data()
stats = fetch_stats()

# Show connection status in sidebar
if data is not None:
    st.sidebar.success("✅ IDS Engine Connected")
else:
    st.sidebar.error("❌ IDS Engine Offline")

# Convert to DataFrame
if data:
    df = pd.DataFrame(data)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df = df.sort_values(by='timestamp', ascending=False)
    
    # Add attack_type column if not present
    if 'attack_type' not in df.columns:
        df['attack_type'] = df.apply(lambda x: x.get('label') if x['is_malicious'] else 'BENIGN', axis=1)
else:
    df = pd.DataFrame(columns=["timestamp", "src_ip", "dst_ip", "label", "confidence", "is_malicious", "attack_type"])

# --- KPI Metrics ---
st.subheader("📊 Key Performance Indicators")
kpi_col1, kpi_col2, kpi_col3, kpi_col4, kpi_col5 = st.columns(5)

total_flows = len(df)
malicious_flows = len(df[df['is_malicious'] == True]) if not df.empty else 0
benign_flows = total_flows - malicious_flows

# Determine threat level
if malicious_flows == 0:
    threat_level = "🟢 LOW"
    threat_color = "normal"
elif malicious_flows <= 5:
    threat_level = "🟡 MODERATE"
    threat_color = "off"
elif malicious_flows <= 20:
    threat_level = "🟠 HIGH"
    threat_color = "off"
else:
    threat_level = "🔴 CRITICAL"
    threat_color = "inverse"

kpi_col1.metric("Total Flows", total_flows)
kpi_col2.metric("Benign Traffic", benign_flows, delta=f"{benign_flows/max(total_flows,1)*100:.0f}%")
kpi_col3.metric("Detected Attacks", malicious_flows, delta_color="inverse")
kpi_col4.metric("Threat Level", threat_level)

# Calculate attack rate
attack_rate = malicious_flows / max(total_flows, 1) * 100
kpi_col5.metric("Attack Rate", f"{attack_rate:.1f}%")

# --- Attack Types Summary ---
if not df.empty and malicious_flows > 0:
    st.subheader("🎯 Attack Types Detected")
    
    attack_df = df[df['is_malicious'] == True]
    
    if 'attack_type' in attack_df.columns:
        attack_types = attack_df['attack_type'].value_counts()
    else:
        attack_types = attack_df['label'].value_counts()
    
    # Display attack types as columns
    attack_cols = st.columns(min(len(attack_types), 6))
    
    attack_colors = {
        'PortScan': '🔍',
        'DDoS': '💥',
        'SSH-Patator': '🔑',
        'FTP-Patator': '📁',
        'DoS Hulk': '💪',
        'DoS Slowloris': '🐌',
        'DoS GoldenEye': '👁️',
        'Web Attack': '🌐',
        'Bot': '🤖',
        'Infiltration': '🕵️',
        'Heartbleed': '💔',
        'ATTACK': '⚠️'
    }
    
    for idx, (attack_type, count) in enumerate(attack_types.items()):
        if idx < len(attack_cols):
            # Find matching emoji
            emoji = '⚠️'
            for key, val in attack_colors.items():
                if key.lower() in str(attack_type).lower():
                    emoji = val
                    break
            attack_cols[idx].metric(f"{emoji} {attack_type}", count)

# --- Latest Alert ---
st.subheader("🚨 Latest Alert")
if not df.empty:
    latest_event = df.iloc[0]
    
    if latest_event['is_malicious']:
        attack_type = latest_event.get('attack_type', latest_event['label'])
        confidence = latest_event['confidence']
        src_ip = latest_event['src_ip']
        dst_ip = latest_event.get('dst_ip', 'unknown')
        dst_port = latest_event.get('dst_port', 'N/A')
        detection_method = latest_event.get('detection_method', 'hybrid')
        
        st.error(f"""
        🚨 **ATTACK DETECTED: {attack_type}**
        
        | Field | Value |
        |-------|-------|
        | Source IP | `{src_ip}` |
        | Target | `{dst_ip}:{dst_port}` |
        | Confidence | **{confidence:.1%}** |
        | Detection Method | `{detection_method}` |
        | Time | {latest_event['timestamp'].strftime('%H:%M:%S')} |
        """)
    else:
        st.success(f"✅ Latest Flow: **BENIGN** from `{latest_event['src_ip']}` (Confidence: {latest_event['confidence']:.1%})")
else:
    st.info("⏳ No events yet. Waiting for traffic...")

# --- Charts ---
st.subheader("📈 Traffic Analysis")
col1, col2 = st.columns(2)

if not df.empty and len(df) > 0:
    # Attack Type Distribution (Pie Chart)
    if 'attack_type' in df.columns:
        chart_col = 'attack_type'
    else:
        chart_col = 'label'
    
    # Create better labels
    df['display_label'] = df.apply(
        lambda x: x.get('attack_type', x['label']) if x['is_malicious'] else 'BENIGN', 
        axis=1
    )
    
    fig_dist = px.pie(
        df, 
        names='display_label', 
        title='🎯 Traffic Classification',
        hole=0.4,
        color_discrete_sequence=px.colors.qualitative.Bold
    )
    fig_dist.update_traces(textinfo='percent+label')
    col1.plotly_chart(fig_dist, use_container_width=True)
    
    # Timeline Chart with Attack Types
    color_map = {
        'BENIGN': '#00c851',
        'ATTACK': '#ff4444',
        'PortScan': '#ff9100',
        'DDoS': '#ff1744',
        'SSH-Patator': '#d500f9',
        'FTP-Patator': '#651fff',
        'DoS Hulk': '#c51162',
        'DoS Slowloris': '#aa00ff',
        'Bot': '#6200ea',
        'Web Attack': '#304ffe'
    }
    
    fig_timeline = px.scatter(
        df, 
        x='timestamp', 
        y='confidence', 
        color='display_label',
        size='confidence',
        title='⏱️ Detection Timeline',
        color_discrete_map=color_map,
        hover_data=['src_ip', 'dst_port']
    )
    fig_timeline.update_layout(
        xaxis_title="Time",
        yaxis_title="Confidence",
        legend_title="Classification"
    )
    col2.plotly_chart(fig_timeline, use_container_width=True)
    
    # Attack Types Bar Chart
    if malicious_flows > 0:
        st.subheader("📊 Attack Distribution")
        attack_summary = df[df['is_malicious'] == True]['display_label'].value_counts().reset_index()
        attack_summary.columns = ['Attack Type', 'Count']
        
        fig_bar = px.bar(
            attack_summary,
            x='Attack Type',
            y='Count',
            title='🎯 Attacks by Type',
            color='Attack Type',
            color_discrete_sequence=px.colors.qualitative.Dark24
        )
        fig_bar.update_layout(showlegend=False)
        st.plotly_chart(fig_bar, use_container_width=True)
else:
    col1.info("Waiting for data...")
    col2.info("Waiting for data...")

# --- Detection Methods Stats ---
if stats and stats.get('detection_methods'):
    st.subheader("🔬 Detection Methods")
    methods = stats['detection_methods']
    method_cols = st.columns(len(methods))
    
    method_icons = {
        'ml': '🤖 ML Model',
        'rules': '📋 Rules',
        'ml-threshold': '📊 ML Threshold',
        'ml-uncertain': '❓ ML Uncertain'
    }
    
    for idx, (method, count) in enumerate(methods.items()):
        display_name = method_icons.get(method, method)
        method_cols[idx].metric(display_name, count)

# --- Live Log ---
st.subheader("📋 Live Traffic Log")
if not df.empty:
    # Select columns to display
    display_cols = ['timestamp', 'src_ip', 'dst_ip', 'dst_port', 'label', 'attack_type', 'confidence', 'detection_method', 'is_malicious']
    available_cols = [c for c in display_cols if c in df.columns]
    
    # Style the dataframe
    def highlight_attacks(row):
        if row.get('is_malicious', False):
            return ['background-color: #ffcccc'] * len(row)
        return ['background-color: #ccffcc'] * len(row)
    
    styled_df = df[available_cols].head(50)
    st.dataframe(
        styled_df,
        height=400,
        use_container_width=True
    )
else:
    st.info("No traffic logged yet.")

# --- Footer ---
st.markdown("---")
st.markdown("""
<div style='text-align: center; color: #666;'>
    <p>🛡️ <strong>Virtual SOC Dashboard</strong> | Powered by RandomForest ML (99.28% Accuracy) + Rule-Based Detection</p>
    <p>Model: Binary Classification (ATTACK/BENIGN) with Attack Type Identification</p>
</div>
""", unsafe_allow_html=True)

# Auto-refresh using JavaScript
st.markdown(
    f"""
    <script>
        setTimeout(function(){{
            window.location.reload();
        }}, {refresh_rate * 1000});
    </script>
    """,
    unsafe_allow_html=True
)
