import streamlit as st
import pandas as pd
import time
import os

st.set_page_config(page_title="SentinAI Live Monitor", layout="wide")

st.title("🛡️ SentinAI: Real-Time Threat Monitor")

# Create a single placeholder OUTSIDE the loop
dashboard_placeholder = st.empty()

def load_data():
    if not os.path.exists("scan_logs.csv"):
        return pd.DataFrame(columns=["Timestamp", "Content", "Status", "Type"])
    # Read CSV and give names to columns since we didn't write a header
    df = pd.read_csv("scan_logs.csv", names=["Timestamp", "Content", "Status", "Type"])
    return df

# Auto-Refresh Loop
while True:
    df = load_data()
    
    # Calculate Stats
    total = len(df)
    threats = len(df[df["Status"] == "DANGER"])
    safe = len(df[df["Status"] == "SAFE"])

    # DRAW EVERYTHING INSIDE THIS CONTAINER
    with dashboard_placeholder.container():
        # 1. Metrics
        c1, c2, c3 = st.columns(3)
        c1.metric("Total Scans", total)
        c2.metric("Threats Blocked", threats)
        c3.metric("Safe", safe)

        # 2. Table
        st.subheader("Live Traffic")
        if not df.empty:
            st.dataframe(df.iloc[::-1], use_container_width=True)

    # Refresh every 2 seconds
    time.sleep(2)
