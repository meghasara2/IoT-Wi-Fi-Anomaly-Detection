# STREAMLIT COMMUNITY CLOUD DEPLOYMENT GUIDE
**IoT Network Guard — Dual-Detector SOC Console**
**Date:** November 15, 2026  
**Repository:** `https://github.com/meghasara2/IoT-WiFi-Anomaly-Detection` (Branch: `main`)  
**Cloud Entry Point:** `src/cloud_dashboard.py`

---

## 1. Overview & Architecture

The public cybersecurity dashboard for **IoT Network Guard** is hosted on **Streamlit Community Cloud**. It operates completely serverless and decoupled from local sniffer hardware, reading exclusively from Supabase Cloud's 9 sanitized PostgreSQL views over PostgREST.

```mermaid
flowchart LR
    Workstation["Local Workstation (Collector Daemon)"] -->|TShark / ESP32| SQLite["Local SQLite WAL"]
    SQLite --> Outbox["cloud_sync_outbox"]
    Outbox -->|Asynchronous Sync| Supabase["Supabase Cloud (PostgreSQL 17.6)"]
    Supabase --> Views["v_public_* Definer Views"]
    Views -->|PostgREST (anon key)| StreamlitCloud["Streamlit Community Cloud (src/cloud_dashboard.py)"]
    StreamlitCloud --> Browser["Public Web Visitors"]
```

---

## 2. Step-by-Step Deployment Instructions

### Step 1: Push Verified Code to GitHub (Requires Operator Approval)
Before deploying on Streamlit Cloud, the verified project code must be committed and pushed to the `main` branch of `https://github.com/meghasara2/IoT-WiFi-Anomaly-Detection`.
*(See Checkpoint D — Git push requires explicit authorization).*

### Step 2: Access Streamlit Community Cloud
1. Navigate to [Streamlit Community Cloud](https://share.streamlit.io/) and log in with your GitHub account (`meghasara2`).
2. In the top-right corner, click **New app**.

### Step 3: Configure App Deployment Parameters
In the "Deploy an app" interface, configure:
- **Repository:** `meghasara2/IoT-WiFi-Anomaly-Detection`
- **Branch:** `main`
- **Main file path:** `src/cloud_dashboard.py`
- **App URL (optional custom subdomain):** `iot-network-guard-soc` (or default assigned subdomain)

### Step 4: Configure Streamlit Secrets (Crucial)
1. In the deployment modal, click **Advanced settings...**.
2. Set **Python version:** `3.11`.
3. In the **Secrets** text area, paste the following configuration (replace `<your-anon-key>` with your actual public anon key from Supabase Dashboard):
   ```toml
   # Supabase Cloud PostgREST Endpoint
   SUPABASE_URL = "https://cwqumhtzeiqrfhlesksw.supabase.co"

   # Supabase Public Anonymous API Key (read-only definer views)
   # Found in Supabase Dashboard -> Project Settings -> API -> anon public key
   SUPABASE_ANON_KEY = "your-actual-supabase-anon-key-here"
   ```
4. Click **Save**.

### Step 5: Launch & Deploy
1. Click **Deploy!**.
2. Streamlit Cloud will pull the repository, install dependencies from `requirements.txt`, and start `src/cloud_dashboard.py`.
3. The dashboard will initialize with dark obsidian SOC styling and display the live connection badge once connected to Supabase.

---

## 3. Post-Deployment Verification Checklist

- [ ] Header banner displays: `Cloud Link Active | Host: cwqumhtzeiqrfhlesksw.supabase.co`.
- [ ] Section 1 (Overview) displays recent collector runs or graceful benign standby banner.
- [ ] Section 2 (Traffic) plots 1-second feature windows without errors.
- [ ] Section 4 (Attacks) displays forensic cards with semantic IP scopes (`LOCAL_NETWORK`, `EXTERNAL_NETWORK`).
- [ ] Section 5 (Sensors) plots temperature, humidity, and PIR motion.
- [ ] Section 6 (Registry) lists authorized phone stations (`Node_3`, `Node_4`, `Node_5`) with zero raw MAC addresses.
- [ ] Navigation works smoothly across all 7 sections.
- [ ] Zero unhandled tracebacks or HTTP 401/403 access errors.

