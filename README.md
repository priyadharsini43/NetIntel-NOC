# 🛡️ NetIntel NOC — Network Traffic Analysis & ML NIDS Platform

> **Real-time PCAP/PCAPNG packet inspection, Machine Learning intrusion detection, and automated SOC reporting in one unified platform.**

NetIntel NOC is a full-stack Network Operations Center (NOC) and Network Intrusion Detection System (NIDS) that analyzes real packet captures (`PCAP`/`PCAPNG`) using **Scapy**, a **CIC-IDS2017 trained Random Forest** classifier, and a **rule-based anomaly engine** to detect port scans, suspicious flows, and network threats.

---

## 🌐 Live Demo & Links

- **Live Application:** [netintel-noc.onrender.com](https://netintel-noc.onrender.com)
- **GitHub Repository:** [github.com/priyadharsini43/NetIntel-NOC](https://github.com/priyadharsini43/NetIntel-NOC)

---

## 🚀 Key Features

- **Deep Packet Inspection:** Parses real `.pcap` and `.pcapng` network captures using Scapy.
- **ML-Powered Threat Classification:** Uses a Random Forest model trained on the **CIC-IDS2017** dataset to classify benign vs. malicious network flows.
- **Hybrid Anomaly Detection:** Combines ML predictions with a deterministic rule engine for port-scan and suspicious traffic detection.
- **Interactive Network Topology:** Visualizes host-to-host communication graphs and traffic flow patterns.
- **Packet Search & Filtering:** Filter captured packets by protocol, IP address, port, or threat severity in real time.
- **Multi-Format SOC Reporting:** Export investigation summaries and threat logs as **CSV**, **JSON**, or formatted **PDF** reports.
- **Sample Traffic Generator:** Includes `generate_pcap.py` to generate synthetic network captures for testing and demonstration.

---

## 🛠️ Tech Stack

| Layer | Technologies |
| :--- | :--- |
| **Frontend** | React, TypeScript, Vite, Tailwind CSS |
| **Backend** | Python, Flask, REST API |
| **Packet Analysis** | Scapy (`PCAP` / `PCAPNG`) |
| **Machine Learning** | scikit-learn, Random Forest, CIC-IDS2017 Dataset |
| **Data & Reporting** | Pandas, ReportLab |
| **Infrastructure** | Docker, Docker Compose, Nginx, Render |

---

## 🏗️ System Architecture

```text
                    User
                      │
                      ▼
              React Dashboard
                      │
                 REST API
                      │
                      ▼
                Flask Backend
                      │
                      ▼
              PCAP / PCAPNG File
                      │
                      ▼
                Scapy Analysis
                      │
              ┌───────┴────────┐
              ▼                ▼
        ML Classification   Rule Engine
        Random Forest       Anomaly Detection
              │                │
              └───────┬────────┘
                      ▼
                 Dashboard
                      │
          ┌───────────┼───────────┐
          ▼           ▼           ▼
      Alerts      Topology     Reports
```

---

## 📁 Project Structure

```text
NetIntel-NOC/
├── core/                   # Packet parsing, feature extraction & ML/rule detection logic
├── routes/                 # Flask REST API endpoints
├── models/                 # Trained Random Forest model & scalers
├── frontend/               # React + TypeScript + Vite dashboard
├── nginx/                  # Reverse proxy configuration
├── scripts/                # Utility and setup scripts
├── app.py                  # Flask application entry point
├── config.py               # Environment & application settings
├── generate_pcap.py        # Sample PCAP generator for testing
├── test_flow.py            # End-to-end analysis pipeline tests
├── requirements.txt        # Python dependencies
├── Dockerfile              # Container build configuration
└── docker-compose.yml      # Multi-container orchestration
```

---

## ⚙️ Getting Started (Local Setup)

### Option 1: Run with Docker Compose (Recommended)

```bash
git clone [https://github.com/priyadharsini43/NetIntel-NOC.git](https://github.com/priyadharsini43/NetIntel-NOC.git)
cd NetIntel-NOC
docker-compose up --build
```

### Option 2: Run Manually

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/priyadharsini43/NetIntel-NOC.git](https://github.com/priyadharsini43/NetIntel-NOC.git)
   cd NetIntel-NOC
   ```

2. **Start the Flask backend:**
   ```bash
   python -m venv venv
   source venv/bin/activate        # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   python app.py
   ```

3. **Start the React frontend:**
   ```bash
   cd frontend
   npm install
   npm run dev
   ```

4. *(Optional)* **Generate a test PCAP file:**
   ```bash
   python generate_pcap.py
   ```

---

## 📊 Workflow

1. **Upload Capture:** Upload any `.pcap` or `.pcapng` file via the web dashboard (or generate one using `generate_pcap.py`).
2. **Analyze Traffic:** Scapy extracts packet headers and flow statistics, passing them through both the Random Forest classifier and rule-based anomaly detector.
3. **Investigate & Export:** Inspect flagged alerts, explore the interactive network topology, and export a **PDF**, **CSV**, or **JSON** SOC report.

---

## 🔮 Future Enhancements

- [ ] Live network interface packet sniffing (`eth0` / `wlan0`)
- [ ] Real-time WebSocket alert streaming
- [ ] SHAP / feature-importance explainability per flagged flow
- [ ] Role-based access control (RBAC) for SOC analysts

---

💡 *Built to bridge packet-level network engineering with automated ML intrusion detection.*
