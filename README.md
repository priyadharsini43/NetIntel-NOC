# NetIntel NOC — Network Traffic Analysis & ML NIDS Platform

NetIntel NOC is a network traffic analysis and machine learning-based intrusion detection platform that analyzes real PCAP/PCAPNG files using Scapy, Random Forest, and rule-based anomaly detection.

---

## 🌐 Live Demo

**Live Application:**  
https://netintel-noc.onrender.com

**GitHub Repository:**  
https://github.com/priyadharsini43/NetIntel-NOC

---

## 🚀 Key Features

- Real PCAP/PCAPNG packet analysis using Scapy
- Random Forest-based network traffic classification
- CIC-IDS2017 trained ML model
- Rule-based anomaly detection
- Network topology visualization
- Packet search and filtering
- Suspicious traffic and port-scan detection
- CSV, JSON, and PDF report export
- Real-time analysis of uploaded network captures

---

## 🛠️ Tech Stack

### Frontend

- React
- TypeScript
- Vite
- Tailwind CSS

### Backend

- Python
- Flask
- REST API

### Network Analysis

- Scapy
- PCAP / PCAPNG

### Machine Learning

- scikit-learn
- Random Forest
- CIC-IDS2017 Dataset

### Reporting

- Pandas
- ReportLab

### Deployment

- Docker
- Render

---

## 🏗️ Architecture

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
