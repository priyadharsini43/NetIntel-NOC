# NetIntel NOC — Network Traffic Analysis & ML NIDS Platform

**NetIntel NOC** is a clean, interview-ready Network Traffic Analysis and Machine Learning Intrusion Detection System (ML NIDS) platform. It parses real recorded `.pcap` and `.pcapng` packet captures using **Scapy**, extracts bidirectional network flows, classifies traffic using a validated **Random Forest ML NIDS**, provides supporting **Rule-Based Alerts**, renders dynamic **Network Topology Graphs**, provides real-time **Packet Filtering**, and exports analysis reports in **PDF, CSV, and JSON** formats.

> **Important**: This project contains **no fake packet data, no hardcoded statistics, and no fabricated ML accuracy numbers**. Every dashboard statistic is computed dynamically from actual uploaded packet captures. Model performance metrics are generated from an independent, unseen test set evaluation.

---

## 1. System Architecture

```text
┌─────────────────────────────────────────────────────────────────┐
│                    REACT FRONTEND (Vite + SPA)                  │
│ Upload Zone | ML NIDS Classifier | Summary Cards | Topology SVG  │
│        Rule Alerts List | Packet Search & Filter Table          │
└────────────────────────────────┬────────────────────────────────┘
                                 │
                   HTTP REST API (Upload / Analyze / Export)
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                      FLASK BACKEND (REST API)                   │
│   /upload (File Validation)  |  /analyze (Scapy & ML Engine)    │
│               /export (PDF / CSV / JSON Generators)             │
└────────────────────────────────┬────────────────────────────────┘
                                 │
       ┌─────────────────────────┴─────────────────────────┐
       ▼                                                   ▼
┌───────────────────────────────┐         ┌───────────────────────────────┐
│     SCAPY PACKET PARSER       │         │      ML NIDS CLASSIFIER       │
│ Frame Extraction (IP, Ports)  │         │ Flow Feature Aggregator (10D) │
│ Stats & Topology Generator    │         │ RandomForest (CIC-IDS2017)    │
└───────────────────────────────┘         └───────────────────────────────┘
```

---

## 2. Security Detection Architecture

The platform uses a two-tier security detection model:

1. **Primary Security Classifier — ML NIDS**:
   - Supervised **Random Forest Classifier** trained on multiclass network intrusion traffic (CIC-IDS2017 taxonomy).
   - Evaluates flow feature vectors to classify traffic into `BENIGN` or specific attack types (`PortScan`, `DDoS`, `DoS`, `BruteForce`, `Bot`).
   - Reports exact model probabilities derived from `predict_proba()`.

2. **Secondary Evidence Layer — Rule-Based Alerts**:
   - Transparent heuristic alerts providing supporting context for suspicious traffic patterns:
     - **High Packet Volume Source**: Flags source IPs generating $\ge 5\%$ of IP traffic AND $\ge 100$ packets.
     - **Possible Port Scan**: Flags source IPs connecting to $\ge 15$ unique destination ports.
     - **High Packet Frequency**: Flags unicast flow pairs with $\ge 100$ packets between source and destination.
     - **Protocol Distribution Spike**: Flags ICMP spikes ($\ge 30\%$) or UDP floods ($\ge 50\%$).

---

## 3. ML Methodology & Feature Pipeline

### Flow Extraction (`core/flow_aggregator.py`)
Bidirectional flow aggregation groups packets into 5-tuple flow keys (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`) and extracts 10 flow-level features:
1. `destination_port`
2. `flow_duration`
3. `total_fwd_packets`
4. `total_bwd_packets`
5. `total_length_fwd`
6. `total_length_bwd`
7. `fwd_pkt_len_mean`
8. `bwd_pkt_len_mean`
9. `flow_bytes_s`
10. `flow_packets_s`

### Data Leakage Prevention & Training (`scripts/train_model.py`)
- **Dataset**: Labeled flow dataset following **CIC-IDS2017 taxonomy** (6,000 flow samples across 6 classes).
- **Train/Test Split**: 80% Train (4,800 samples) / 20% Unseen Test Set (1,200 samples) with `random_state=42` and class stratification.
- **Leakage Prevention**: `StandardScaler` is fitted **ONLY** on the training data (`X_train`). The test set (`X_test`) is kept completely unseen during scaling and hyperparameter configuration.

### Validated Test Set Metrics (`models/evaluation.json`)
```text
Accuracy          : 99.92%
Macro Precision   : 99.73%
Macro Recall      : 99.97%
Macro F1-Score    : 99.85%
Weighted Precision: 99.92%
Weighted Recall   : 99.92%
Weighted F1-Score : 99.92%
False Positive Rate: 0.00% (0 / 600 Benign test flows)
```

---

## 4. Tech Stack

- **Frontend**: React 18, Vite, Tailwind CSS, Lucide Icons
- **Backend**: Python 3.11+, Flask REST API
- **Packet & Flow Engine**: Scapy (`scapy.all.rdpcap`), Flow Aggregator
- **ML Framework**: scikit-learn (`RandomForestClassifier`, `StandardScaler`), joblib
- **Reporting**: ReportLab (PDF), Pandas (CSV)

---

## 5. Quick Start Guide

### Prerequisites
- Python 3.11+
- Node.js 18+

### Step 1: Start Backend (Flask REST API)
```bash
# In the project root directory
.\.venv\Scripts\activate

# Train ML NIDS Model (Generates model artifacts in models/)
python scripts/train_model.py

# Start Flask Backend (Runs on http://localhost:5000)
python app.py
```

### Step 2: Start Frontend (React SPA)
```bash
# In a new terminal, navigate to frontend directory
cd frontend

# Install frontend dependencies (if not installed)
npm install

# Start Vite Development Server (Runs on http://localhost:5173)
npm run dev
```

---

## 6. Verification & Testing

### Automated Backend Unit Tests
Run backend test suite verifying Scapy parsing, flow extraction, ML prediction output, anomaly rules, stats, and report exports:
```bash
.\.venv\Scripts\python.exe test_flow.py
```
*Result:* **7 / 7 PASS (OK)**

### Frontend Production Build
Run frontend compilation:
```bash
cd frontend && npm run build
```
*Result:* **Built successfully with 0 errors**

---

## 7. Technical Interview Q&A Guide

### Q1: How does your ML NIDS extract features from PCAP traffic?
**Answer:** The system uses `core/flow_aggregator.py` to group Scapy packets into bidirectional 5-tuple flows (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`). It extracts 10 features including forward/backward packet counts, forward/backward total byte lengths, mean packet sizes, and flow packet/byte rates.

### Q2: How did you prevent data leakage during model training?
**Answer:** The training pipeline in `scripts/train_model.py` uses an 80/20 stratified split (`random_state=42`). Crucially, the `StandardScaler` is fitted **ONLY** on the 80% training set (`X_train`), and then applied to transform the test set (`X_test`). The test set remains completely unseen during feature scaling and model training.

### Q3: What is the difference between Model Evaluation and PCAP Inference?
**Answer:** Model Evaluation is performed on an unseen test dataset with known ground-truth labels to measure Accuracy, Precision, Recall, and FPR. Real PCAP Inference is performed on uploaded, unlabeled network captures where the model produces predictions based on flow feature probabilities.

### Q4: Why combine Machine Learning with Rule-Based Alerts?
**Answer:** Machine Learning provides probabilistic flow-level attack classification (`BENIGN` vs `ATTACK` / `PortScan`, `DDoS`, etc.), while transparent Rule-Based Alerts provide explainable supporting indicators (e.g. flagging a host contacting $\ge 15$ unique ports) to help analysts understand traffic patterns.

---

## 8. Limitations

1. **Unlabeled Inference**: Predictions on uploaded real-world PCAP files are model inferences, not ground-truth verified attack labels.
2. **Unsupported Traffic**: Non-IP traffic (e.g. pure ARP or raw Ethernet frames) is safely excluded from ML flow inference and reported under protocol distribution and packet tables.


