import os
import json
import joblib
import numpy as np
import logging
from core.flow_aggregator import extract_flows_from_packets

logger = logging.getLogger("flask.app")

MODEL_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models"))
MODEL_PATH = os.path.join(MODEL_DIR, "network_model.joblib")
CONFIG_PATH = os.path.join(MODEL_DIR, "feature_config.json")
EVAL_PATH = os.path.join(MODEL_DIR, "evaluation.json")

_model_cache = None


def load_model_artifacts():
    """Loads trained model, scaler, and configuration from disk."""
    global _model_cache
    if _model_cache is not None:
        return _model_cache

    if not os.path.exists(MODEL_PATH) or not os.path.exists(CONFIG_PATH):
        logger.warning("ML model artifacts not found on disk.")
        return None

    try:
        artifact = joblib.load(MODEL_PATH)
        with open(CONFIG_PATH, "r") as f:
            config = json.load(f)

        eval_data = {}
        if os.path.exists(EVAL_PATH):
            with open(EVAL_PATH, "r") as f:
                eval_data = json.load(f)

        _model_cache = {
            "clf": artifact.get("model"),
            "scaler": artifact.get("scaler"),
            "classes": artifact.get("classes", []),
            "config": config,
            "evaluation": eval_data
        }
        logger.info(f"Loaded ML NIDS model successfully ({len(_model_cache['classes'])} classes).")
        return _model_cache
    except Exception as e:
        logger.error(f"Failed to load ML model: {e}")
        return None


def predict_traffic(parsed_data):
    """
    Runs flow feature extraction and ML classification on parsed PCAP packets.
    Returns structured JSON-safe prediction summary.
    """
    artifacts = load_model_artifacts()

    if artifacts is None or artifacts.get("clf") is None:
        return {
            "model_available": False,
            "status": "UNAVAILABLE",
            "prediction": "UNAVAILABLE",
            "attack_type": None,
            "confidence": 0.0,
            "details": "ML model not trained or artifacts missing.",
            "evaluated_flows": 0
        }

    clf = artifacts["clf"]
    scaler = artifacts["scaler"]
    supported_classes = artifacts["classes"]

    # Extract flows from parsed packets
    packets = parsed_data.get("packets", [])
    flows = extract_flows_from_packets(packets)

    if not flows:
        return {
            "model_available": True,
            "status": "BENIGN",
            "prediction": "BENIGN",
            "attack_type": None,
            "confidence": 100.0,
            "details": "No valid IP flows detected in capture for ML evaluation.",
            "evaluated_flows": 0,
            "attack_flows": 0,
            "benign_flows": 0,
            "supported_classes": supported_classes
        }

    import pandas as pd
    # Extract feature matrix X as DataFrame with feature names
    feature_matrix = [f["feature_vector"] for f in flows]
    X_df = pd.DataFrame(feature_matrix, columns=artifacts["config"]["feature_names"])
    X_scaled = scaler.transform(X_df)

    predictions = clf.predict(X_scaled)
    probabilities = clf.predict_proba(X_scaled)

    attack_counts = {}
    attack_flows_count = 0
    benign_flows_count = 0
    total_confidences = []

    for idx, pred_class in enumerate(predictions):
        class_idx = list(clf.classes_).index(pred_class)
        prob = float(probabilities[idx][class_idx]) * 100.0
        total_confidences.append(prob)

        if pred_class == "BENIGN":
            benign_flows_count += 1
        else:
            attack_flows_count += 1
            attack_counts[pred_class] = attack_counts.get(pred_class, 0) + 1

    overall_prediction = "ATTACK" if attack_flows_count > 0 else "BENIGN"
    primary_attack_type = None

    if attack_flows_count > 0:
        # Most frequent attack type detected
        primary_attack_type = max(attack_counts, key=attack_counts.get)

    avg_confidence = round(float(np.mean(total_confidences)), 1) if total_confidences else 0.0

    return {
        "model_available": True,
        "status": overall_prediction,
        "prediction": overall_prediction,
        "is_attack": bool(attack_flows_count > 0),
        "attack_type": primary_attack_type,
        "confidence": avg_confidence,
        "model_probability": avg_confidence,
        "evaluated_flows": len(flows),
        "attack_flows": attack_flows_count,
        "benign_flows": benign_flows_count,
        "supported_classes": supported_classes,
        "evaluation_metrics": artifacts.get("evaluation", {})
    }
