"""
NetIntel NOC - Genuine CIC-IDS2017 ML NIDS training
---------------------------------------------------
This script intentionally uses ONLY genuine labelled CIC-IDS2017 CSV files.

Evaluation design:
1. Primary evaluation:
   - For every source CSV independently, sort by Timestamp when available.
   - Earliest 80% of each source file -> training.
   - Latest 20% -> test.
   - The per-file training portions are combined into one training set.
   - No random shuffling across the chronological boundary.

2. Secondary source-file holdout:
   - One source file is held out completely when feasible.
   - A second Random Forest is trained on the other source files.
   - Only classes represented in that training data can be evaluated.
   - This is an additional robustness check, not a replacement for the primary result.

No synthetic data, artificial samples, metric manipulation, or silent downsampling is allowed.
"""

import json
import os
import re
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# Ensure project root is importable.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from core.flow_aggregator import FEATURE_NAMES


EXPECTED_FILES = {
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
}

# These are the exact ten features expected by the inference pipeline.
CIC_COLUMN_MAP = {
    "Destination Port": "destination_port",
    "Flow Duration": "flow_duration",
    "Total Fwd Packets": "total_fwd_packets",
    "Total Backward Packets": "total_bwd_packets",
    "Total Length of Fwd Packets": "total_length_fwd",
    "Total Length of Bwd Packets": "total_length_bwd",
    "Fwd Packet Length Mean": "fwd_pkt_len_mean",
    "Bwd Packet Length Mean": "bwd_pkt_len_mean",
    "Flow Bytes/s": "flow_bytes_s",
    "Flow Packets/s": "flow_packets_s",
    "Label": "label",
}

# Candidate normalized names for each canonical feature in CIC-IDS2017 files.
REQUIRED_COLUMN_CANDIDATES = {
    "destination_port": ["Destination Port"],
    "flow_duration": ["Flow Duration"],
    "total_fwd_packets": ["Total Fwd Packets"],
    "total_bwd_packets": ["Total Backward Packets"],
    "total_length_fwd": ["Total Length of Fwd Packets"],
    "total_length_bwd": ["Total Length of Bwd Packets"],
    "fwd_pkt_len_mean": ["Fwd PacketLength Mean", "Fwd Packet Length Mean"],
    "bwd_pkt_len_mean": ["Bwd Packet Length Mean", "Bwd PacketLength Mean"],
    "flow_bytes_s": ["Flow Bytes/s"],
    "flow_packets_s": ["Flow Packets/s"],
    "label": ["Label"],
}

# Normalize punctuation/spacing before taxonomy mapping.
LABEL_MAP = {
    "BENIGN": "BENIGN",
    "FTP-PATATOR": "BruteForce",
    "SSH-PATATOR": "BruteForce",
    "DOS SLOWLORIS": "DoS",
    "DOS SLOWHTTPTEST": "DoS",
    "DOS HULK": "DoS",
    "DOS GOLDENEYE": "DoS",
    "HEARTBLEED": "DoS",
    "DDOS": "DDoS",
    "PORTSCAN": "PortScan",
    "BOT": "Bot",
    "INFILTRATION": "Infiltration",
    "WEB ATTACK - BRUTE FORCE": "BruteForce",
    "WEB ATTACK - XSS": "WebAttack",
    "WEB ATTACK - SQL INJECTION": "WebAttack",
}

OUTPUT_DIR = PROJECT_ROOT / "models"
DATA_DIR = PROJECT_ROOT / "data"
MODEL_PATH = OUTPUT_DIR / "network_model.joblib"
CONFIG_PATH = OUTPUT_DIR / "feature_config.json"
EVAL_PATH = OUTPUT_DIR / "evaluation.json"

RANDOM_STATE = 42
N_ESTIMATORS = 100
MAX_DEPTH = 15
CHUNK_SIZE = 100_000


def normalize_label(value):
    """Return a canonical label key without inventing a class."""
    text = str(value).strip().lstrip("\ufeff")
    text = (
        text.replace("\ufffd", "-")
        .replace("\x96", "-")
        .replace("–", "-")
        .replace("—", "-")
    )
    text = re.sub(r"\s+", " ", text)
    return text.upper()


def map_label(value):
    key = normalize_label(value)
    return LABEL_MAP.get(key)


def find_expected_csvs(data_dir):
    """Recursively find all eight expected CIC-IDS2017 CSV files."""
    data_dir = Path(data_dir)
    found = {}

    if not data_dir.exists():
        raise RuntimeError(f"Dataset directory does not exist: {data_dir}")

    for path in data_dir.rglob("*.csv"):
        if path.name in EXPECTED_FILES:
            found[path.name] = path

    missing = sorted(EXPECTED_FILES - set(found))
    if missing:
        raise RuntimeError(
            "CIC-IDS2017 dataset is incomplete. Missing expected files:\n"
            + "\n".join(f"  - {name}" for name in missing)
        )

    return [found[name] for name in sorted(found)]


def read_one_csv(path):
    """
    Read only the required CIC columns in chunks.
    No downsampling is performed.
    """
    print(f"\n[*] Loading: {path.name}")

    first_chunk = True
    pieces = []
    raw_rows = 0

    # Read header first so we can verify and map required source columns.
    header_df = pd.read_csv(path, nrows=0)
    raw_cols = list(header_df.columns)
    stripped_map = {str(c).strip(): c for c in raw_cols}

    usecols_raw = []
    raw_to_canonical = {}
    missing = []

    for canonical_name, candidates in REQUIRED_COLUMN_CANDIDATES.items():
        found_raw = None
        for cand in candidates:
            if cand in stripped_map:
                found_raw = stripped_map[cand]
                break
        if found_raw is not None:
            usecols_raw.append(found_raw)
            raw_to_canonical[found_raw] = canonical_name
        else:
            missing.append(canonical_name)

    if missing:
        raise RuntimeError(
            f"{path.name} is missing required CIC-IDS2017 features: {missing}"
        )

    # Preserve Timestamp if available for chronological splitting.
    if "Timestamp" in stripped_map:
        timestamp_raw = stripped_map["Timestamp"]
        usecols_raw.append(timestamp_raw)
        raw_to_canonical[timestamp_raw] = "Timestamp"

    for chunk in pd.read_csv(path, usecols=usecols_raw, chunksize=CHUNK_SIZE):
        raw_rows += len(chunk)
        chunk = chunk.rename(columns=raw_to_canonical)

        # Preserve Timestamp for chronological evaluation.
        if "Timestamp" not in chunk.columns:
            chunk["Timestamp"] = pd.NaT
        else:
            chunk["Timestamp"] = pd.to_datetime(
                chunk["Timestamp"], errors="coerce"
            )

        # Numeric coercion: invalid numeric values become NaN and are removed.
        for feature in FEATURE_NAMES:
            chunk[feature] = pd.to_numeric(chunk[feature], errors="coerce")

        # Normalize labels, then discard unsupported labels only.
        chunk["_original_label"] = chunk["label"].astype(str).str.strip()
        chunk["_mapped_label"] = chunk["label"].map(map_label)

        pieces.append(
            chunk[
                list(FEATURE_NAMES)
                + ["_original_label", "_mapped_label", "Timestamp"]
            ]
        )

        if first_chunk:
            first_chunk = False

    df = pd.concat(pieces, ignore_index=True)

    # Print original label distribution before mapping/exclusion safely.
    print("[*] Original label distribution:")
    for label_val, count in df["_original_label"].value_counts(dropna=False).items():
        safe_label = str(label_val).encode("ascii", errors="replace").decode("ascii")
        print(f"    {safe_label:35s}: {count:,}")

    unsupported_mask = df["_mapped_label"].isna()
    unsupported_count = int(unsupported_mask.sum())

    if unsupported_count:
        print(
            f"[!] Excluding {unsupported_count:,} rows with unsupported/unknown labels."
        )
        print("[!] Unsupported labels:")
        for label_val, count in df.loc[unsupported_mask, "_original_label"].value_counts(dropna=False).items():
            safe_label = str(label_val).encode("ascii", errors="replace").decode("ascii")
            print(f"    {safe_label:35s}: {count:,}")

    # Remove rows with unsupported labels or invalid feature values.
    before_clean = len(df)
    valid_feature_mask = np.isfinite(df[list(FEATURE_NAMES)]).all(axis=1)
    valid_label_mask = df["_mapped_label"].notna()

    clean = df.loc[valid_feature_mask & valid_label_mask].copy()
    removed_invalid = before_clean - len(clean)

    clean["label"] = clean["_mapped_label"]
    clean["source_file"] = path.name

    clean = clean[
        list(FEATURE_NAMES) + ["label", "Timestamp", "source_file"]
    ].reset_index(drop=True)

    print(f"[*] Raw rows read: {raw_rows:,}")
    print(f"[*] Rows removed for invalid/NaN/Inf/unsupported data: {removed_invalid:,}")
    print(f"[*] Clean rows retained: {len(clean):,}")
    print("[*] Final mapped label distribution:")
    print(clean["label"].value_counts().to_string())

    return clean, {
        "source_file": path.name,
        "raw_rows": raw_rows,
        "clean_rows_before_global_dedup": len(clean),
        "invalid_or_unsupported_removed": removed_invalid,
        "original_label_distribution": df["_original_label"].value_counts(
            dropna=False
        ).to_dict(),
        "mapped_label_distribution": clean["label"].value_counts().to_dict(),
    }


def remove_exact_duplicates(df):
    """
    Remove only exact duplicates.

    First removes duplicates across the ten features + label.
    Feature-only duplicates are then inspected. If the same ten features occur
    with different labels, rows are NOT arbitrarily deleted; those conflicts
    are retained and reported because deleting one label would fabricate a
    preference.
    """
    before = len(df)

    feature_label_dups = df.duplicated(
        subset=list(FEATURE_NAMES) + ["label"], keep="first"
    )
    exact_feature_label_count = int(feature_label_dups.sum())

    deduped = df.loc[~feature_label_dups].copy()

    feature_dup_mask = deduped.duplicated(
        subset=list(FEATURE_NAMES), keep=False
    )
    feature_dup_rows = int(feature_dup_mask.sum())

    conflicting_groups = 0
    if feature_dup_rows:
        grouped = deduped.loc[feature_dup_mask].groupby(
            list(FEATURE_NAMES), dropna=False, sort=False
        )["label"].nunique()
        conflicting_groups = int((grouped > 1).sum())

    print("\n[*] Duplicate handling")
    print(f"    Rows before exact deduplication: {before:,}")
    print(
        "    Exact duplicates on 10 features + label removed: "
        f"{exact_feature_label_count:,}"
    )
    print(f"    Rows after exact deduplication: {len(deduped):,}")
    print(
        "    Feature-only duplicate rows remaining: "
        f"{feature_dup_rows:,}"
    )
    print(
        "    Feature-only groups with conflicting labels retained: "
        f"{conflicting_groups:,}"
    )

    return deduped, {
        "rows_before": before,
        "exact_feature_label_duplicates_removed": exact_feature_label_count,
        "rows_after": len(deduped),
        "feature_only_duplicate_rows_remaining": feature_dup_rows,
        "conflicting_feature_groups_retained": conflicting_groups,
    }


def chronological_primary_split(df):
    """
    Split each source file independently:
      - If Timestamp exists: earliest 80% -> train, latest 20% -> test.
      - If Timestamp is unavailable: deterministic stratified 80/20 split per source file.
    """
    train_parts = []
    test_parts = []
    split_info = {}

    for source_file, group in df.groupby("source_file", sort=True):
        g = group.copy()

        timestamp_available = g["Timestamp"].notna().any()
        if timestamp_available:
            g = g.sort_values(
                by="Timestamp",
                kind="mergesort",
                na_position="last",
            ).reset_index(drop=True)
            split_method = "Timestamp chronological 80/20"

            n = len(g)
            if n < 2:
                raise RuntimeError(
                    f"Source file {source_file} has fewer than 2 usable rows."
                )

            split_at = max(1, int(np.floor(n * 0.80)))
            if split_at >= n:
                split_at = n - 1

            train_g = g.iloc[:split_at].copy()
            test_g = g.iloc[split_at:].copy()
        else:
            split_method = (
                "Timestamp unavailable in MachineLearningCSV; "
                "deterministic stratified 80/20 split used."
            )
            class_counts = g["label"].value_counts()
            single_sample_classes = set(class_counts[class_counts < 2].index)

            if single_sample_classes:
                single_mask = g["label"].isin(single_sample_classes)
                train_single = g.loc[single_mask].copy()
                g_strat = g.loc[~single_mask].copy()

                if not g_strat.empty and g_strat["label"].nunique() > 1:
                    train_g_strat, test_g = train_test_split(
                        g_strat,
                        test_size=0.20,
                        stratify=g_strat["label"],
                        random_state=RANDOM_STATE,
                    )
                    train_g = pd.concat([train_single, train_g_strat], ignore_index=True)
                else:
                    train_g = g.copy()
                    test_g = g.iloc[0:0].copy()
            else:
                train_g, test_g = train_test_split(
                    g,
                    test_size=0.20,
                    stratify=g["label"],
                    random_state=RANDOM_STATE,
                )

        train_parts.append(train_g)
        test_parts.append(test_g)

        split_info[source_file] = {
            "total": len(g),
            "train": len(train_g),
            "test": len(test_g),
            "method": split_method,
            "train_classes": train_g["label"].value_counts().to_dict(),
            "test_classes": test_g["label"].value_counts().to_dict(),
            "missing_test_classes": sorted(
                set(train_g["label"]) - set(test_g["label"])
            ),
            "test_classes_not_seen_in_train": sorted(
                set(test_g["label"]) - set(train_g["label"])
            ),
        }

    train_df = pd.concat(train_parts, ignore_index=True)
    test_df = pd.concat(test_parts, ignore_index=True)

    return train_df, test_df, split_info


def select_secondary_holdout_file(df):
    """
    Deterministically select a source file for secondary holdout evaluation.

    Selection Criteria:
    1. Candidate file must contain at least one attack class (not BENIGN-only).
    2. Prefer files whose attack classes are ALL represented in the remaining source files.
    3. Among feasible candidates, choose the file with the largest number of clean rows.
    4. If no fully feasible candidate exists, select a deterministic fallback (fewest unseen classes,
       then largest row count, then file name) and explicitly report unseen classes.
    """
    file_summaries = []

    for source_file, group in df.groupby("source_file", sort=True):
        classes = set(group["label"].unique())
        attack_classes = classes - {"BENIGN"}
        if not attack_classes:
            continue

        other_rows = df[df["source_file"] != source_file]
        other_classes = set(other_rows["label"].unique())
        unseen_classes = sorted(classes - other_classes)

        file_summaries.append({
            "source_file": source_file,
            "rows": len(group),
            "classes": sorted(classes),
            "attack_classes": sorted(attack_classes),
            "unseen_classes": unseen_classes,
            "is_fully_feasible": len(unseen_classes) == 0,
        })

    if not file_summaries:
        return None, None

    feasible = [f for f in file_summaries if f["is_fully_feasible"]]

    if feasible:
        feasible.sort(key=lambda x: (-x["rows"], x["source_file"]))
        selected = feasible[0]
        selected["selection_reason"] = (
            f"Fully feasible candidate with largest clean row count ({selected['rows']:,} rows). "
            f"All classes {selected['classes']} exist in remaining source files."
        )
    else:
        file_summaries.sort(key=lambda x: (len(x["unseen_classes"]), -x["rows"], x["source_file"]))
        selected = file_summaries[0]
        selected["selection_reason"] = (
            f"Fallback candidate with fewest unseen classes ({selected['unseen_classes']}) "
            f"and largest clean row count ({selected['rows']:,} rows)."
        )

    return selected["source_file"], selected


def fit_random_forest(X_train, y_train):
    """Create the fixed, non-tuned model requested for this project."""
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)

    model = RandomForestClassifier(
        n_estimators=N_ESTIMATORS,
        max_depth=MAX_DEPTH,
        random_state=RANDOM_STATE,
        class_weight="balanced",
        n_jobs=-1,
    )
    model.fit(X_train_scaled, y_train)

    return model, scaler


def evaluate_model(model, scaler, X_test, y_test, all_classes=None):
    X_test_scaled = scaler.transform(X_test)
    y_pred = model.predict(X_test_scaled)
    model_probability = model.predict_proba(X_test_scaled)

    labels = list(all_classes) if all_classes is not None else list(model.classes_)
    cm = confusion_matrix(y_test, y_pred, labels=labels)

    report = classification_report(
        y_test,
        y_pred,
        labels=labels,
        output_dict=True,
        zero_division=0,
    )

    macro_prec = precision_score(
        y_test, y_pred, labels=labels, average="macro", zero_division=0
    )
    macro_rec = recall_score(
        y_test, y_pred, labels=labels, average="macro", zero_division=0
    )
    macro_f1 = f1_score(
        y_test, y_pred, labels=labels, average="macro", zero_division=0
    )

    weighted_prec = precision_score(
        y_test, y_pred, labels=labels, average="weighted", zero_division=0
    )
    weighted_rec = recall_score(
        y_test, y_pred, labels=labels, average="weighted", zero_division=0
    )
    weighted_f1 = f1_score(
        y_test, y_pred, labels=labels, average="weighted", zero_division=0
    )

    per_class = {}
    for cls in labels:
        key = str(cls)
        if key in report:
            per_class[key] = {
                "precision": round(float(report[key]["precision"]), 4),
                "recall": round(float(report[key]["recall"]), 4),
                "f1_score": round(float(report[key]["f1-score"]), 4),
                "support": int(report[key]["support"]),
            }

    zero_support_classes = [
        cls for cls in labels if per_class.get(str(cls), {}).get("support", 0) == 0
    ]

    # BENIGN=0, every other evaluated class=ATTACK.
    y_test_bin = np.where(y_test == "BENIGN", 0, 1)
    y_pred_bin = np.where(y_pred == "BENIGN", 0, 1)

    cm_bin = confusion_matrix(y_test_bin, y_pred_bin, labels=[0, 1])
    tn, fp, fn, tp = map(int, [cm_bin[0, 0], cm_bin[0, 1], cm_bin[1, 0], cm_bin[1, 1]])

    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    tpr = tp / (tp + fn) if (tp + fn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    f1 = (
        2 * precision * tpr / (precision + tpr)
        if (precision + tpr)
        else 0.0
    )

    # Mathematical consistency checks.
    assert int(cm.sum()) == len(y_test)
    assert int(cm_bin.sum()) == len(y_test)
    assert abs(fpr - (fp / (fp + tn) if (fp + tn) else 0.0)) < 1e-12
    assert abs(
        accuracy_score(y_test, y_pred) - (np.trace(cm) / len(y_test))
    ) < 1e-12

    return {
        "accuracy": round(float(accuracy_score(y_test, y_pred)), 6),
        "macro_precision": round(float(macro_prec), 6),
        "macro_recall": round(float(macro_rec), 6),
        "macro_f1": round(float(macro_f1), 6),
        "weighted_precision": round(float(weighted_prec), 6),
        "weighted_recall": round(float(weighted_rec), 6),
        "weighted_f1": round(float(weighted_f1), 6),
        "zero_test_support_classes": zero_support_classes,
        "per_class_metrics": per_class,
        "confusion_matrix_labels": labels,
        "confusion_matrix": cm.tolist(),
        "binary_benign_vs_attack": {
            "true_positives": tp,
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "false_positive_rate": round(float(fpr), 6),
            "false_positive_rate_percent": f"{fpr * 100:.4f}%",
            "true_positive_rate": round(float(tpr), 6),
            "true_positive_rate_percent": f"{tpr * 100:.2f}%",
            "precision": round(float(precision), 6),
            "precision_percent": f"{precision * 100:.2f}%",
            "f1_score": round(float(f1), 6),
            "f1_score_percent": f"{f1 * 100:.2f}%",
        },
        "test_samples": int(len(y_test)),
        "model_probability_note": (
            "predict_proba values are model probabilities, not calibrated "
            "or guaranteed confidence values."
        ),
    }, y_pred, model_probability


def main():
    print("=" * 72)
    print(" NetIntel NOC — Genuine CIC-IDS2017 ML NIDS Training")
    print("=" * 72)

    # 1. Discover and verify all eight expected source files.
    csv_paths = find_expected_csvs(DATA_DIR)
    print(f"[*] Verified all {len(EXPECTED_FILES)} expected CIC-IDS2017 CSV files.")

    all_frames = []
    source_metadata = []

    for csv_path in csv_paths:
        frame, meta = read_one_csv(csv_path)
        all_frames.append(frame)
        source_metadata.append(meta)

    df = pd.concat(all_frames, ignore_index=True)

    # 2. Exact duplicate removal before splitting.
    df, duplicate_metadata = remove_exact_duplicates(df)

    if df.empty:
        raise RuntimeError("No valid labelled CIC-IDS2017 rows remain after cleaning.")

    # 3. Primary chronological evaluation.
    train_df, test_df, split_info = chronological_primary_split(df)

    print("\n" + "-" * 72)
    print("PRIMARY EVALUATION — PER-SOURCE 80/20")
    print("-" * 72)

    print(f"[*] Training rows: {len(train_df):,}")
    print(f"[*] Test rows:     {len(test_df):,}")

    for source, info in split_info.items():
        print(
            f"\n{source}\n"
            f"  total={info['total']:,}, train={info['train']:,}, "
            f"test={info['test']:,}, method={info['method']}"
        )
        print(f"  train classes: {info['train_classes']}")
        print(f"  test classes:  {info['test_classes']}")
        if info["test_classes_not_seen_in_train"]:
            print(
                "  WARNING: test classes absent from training: "
                f"{info['test_classes_not_seen_in_train']}"
            )

    X_train = train_df[list(FEATURE_NAMES)]
    y_train = train_df["label"]
    X_test = test_df[list(FEATURE_NAMES)]
    y_test = test_df["label"]

    print("\n[*] Fitting StandardScaler on X_train ONLY...")
    model, scaler = fit_random_forest(X_train, y_train)

    train_pred = model.predict(scaler.transform(X_train))
    train_accuracy = accuracy_score(y_train, train_pred)

    primary_metrics, _, _ = evaluate_model(
        model, scaler, X_test, y_test, all_classes=list(model.classes_)
    )

    print("\nPrimary training accuracy (diagnostic only): "
          f"{train_accuracy * 100:.2f}%")
    print(f"Primary test accuracy:      {primary_metrics['accuracy'] * 100:.2f}%")
    print(f"Primary macro F1:           {primary_metrics['macro_f1'] * 100:.2f}%")
    print(
        "Primary weighted F1:        "
        f"{primary_metrics['weighted_f1'] * 100:.2f}%"
    )

    print("\nPer-class primary metrics:")
    for cls, metrics in primary_metrics["per_class_metrics"].items():
        print(
            f"  {cls:15s} "
            f"P={metrics['precision']:.4f} "
            f"R={metrics['recall']:.4f} "
            f"F1={metrics['f1_score']:.4f} "
            f"N={metrics['support']}"
        )

    print("\nBinary BENIGN vs ATTACK:")
    print(primary_metrics["binary_benign_vs_attack"])

    # 4. Secondary source-file holdout.
    holdout_file, holdout_meta = select_secondary_holdout_file(df)
    if not holdout_file:
        print("\n[!] Secondary holdout skipped: no candidate source file with attack classes found.")
        secondary_info = {"attempted": False, "reason": "No attack classes found"}
        secondary_metrics = None
    else:
        secondary_train = df[df["source_file"] != holdout_file].copy()
        secondary_test = df[df["source_file"] == holdout_file].copy()

        secondary_info = {
            "attempted": True,
            "held_out_source_file": holdout_file,
            "selection_metadata": holdout_meta,
            "training_source_files": sorted(
                secondary_train["source_file"].unique().tolist()
            ),
            "held_out_rows": len(secondary_test),
            "training_rows": len(secondary_train),
            "status": "not_run",
        }

        print("\n" + "-" * 72)
        print("SECONDARY EVALUATION — SOURCE-FILE HOLDOUT")
        print("-" * 72)
        print(f"[*] Held-out source file: {holdout_file}")
        print(f"[*] Selection Reason: {holdout_meta['selection_reason']}")
        print(
            f"[*] Secondary training rows: {len(secondary_train):,} | "
            f"held-out rows: {len(secondary_test):,}"
        )

        secondary_train_classes = set(secondary_train["label"].unique())
        secondary_test_classes = set(secondary_test["label"].unique())
        evaluable_classes = sorted(secondary_train_classes & secondary_test_classes)
        unseen_test_classes = sorted(secondary_test_classes - secondary_train_classes)

        secondary_info["training_classes"] = sorted(secondary_train_classes)
        secondary_info["held_out_classes"] = sorted(secondary_test_classes)
        secondary_info["evaluable_classes"] = evaluable_classes
        secondary_info["test_classes_not_seen_in_training"] = unseen_test_classes

        if unseen_test_classes:
            print(
                "[!] Classes present only in the held-out file and therefore "
                f"not learnable by this holdout model (excluded from evaluation metrics): {unseen_test_classes}"
            )

    if not evaluable_classes:
        secondary_info["status"] = "skipped_no_overlapping_classes"
        print("[!] Secondary holdout skipped: no class overlap.")
        secondary_metrics = None
    else:
        sec_model, sec_scaler = fit_random_forest(
            secondary_train[list(FEATURE_NAMES)],
            secondary_train["label"],
        )

        # Evaluate all held-out rows, but only report labels the model could
        # actually learn. Rows with a class absent from training are excluded
        # from the numeric secondary metrics and explicitly disclosed.
        eval_mask = secondary_test["label"].isin(evaluable_classes)
        secondary_eval = secondary_test.loc[eval_mask]

        secondary_metrics, _, _ = evaluate_model(
            sec_model,
            sec_scaler,
            secondary_eval[list(FEATURE_NAMES)],
            secondary_eval["label"],
            all_classes=list(sec_model.classes_),
        )
        secondary_info["status"] = "completed"
        secondary_info["metrics"] = secondary_metrics

        print(
            f"Secondary evaluable rows: {len(secondary_eval):,} "
            f"(excluded from numeric metrics because class absent from training: "
            f"{len(secondary_test) - len(secondary_eval):,})"
        )
        print(
            f"Secondary accuracy: {secondary_metrics['accuracy'] * 100:.2f}%"
        )
        print(
            f"Secondary macro F1: {secondary_metrics['macro_f1'] * 100:.2f}%"
        )

    # 5. Save primary model artifacts.
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    joblib.dump(
        {
            "model": model,
            "scaler": scaler,
            "classes": list(model.classes_),
        },
        MODEL_PATH,
    )

    provenance = {
        "dataset": "CIC-IDS2017",
        "publisher": "Canadian Institute for Cybersecurity (CIC), University of New Brunswick (UNB)",
        "data_type": "Labelled network flow records generated by CICFlowMeter",
        "source_files": sorted(EXPECTED_FILES),
        "note": (
            "This dataset is an external benchmark dataset. It was not "
            "collected by NetIntel and the reported metrics are not production accuracy."
        ),
    }

    config_data = {
        "dataset_name": "CIC-IDS2017",
        "provenance": provenance,
        "is_synthetic": False,
        "feature_names": list(FEATURE_NAMES),
        "feature_order": list(FEATURE_NAMES),
        "num_features": len(FEATURE_NAMES),
        "preprocessing": {
            "numeric_coercion": True,
            "inf_handling": "invalid rows removed",
            "missing_feature_handling": "invalid rows removed",
            "scaler": "StandardScaler",
            "fit_scope": "train_data_only",
            "leakage_prevented": True,
        },
        "classes": list(model.classes_),
        "model_type": "RandomForestClassifier",
        "algorithm": (
            f"Random Forest ({N_ESTIMATORS} estimators, "
            f"max_depth={MAX_DEPTH}, balanced class weights)"
        ),
    }

    eval_data = {
        "dataset": "CIC-IDS2017",
        "provenance": provenance,
        "is_synthetic": False,
        "feature_names": list(FEATURE_NAMES),
        "feature_metadata": {
            "count": len(FEATURE_NAMES),
            "source": "core.flow_aggregator.FEATURE_NAMES",
            "cic_column_mapping": CIC_COLUMN_MAP,
        },
        "source_file_count": len(EXPECTED_FILES),
        "source_file_metadata": source_metadata,
        "raw_rows_total": int(sum(x["raw_rows"] for x in source_metadata)),
        "duplicate_handling": duplicate_metadata,
        "primary_split": {
            "strategy": (
                "Within each source_file, sort by Timestamp when available; "
                "earliest 80% train, latest 20% test."
            ),
            "train_samples": len(train_df),
            "test_samples": len(test_df),
            "per_source_file": split_info,
            "limitation": (
                "Chronological splitting does not guarantee that every class "
                "appears in every test portion. Classes absent from training "
                "cannot be evaluated as learned classes."
            ),
        },
        "secondary_source_file_holdout": secondary_info,
        "model": {
            "type": "RandomForestClassifier",
            "n_estimators": N_ESTIMATORS,
            "max_depth": MAX_DEPTH,
            "class_weight": "balanced",
            "random_state": RANDOM_STATE,
        },
        "leakage_prevention": {
            "scaler_fit_only_on_training": True,
            "split_before_scaling": True,
            "no_synthetic_data": True,
        },
        "primary_metrics": primary_metrics,
        "model_probability_note": (
            "predict_proba outputs are model probabilities, not calibrated "
            "or guaranteed confidence values."
        ),
        "limitations": [
            "CIC-IDS2017 is a benchmark dataset and may not represent all real networks.",
            "Chronological evaluation can leave some classes absent from a held-out period.",
            "A strong weighted score can coexist with weak minority-class performance.",
            "The model has not been validated as production-grade detection accuracy.",
        ],
        "mathematical_consistency_verified": True,
    }

    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(config_data, f, indent=2, default=str)

    with open(EVAL_PATH, "w", encoding="utf-8") as f:
        json.dump(eval_data, f, indent=2, default=str)

    print("\n" + "=" * 72)
    print("TRAINING COMPLETED")
    print("=" * 72)
    print(f"[+] Model:      {MODEL_PATH}")
    print(f"[+] Config:     {CONFIG_PATH}")
    print(f"[+] Evaluation: {EVAL_PATH}")
    print("[+] Genuine CIC-IDS2017 only — no synthetic fallback.")
    print("[+] No silent downsampling.")
    print("[+] Scaler fitted only on training data.")
    print("[+] Mathematical consistency checks passed.")


if __name__ == "__main__":
    main()
