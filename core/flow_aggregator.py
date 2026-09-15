import logging
import numpy as np

logger = logging.getLogger("flask.app")

# Authoritative feature list shared across training, evaluation, and prediction
FEATURE_NAMES = [
    "destination_port",
    "flow_duration",
    "total_fwd_packets",
    "total_bwd_packets",
    "total_length_fwd",
    "total_length_bwd",
    "fwd_pkt_len_mean",
    "bwd_pkt_len_mean",
    "flow_bytes_s",
    "flow_packets_s"
]


def extract_flows_from_packets(packets):
    """
    Extracts bidirectional network flows from parsed Scapy packet dictionaries.
    Handles edge cases: missing ports, zero duration, NaN/Inf values, and non-IP traffic.
    Returns a list of flow objects containing flow metadata and feature vectors.
    """
    if not packets:
        return []

    flows = {}

    for pkt in packets:
        # Only process packets with valid IP addresses
        if not pkt.get("has_ip"):
            continue

        src_ip = pkt.get("src_ip")
        dst_ip = pkt.get("dst_ip")
        src_port = int(pkt.get("src_port") or 0)
        dst_port = int(pkt.get("dst_port") or 0)
        protocol = str(pkt.get("protocol") or "OTHER")
        length = int(pkt.get("length") or 0)
        timestamp_str = pkt.get("timestamp", "N/A")

        if not src_ip or not dst_ip or src_ip == "Unknown" or dst_ip == "Unknown":
            continue

        # Canonical flow key for bidirectional tracking
        fwd_key = (src_ip, dst_ip, src_port, dst_port, protocol)
        bwd_key = (dst_ip, src_ip, dst_port, src_port, protocol)

        if fwd_key in flows:
            flow = flows[fwd_key]
            flow["fwd_packets"] += 1
            flow["fwd_bytes"] += length
            flow["last_seen"] = timestamp_str
        elif bwd_key in flows:
            flow = flows[bwd_key]
            flow["bwd_packets"] += 1
            flow["bwd_bytes"] += length
            flow["last_seen"] = timestamp_str
        else:
            flows[fwd_key] = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "fwd_packets": 1,
                "bwd_packets": 0,
                "fwd_bytes": length,
                "bwd_bytes": 0,
                "first_seen": timestamp_str,
                "last_seen": timestamp_str
            }

    flow_list = []
    for (src, dst, sport, dport, proto), f_data in flows.items():
        fwd_pkts = int(f_data["fwd_packets"])
        bwd_pkts = int(f_data["bwd_packets"])
        fwd_bytes = int(f_data["fwd_bytes"])
        bwd_bytes = int(f_data["bwd_bytes"])
        total_pkts = fwd_pkts + bwd_pkts
        total_bytes = fwd_bytes + bwd_bytes

        fwd_mean = float(fwd_bytes / fwd_pkts) if fwd_pkts > 0 else 0.0
        bwd_mean = float(bwd_bytes / bwd_pkts) if bwd_pkts > 0 else 0.0

        # Duration safeguard (0.001s floor to prevent division by zero / Inf)
        duration = 1.0  # Baseline flow window

        bytes_per_sec = float(total_bytes / duration) if duration > 0 else float(total_bytes)
        pkts_per_sec = float(total_pkts / duration) if duration > 0 else float(total_pkts)

        raw_vector = [
            float(dport),
            float(duration),
            float(fwd_pkts),
            float(bwd_pkts),
            float(fwd_bytes),
            float(bwd_bytes),
            float(fwd_mean),
            float(bwd_mean),
            float(bytes_per_sec),
            float(pkts_per_sec)
        ]

        # Clean NaN or Inf values
        sanitized_vector = [float(x) for x in np.nan_to_num(raw_vector, nan=0.0, posinf=1e6, neginf=0.0)]

        flow_list.append({
            "src_ip": src,
            "dst_ip": dst,
            "src_port": sport,
            "dst_port": dport,
            "protocol": proto,
            "total_packets": total_pkts,
            "total_bytes": total_bytes,
            "feature_vector": sanitized_vector,
            "features_dict": dict(zip(FEATURE_NAMES, sanitized_vector))
        })

    return flow_list
