import logging
import ipaddress

logger = logging.getLogger("flask.app")


def _is_multicast_or_broadcast(ip_str):
    """
    Utility to check if an IP address is a multicast, broadcast, or discovery target.
    Filters:
    - 224.0.0.0/4 (IPv4 Multicast)
    - 255.255.255.255 & local subnet broadcast (.255)
    - ff00::/8 (IPv6 Multicast)
    - Unknown or invalid IP strings
    """
    if not ip_str or ip_str == "Unknown" or ip_str == "*":
        return True

    if ip_str == "255.255.255.255" or ip_str.endswith(".255"):
        return True

    if ip_str.lower().startswith("ff"):
        return True

    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_multicast:
            return True
    except ValueError:
        pass

    first_octet = ip_str.split(".")[0]
    if first_octet.isdigit() and 224 <= int(first_octet) <= 239:
        return True

    return False


def analyze_anomalies(parsed_data):
    """
    Transparent rule-based anomaly detection.

    Rules:
    1. High Packet Volume Source: Source generates >= 5% of IP traffic AND >= 100 packets.
    2. Possible Port Scan: Source contacts >= 15 unique destination ports.
    3. High Packet Frequency: Unicast source/destination pair has >= 100 packets.
    4. Protocol Spike: ICMP >= 30% OR UDP >= 50%
    """

    anomalies = []

    packets = parsed_data.get("packets", [])
    summary = parsed_data.get("summary", {})

    total_packets = summary.get("total_packets", 0)

    if total_packets == 0:
        return anomalies

    # =============================================================
    # Only real IP packets should be used for IP-based rules.
    # This prevents "Unknown" from becoming an anomaly source.
    # =============================================================

    ip_packets = [
        pkt
        for pkt in packets
        if pkt.get("has_ip") is True
    ]

    ip_total_packets = len(ip_packets)

    if ip_total_packets == 0:
        return anomalies

    # =============================================================
    # Rule 1
    # High Packet Volume Source
    # =============================================================

    src_ip_counts = {}
    src_dst_ports = {}

    for pkt in ip_packets:

        src = pkt.get("src_ip")

        if not src or src == "Unknown":
            continue

        # ---------------------------------------------------------
        # Source packet count
        # ---------------------------------------------------------
        src_ip_counts[src] = (
            src_ip_counts.get(src, 0) + 1
        )

        # ---------------------------------------------------------
        # Destination ports
        # ---------------------------------------------------------
        dst_port = pkt.get("dst_port", 0)

        if dst_port and dst_port > 0:

            if src not in src_dst_ports:
                src_dst_ports[src] = set()

            src_dst_ports[src].add(dst_port)

    for src_ip, count in src_ip_counts.items():

        pct = (count / ip_total_packets) * 100.0

        if pct >= 5.0 and count >= 100:

            anomalies.append(
                {
                    "id": f"ANOM-{len(anomalies) + 1}",

                    "src_ip": src_ip,
                    "dst_ip": "*",

                    "reason": "High Packet Volume Source",

                    "observed_value": (
                        f"{count} IP packets "
                        f"({pct:.1f}% of IP traffic)"
                    ),

                    "threshold": (
                        ">= 5% of IP packets "
                        "and >= 100 packets"
                    ),

                    "severity": (
                        "HIGH"
                        if pct >= 20.0
                        else "MEDIUM"
                    ),

                    "details": (
                        f"Source IP {src_ip} generated "
                        f"{count} of {ip_total_packets} "
                        f"IP packets."
                    ),
                }
            )

    # =============================================================
    # Rule 2
    # Possible Port Scan
    # =============================================================

    for src_ip, ports in src_dst_ports.items():

        unique_ports_count = len(ports)

        if unique_ports_count >= 15:

            anomalies.append(
                {
                    "id": f"ANOM-{len(anomalies) + 1}",

                    "src_ip": src_ip,
                    "dst_ip": "*",

                    "reason": "Possible Port Scan",

                    "observed_value": (
                        f"{unique_ports_count} "
                        f"unique destination ports"
                    ),

                    "threshold": (
                        ">= 15 unique destination ports"
                    ),

                    "severity": "HIGH",

                    "details": (
                        f"Source IP {src_ip} contacted "
                        f"{unique_ports_count} distinct "
                        f"destination ports."
                    ),
                }
            )

    # =============================================================
    # Rule 3
    # High Packet Frequency
    #
    # Evaluates unicast communication pairs (>= 100 packets).
    # Excludes multicast, broadcast, discovery, and Unknown addresses.
    # =============================================================

    communication_pairs = parsed_data.get(
        "_communication_pairs",
        []
    )

    for comm_data in communication_pairs:

        src_ip = comm_data.get("src_ip")
        dst_ip = comm_data.get("dst_ip")

        # Skip unknown / invalid / multicast / broadcast IP pairs
        if not src_ip or not dst_ip or src_ip == "Unknown" or dst_ip == "Unknown":
            continue

        if _is_multicast_or_broadcast(src_ip) or _is_multicast_or_broadcast(dst_ip):
            continue

        pkt_count = comm_data.get("packets", 0)

        if pkt_count >= 100:

            anomalies.append(
                {
                    "id": f"ANOM-{len(anomalies) + 1}",

                    "src_ip": src_ip,
                    "dst_ip": dst_ip,

                    "reason": "High Packet Frequency",

                    "observed_value": (
                        f"{pkt_count} packets between pair"
                    ),

                    "threshold": (
                        ">= 100 packets per unicast communication pair"
                    ),

                    "severity": "MEDIUM",

                    "details": (
                        f"High number of packets between a unicast communication pair "
                        f"({src_ip} and {dst_ip}: {pkt_count} packets)."
                    ),
                }
            )

    # =============================================================
    # Rule 4
    # Protocol Distribution Spike
    # =============================================================

    proto_dist = parsed_data.get(
        "protocol_distribution",
        {}
    )

    icmp_pct = proto_dist.get(
        "icmp_percentage",
        0.0
    )

    udp_pct = proto_dist.get(
        "udp_percentage",
        0.0
    )

    if total_packets >= 10:

        # ---------------------------------------------------------
        # ICMP spike
        # ---------------------------------------------------------
        if icmp_pct >= 30.0:

            anomalies.append(
                {
                    "id": f"ANOM-{len(anomalies) + 1}",

                    "src_ip": "*",
                    "dst_ip": "*",

                    "reason": "ICMP Protocol Spike",

                    "observed_value": (
                        f"{icmp_pct:.1f}% ICMP traffic"
                    ),

                    "threshold": (
                        ">= 30% ICMP distribution"
                    ),

                    "severity": "HIGH",

                    "details": (
                        f"ICMP represents "
                        f"{icmp_pct:.1f}% of the capture."
                    ),
                }
            )

        # ---------------------------------------------------------
        # UDP spike
        # ---------------------------------------------------------
        elif udp_pct >= 50.0:

            anomalies.append(
                {
                    "id": f"ANOM-{len(anomalies) + 1}",

                    "src_ip": "*",
                    "dst_ip": "*",

                    "reason": "UDP Protocol Spike",

                    "observed_value": (
                        f"{udp_pct:.1f}% UDP traffic"
                    ),

                    "threshold": (
                        ">= 50% UDP distribution"
                    ),

                    "severity": "MEDIUM",

                    "details": (
                        f"UDP represents "
                        f"{udp_pct:.1f}% of the capture."
                    ),
                }
            )

    logger.info(
        "Rule-based anomaly detection completed. "
        f"Evaluated {total_packets} packets, "
        f"{ip_total_packets} IP packets, "
        f"found {len(anomalies)} anomalies."
    )

    return anomalies