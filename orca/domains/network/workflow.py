"""
Network Protocol Domain Sub-Graph (QUIC Focus)

LangGraph sub-graph for network protocol analysis:
  1. pcap_ingest           — parse PCAP, extract UDP flows, compute traffic statistics
  2. traffic_statistics     — compute per-connection and aggregate statistics (no LLM)
  3. quic_handshake        — analyse handshake patterns, JA4 fingerprinting
  4. attack_classification — classify traffic as specific QUIC attack type
  5. anomaly_detect        — flag RFC non-conformance and protocol violations
"""
from __future__ import annotations
import json
from typing import Any, Dict, List
from langgraph.graph import StateGraph, END
from langchain_core.messages import AIMessage

from orca.core.state import OrcaWorkflowState
from orca.core.llm.provider import LLMProvider

llm = LLMProvider()


def _step(state, nd, step_name, msg):
    return {
        "network_domain": nd,
        "current_step": (state.get("current_step") or 0) + 1,
        "completed_steps": (state.get("completed_steps") or []) + [step_name],
        "messages": [AIMessage(content=msg)],
    }


# ── Agent: PCAP Ingestion ─────────────────────────────────────

def pcap_ingest_agent(state: OrcaWorkflowState) -> Dict:
    """Parse PCAP with scapy, extract UDP flows, compute per-flow packet counts."""
    nd = state.get("network_domain") or {}
    pcap_path = state.get("pcap_path")

    if not pcap_path:
        return _step(state, nd, "pcap_ingest", "PCAP ingestion skipped — no pcap_path provided.")

    try:
        from scapy.all import rdpcap, UDP
        packets = rdpcap(pcap_path)
        udp_packets = [p for p in packets if p.haslayer(UDP)]

        # Extract all UDP flows
        flows = {}
        for pkt in udp_packets:
            udp = pkt[UDP]
            src_ip = pkt.src if hasattr(pkt, 'src') else ''
            dst_ip = pkt.dst if hasattr(pkt, 'dst') else ''
            flow_key = (src_ip, udp.sport, dst_ip, udp.dport)
            reverse_key = (dst_ip, udp.dport, src_ip, udp.sport)

            if flow_key not in flows and reverse_key not in flows:
                flows[flow_key] = {
                    "src_ip": src_ip, "src_port": udp.sport,
                    "dst_ip": dst_ip, "dst_port": udp.dport,
                    "packets_sent": 0, "packets_received": 0,
                    "bytes_sent": 0, "bytes_received": 0,
                    "first_seen": float(pkt.time), "last_seen": float(pkt.time),
                }

            if flow_key in flows:
                flows[flow_key]["packets_sent"] += 1
                flows[flow_key]["bytes_sent"] += len(pkt)
                flows[flow_key]["last_seen"] = max(flows[flow_key]["last_seen"], float(pkt.time))
            elif reverse_key in flows:
                flows[reverse_key]["packets_received"] += 1
                flows[reverse_key]["bytes_received"] += len(pkt)
                flows[reverse_key]["last_seen"] = max(flows[reverse_key]["last_seen"], float(pkt.time))

        # Filter to QUIC-relevant flows
        connections = []
        for flow_key, flow in flows.items():
            quic_ports = (443, 4433, 4434, 4435, 4436, 4437, 4438, 4567, 8443)
            is_quic = flow["dst_port"] in quic_ports or flow["src_port"] in quic_ports
            if is_quic or len(flows) < 500:
                flow["total_packets"] = flow["packets_sent"] + flow["packets_received"]
                flow["duration"] = round(flow["last_seen"] - flow["first_seen"], 4)
                flow["bidirectional"] = flow["packets_received"] > 0
                connections.append(flow)

        # Compute capture duration
        if udp_packets:
            capture_start = float(udp_packets[0].time)
            capture_end = float(udp_packets[-1].time)
            capture_duration = round(capture_end - capture_start, 2)
        else:
            capture_duration = 0

        nd["pcap_path"] = pcap_path
        nd["connections"] = connections
        nd["total_packets"] = len(packets)
        nd["udp_packets"] = len(udp_packets)
        nd["capture_duration_seconds"] = capture_duration

        return _step(state, nd, "pcap_ingest",
                     f"PCAP ingested — {len(connections)} flows, {len(udp_packets)} UDP packets, {capture_duration}s duration.")
    except ImportError:
        return _step(state, nd, "pcap_ingest", "PCAP ingestion failed — scapy not installed.")
    except Exception as exc:
        nd["error"] = str(exc)
        return _step(state, nd, "pcap_ingest", f"PCAP ingestion failed: {exc}")


# ── Agent: Traffic Statistics (no LLM) ───────────────────────

def traffic_statistics_agent(state: OrcaWorkflowState) -> Dict:
    """Compute statistical features from connection data. No LLM call."""
    nd = state.get("network_domain") or {}
    connections = nd.get("connections", [])
    duration = nd.get("capture_duration_seconds", 0)

    if not connections:
        nd["statistics"] = {}
        return _step(state, nd, "traffic_statistics", "Statistics skipped — no connections.")

    total_connections = len(connections)
    total_packets = sum(c.get("total_packets", 0) for c in connections)
    bidirectional = sum(1 for c in connections if c.get("bidirectional"))
    unidirectional = total_connections - bidirectional
    packets_per_conn = [c.get("total_packets", 0) for c in connections]
    durations = [c.get("duration", 0) for c in connections]

    # Unique source ports (indicator of many different clients or spoofed sources)
    unique_src_ports = len(set(c.get("src_port") for c in connections))

    # Handshake completion estimate: bidirectional flows with >3 packets
    completed_handshakes = sum(1 for c in connections if c.get("bidirectional") and c.get("total_packets", 0) > 3)
    handshake_completion_rate = round(completed_handshakes / max(total_connections, 1), 3)

    # Single-packet flows (incomplete connections)
    single_packet_flows = sum(1 for c in connections if c.get("total_packets", 0) == 1)
    single_packet_ratio = round(single_packet_flows / max(total_connections, 1), 3)

    # Connections per second
    connections_per_second = round(total_connections / max(duration, 0.1), 2)

    # Packet size statistics
    avg_packets_per_conn = round(sum(packets_per_conn) / max(len(packets_per_conn), 1), 2)
    max_packets_per_conn = max(packets_per_conn) if packets_per_conn else 0
    min_packets_per_conn = min(packets_per_conn) if packets_per_conn else 0

    stats = {
        "total_connections": total_connections,
        "total_packets": total_packets,
        "capture_duration_seconds": duration,
        "connections_per_second": connections_per_second,
        "bidirectional_flows": bidirectional,
        "unidirectional_flows": unidirectional,
        "unique_source_ports": unique_src_ports,
        "handshake_completion_rate": handshake_completion_rate,
        "single_packet_flows": single_packet_flows,
        "single_packet_ratio": single_packet_ratio,
        "avg_packets_per_connection": avg_packets_per_conn,
        "max_packets_per_connection": max_packets_per_conn,
        "min_packets_per_connection": min_packets_per_conn,
    }

    # LLM interprets the statistical profile
    try:
        llm_stats = llm.query_json(
            system="You are a network traffic analyst examining QUIC protocol traffic statistics.",
            user=f"""Interpret these traffic statistics from a QUIC capture:

- Total connections: {total_connections}
- Capture duration: {duration} seconds
- Connections per second: {connections_per_second}
- Bidirectional flows: {bidirectional} ({round(bidirectional/max(total_connections,1)*100,1)}%)
- Unidirectional flows: {unidirectional} ({round(unidirectional/max(total_connections,1)*100,1)}%)
- Handshake completion rate: {handshake_completion_rate}
- Single-packet flows: {single_packet_flows} ({single_packet_ratio} ratio)
- Avg packets per connection: {avg_packets_per_conn}
- Min/Max packets per connection: {min_packets_per_conn}/{max_packets_per_conn}
- Unique source ports: {unique_src_ports}

What do these statistics suggest about the nature of this traffic? Is it normal, or does it show signs of an attack? Explain your reasoning.

Return JSON: {{
    "traffic_profile": "normal|high_volume|burst_pattern|probe_pattern|mixed",
    "notable_findings": ["list of significant observations"],
    "preliminary_assessment": "explanation of what these numbers suggest"
}}""",
        )
        stats["llm_interpretation"] = llm_stats
    except Exception:
        pass

    nd["statistics"] = stats

    return _step(state, nd, "traffic_statistics",
                 f"Statistics: {total_connections} connections, {connections_per_second} conn/s, "
                 f"handshake completion {handshake_completion_rate}, single-packet ratio {single_packet_ratio}.")


# ── Agent: QUIC Handshake Analysis ────────────────────────────

def quic_handshake_agent(state: OrcaWorkflowState) -> Dict:
    """Analyse QUIC handshake patterns and JA4 fingerprints."""
    nd = state.get("network_domain") or {}
    connections = nd.get("connections", [])
    pcap_path = nd.get("pcap_path") or state.get("pcap_path")

    if not connections:
        return _step(state, nd, "quic_handshake", "Handshake analysis skipped — no connections.")

    # JA4 fingerprinting
    ja4_results = []
    if pcap_path:
        try:
            from orca.domains.network.ja4_fingerprinter import JA4Fingerprinter
            fingerprinter = JA4Fingerprinter()
            ja4_results = fingerprinter.extract_from_pcap(pcap_path)
            nd["ja4_fingerprints"] = ja4_results
        except Exception:
            pass

    try:
        stats = nd.get("statistics", {})
        data = {
            "connections_sample": connections[:15],
            "statistics": stats,
            "ja4_fingerprints": ja4_results[:10],
        }
        result = llm.query_json(
            system="You are a QUIC protocol analyst with knowledge of RFC 9000, RFC 9001, and RFC 9114.",
            user=f"""Examine these QUIC connection flows and statistics.

For each connection, determine:
- Whether the handshake completed (bidirectional with >3 packets = likely complete)
- Whether transport parameters appear normal
- Whether connection IDs follow expected patterns

Statistics show: {stats.get('total_connections', 0)} connections, {stats.get('connections_per_second', 0)} connections/sec, handshake completion rate {stats.get('handshake_completion_rate', 0)}, single-packet ratio {stats.get('single_packet_ratio', 0)}.

Return JSON: {{"handshake_summary": "...", "completed_handshakes_estimate": 0, "failed_handshakes_estimate": 0, "suspicious_findings": [...]}}

Data: {json.dumps(data, default=str)[:3000]}""",
        )
        nd["handshake_analysis"] = result
        ja4_info = f", {len(ja4_results)} JA4 fingerprints" if ja4_results else ""
        return _step(state, nd, "quic_handshake", f"Handshake analysis done{ja4_info}.")
    except Exception as exc:
        return _step(state, nd, "quic_handshake", f"Handshake analysis failed: {exc}")


# ── Agent: Attack Classification ─────────────────────────────

def _detect_bursts(connections_list, gap_seconds: float = 1.0, min_burst: int = 5):
    """Return list of burst sizes detected in connection start times."""
    first_times = sorted(c.get("first_seen", 0) for c in connections_list if c.get("first_seen"))
    if not first_times:
        return []
    bursts = []
    current = 1
    for i in range(1, len(first_times)):
        if first_times[i] - first_times[i-1] < gap_seconds:
            current += 1
        else:
            if current > min_burst:
                bursts.append(current)
            current = 1
    if current > min_burst:
        bursts.append(current)
    return bursts


CLASSIFIER_SYSTEM_PROMPT = """You are a network security analyst specialising in QUIC protocol attacks.

You must classify the traffic into exactly ONE of these categories:

1. NORMAL — Legitimate QUIC traffic. Characteristics: high handshake completion (>=0.9), all or nearly all bidirectional flows, single_packet_ratio near 0, consistent packet counts. Connection rate alone is NOT an attack signal — a fast benign client (load test, scripted download loop) can exceed 10 conn/sec while still completing every handshake. Identical byte counts across connections is NORMAL when clients request the same resource.

2. FLOODING_DOS — Connection flooding denial of service. Characteristics: high connection rate (>10/sec) combined with signs that the server is struggling — LOW handshake completion, many unidirectional or single-packet flows, or far fewer observed connections than the attacker attempted. A flood absorbed cleanly by a resilient server IS still a flood — the distinguishing signal from a benign fast client is sustained volume (hundreds to thousands of connections over tens of seconds).

3. SLOWLORIS_DOS — Slow connection exhaustion. Characteristics: connections arrive in bursts (many at once, then silence, then another burst), moderate total connection count but periodic pattern, designed to hold server resources.

4. CONNECTION_ID_MANIPULATION — Forged QUIC packets with random/invalid connection IDs. Characteristics: single_packet_ratio >= 0.9, handshake_completion_rate ~0, all or nearly all unidirectional flows, uniform packet sizes. Distinct from FLOODING_DOS even at high rates: the defining signal is that NO connection ever completes.

5. MAN_IN_THE_MIDDLE — Attacker intercepting and injecting forged packets alongside legitimate traffic. Characteristics: roughly equal counts of bidirectional and unidirectional flows in the SAME capture (the bidir half is legit, the unidir half is forged/dropped), handshake_completion_rate between 0.4 and 0.7. The legitimate bidirectional flows may be short — MitM is identified by the SPLIT pattern, not by heavy data exchange.

6. UNKNOWN_ATTACK — Reserved for traffic that does not fit ANY category above within its stated tolerances. Do not use this when a specific rule matches.

DECISION RULES (evaluate in order — FIRST MATCH WINS; do not fall through to UNKNOWN when a rule matches):

Rule A. single_packet_ratio >= 0.9 AND handshake_completion_rate <= 0.05 AND unidirectional_flows >= 0.9 * total_connections
        → CONNECTION_ID_MANIPULATION. Takes precedence over FLOODING_DOS regardless of connection rate — zero completion rules out flooding.

Rule B. 0.4 <= handshake_completion_rate <= 0.7 AND bidirectional_flows and unidirectional_flows are each within 30% of total_connections / 2
        → MAN_IN_THE_MIDDLE. The even split is the authoritative signal. Do not downgrade to UNKNOWN because the bidirectional flows look "short" or "systematic" — scripted MitM test traffic is expected to look systematic.

Rule C. `Burst pattern detected` line in the prompt indicates >= 3 bursts with >= 10 connections each
        → SLOWLORIS_DOS. Absolute precedence over Rules D, E, E2.

Rule D. handshake_completion_rate >= 0.9 AND single_packet_ratio <= 0.05 AND unidirectional_flows == 0
        AND (connections_per_second <= 10 OR total_connections < 100 OR capture_duration_seconds < 30)
        AND no burst pattern detected
        → NORMAL. A fast benign client (scripted download loop, load test) can exceed 10 conn/sec briefly — identified by short duration (<30s) or low total volume (<100).

Rule E. connections_per_second > 10 AND (handshake_completion_rate < 0.5 OR single_packet_ratio > 0.3 OR unidirectional_flows > 0.2 * total_connections)
        → FLOODING_DOS (with server distress).

Rule E2. connections_per_second > 10 AND total_connections >= 100 AND capture_duration_seconds >= 30
        → FLOODING_DOS (sustained flood absorbed cleanly is still a flood — server accepting every connection is vulnerable, not innocent).

Rule F. None of the above match within their tolerances → UNKNOWN_ATTACK.

Rules are evaluated in order A → B → C → D → E → E2 → F. First match wins. Ignore the preliminary `traffic_profile` label in the supplied llm_interpretation — apply the rules directly to the numeric statistics."""


def _classifier_user_prompt(stats, handshake, burst_info, data):
    return f"""Classify this QUIC traffic.

Traffic statistics:
- Total connections: {stats.get('total_connections', 0)}
- Capture duration: {stats.get('capture_duration_seconds', 0)} seconds
- Connections per second: {stats.get('connections_per_second', 0)}
- Bidirectional flows: {stats.get('bidirectional_flows', 0)}
- Unidirectional flows: {stats.get('unidirectional_flows', 0)}
- Handshake completion rate: {stats.get('handshake_completion_rate', 0)}
- Single-packet flows: {stats.get('single_packet_flows', 0)} ({stats.get('single_packet_ratio', 0)} ratio)
- Avg packets per connection: {stats.get('avg_packets_per_connection', 0)}
- Unique source ports: {stats.get('unique_source_ports', 0)}{burst_info}

Handshake analysis: {json.dumps(handshake, default=str)[:1000]}

Return JSON:
{{
  "classification": "NORMAL|FLOODING_DOS|SLOWLORIS_DOS|CONNECTION_ID_MANIPULATION|MAN_IN_THE_MIDDLE|UNKNOWN_ATTACK",
  "confidence": 0.0-1.0,
  "evidence": ["list of specific indicators that support the classification"],
  "description": "one paragraph explaining the classification and what the traffic shows"
}}

Data: {json.dumps(data, default=str)[:2000]}"""


CLASSIFIER_VOTES = 5


def attack_classification_agent(state: OrcaWorkflowState) -> Dict:
    """Classify traffic as a specific QUIC attack type via LLM self-consistency voting.

    Runs the classifier CLASSIFIER_VOTES times and takes the majority label
    (Wang et al. 2022, self-consistency). This tightens reproducibility on
    borderline cases where a single LLM call drifts, while keeping the
    classification step LLM-driven for the paper's cross-domain thesis.
    """
    nd = state.get("network_domain") or {}
    stats = nd.get("statistics", {})
    handshake = nd.get("handshake_analysis", {})

    if not stats:
        return _step(state, nd, "attack_classification", "Classification skipped — no statistics.")

    try:
        data = {
            "statistics": stats,
            "handshake_analysis": handshake,
            "connections_sample": nd.get("connections", [])[:10],
        }

        connections_list = nd.get("connections", [])
        bursts = _detect_bursts(connections_list) if connections_list and stats.get("capture_duration_seconds", 0) > 10 else []
        burst_info = f"\n- Burst pattern detected: {len(bursts)} bursts of {bursts[:5]} connections each" if bursts else ""

        user_prompt = _classifier_user_prompt(stats, handshake, burst_info, data)

        votes = []
        responses = []
        for _ in range(CLASSIFIER_VOTES):
            try:
                r = llm.query_json(system=CLASSIFIER_SYSTEM_PROMPT, user=user_prompt)
                label = r.get("classification", "UNKNOWN_ATTACK")
                votes.append(label)
                responses.append(r)
            except Exception:
                continue

        if not votes:
            raise RuntimeError("All classifier votes failed")

        # Majority vote; ties broken by first-seen order
        tally = {}
        for v in votes:
            tally[v] = tally.get(v, 0) + 1
        winner = max(tally, key=lambda k: (tally[k], -votes.index(k)))
        agreement = tally[winner] / len(votes)

        # Take the first response matching the winning label for evidence/description
        result = next(r for r, v in zip(responses, votes) if v == winner)
        result["classification"] = winner
        result["self_consistency"] = {
            "votes": votes,
            "agreement": round(agreement, 3),
            "tally": tally,
        }

        nd["attack_classification"] = result
        return _step(state, nd, "attack_classification",
                     f"Classification: {winner} (agreement {agreement:.0%}, {tally[winner]}/{len(votes)} votes).")
    except Exception as exc:
        nd["attack_classification"] = {"classification": "ERROR", "error": str(exc)}
        return _step(state, nd, "attack_classification", f"Classification failed: {exc}")


# ── Agent: Anomaly Detection ──────────────────────────────────

def anomaly_detection_agent(state: OrcaWorkflowState) -> Dict:
    """Flag specific RFC 9000 violations and protocol anomalies."""
    nd = state.get("network_domain") or {}
    stats = nd.get("statistics", {})
    classification = nd.get("attack_classification", {})

    try:
        data = {
            "statistics": stats,
            "classification": classification,
            "connections_sample": nd.get("connections", [])[:10],
            "handshake": nd.get("handshake_analysis", {}),
        }
        result = llm.query_json(
            system="You are a QUIC protocol security researcher with detailed knowledge of RFC 9000.",
            user=f"""Based on the traffic classification ({classification.get('classification', 'unknown')}) and statistics, identify specific protocol violations and security concerns.

For each finding, cite the specific RFC 9000 section that is relevant.

Focus on:
- Incomplete handshakes (RFC 9000 Section 7)
- Connection ID handling violations (RFC 9000 Section 5.1)
- Amplification attack indicators (RFC 9000 Section 8)
- Connection migration anomalies (RFC 9000 Section 9)
- Flow control violations (RFC 9000 Section 4)

Return JSON: {{"anomalies": [{{"type": "...", "description": "...", "severity": "high|medium|low", "rfc_section": "...", "recommendation": "..."}}]}}

Data: {json.dumps(data, default=str)[:3000]}""",
        )
        nd["anomalies"] = result
        return _step(state, nd, "anomaly_detection",
                     f"Anomaly detection done — {len(result.get('anomalies', []))} findings.")
    except Exception as exc:
        return _step(state, nd, "anomaly_detection", f"Anomaly detection failed: {exc}")


# ── Agent: QUIC Binary Security Assessment ────────────────────

def quic_binary_assessment_agent(state: OrcaWorkflowState) -> Dict:
    """Analyse QUIC-specific functions in the binary for security properties.

    This is the cross-domain agent: it takes the attack classification from
    traffic analysis and examines the binary to explain WHY the attack
    works or doesn't work against this implementation.

    Unlike other agents, this one reopens the binary and specifically searches
    for QUIC-related functions by name pattern, then decompiles them directly.
    This avoids relying on the generic top-N enrichment which may miss
    security-critical QUIC functions.
    """
    nd = state.get("network_domain") or {}
    bd = state.get("binary_domain") or {}
    sa = bd.get("static_analysis", {})
    classification = nd.get("attack_classification", {})
    attack_type = classification.get("classification", "UNKNOWN")
    traffic_stats = nd.get("statistics", {})

    if not sa or sa.get("error"):
        return _step(state, nd, "quic_binary_assessment", "QUIC binary assessment skipped — no binary analysis data.")

    # QUIC keywords — match broadly to catch all QUIC-related functions
    QUIC_KEYWORDS = [
        "quic", "h3", "http3", "http_v3",
        "picoquic", "ngtcp2", "lsquic", "msquic", "quiche",
    ]
    # Secondary keywords for non-QUIC-prefixed security functions
    SECURITY_KEYWORDS = [
        "flood", "limit", "rate", "throttle", "timeout", "idle",
        "amplif", "migration", "path_valid", "connid", "conn_id",
        "retry", "token", "replay", "early_data", "0rtt",
        "close_connection", "shutdown", "reset", "reject",
        "stream", "crypto", "ssl", "tls", "handshake",
        # Connection management patterns
        "busy", "refuse", "incoming", "accept", "max_conn",
        "max_half_open", "adjust_max", "connection_limit",
        "too_many", "overload", "backpressure",
    ]

    # Step 1: Reopen the binary — do a FULL function name census + targeted decompilation
    binary_path = state.get("binary_path")
    quic_functions = []
    function_name_census = {}  # Maps security category -> list of function names

    # Security mechanism indicators — if a function name contains these, the mechanism likely exists
    MECHANISM_INDICATORS = {
        "connection_limits": ["max_conn", "adjust_max", "max_number", "max_inchoate", "max_half_open",
                              "server_busy", "queue_busy", "too_many", "connection_limit", "reject_conn"],
        "rate_limiting": ["rate_limit", "throttle", "flood", "cooldown", "batch_size", "shrink_batch",
                          "max_packets", "pacing", "max_operations", "noprogress"],
        "anti_amplification": ["amplif", "amp_factor", "path_limit", "path_allowance", "bytes_recv",
                               "bytes_sent", "anti_amp", "validated_path", "dcid_tx_left"],
        "connection_id_validation": ["validate_cid", "verify_cid", "connection_id_frame", "retire_cid",
                                     "new_connection_id", "retire_connection_id", "cid_sequence", "dcid"],
        "idle_timeout": ["idle_timeout", "idle_conn", "noprogress_timeout", "max_idle", "close_idle"],
        "retry_and_tokens": ["retry", "token", "stateless_reset", "new_token", "verify_token",
                             "validate_token", "send_retry", "queue_retry"],
        "path_validation": ["path_challenge", "path_response", "path_valid", "migration"],
        "anti_replay": ["replay", "early_data", "0rtt", "pn_already_received", "max_pkt_num"],
    }

    if binary_path:
        try:
            from pathlib import Path
            from orca.core.re_backends.selector import REBackendSelector
            from orca.core.models import REBackendType

            selector = REBackendSelector()
            backends = selector.select(Path(binary_path))
            backend = None
            for attempt in [backends[0], REBackendType.BINARY_NINJA, REBackendType.GHIDRA]:
                try:
                    candidate = selector.create_backend(attempt, Path(binary_path))
                    candidate.open()
                    backend = candidate
                    break
                except Exception:
                    continue

            if backend:
                try:
                    all_functions = backend.get_functions()

                    # PHASE 1: Function name census — scan ALL function names
                    all_names = [f.name for f in all_functions]
                    for category, indicators in MECHANISM_INDICATORS.items():
                        matches = []
                        for name in all_names:
                            name_lower = name.lower()
                            if any(ind in name_lower for ind in indicators):
                                matches.append(name)
                        if matches:
                            function_name_census[category] = matches

                    # Also scan binary strings for mechanism indicators
                    raw_strings = sa.get("strings", {}).get("raw", [])
                    string_indicators = {
                        "connection_limits": ["server busy", "max connections", "too many connections",
                                              "connection limit", "max_nb_connections"],
                        "rate_limiting": ["rate limit", "flood detected", "too many requests"],
                        "anti_amplification": ["amplification", "anti-amplification", "amp factor"],
                        "idle_timeout": ["idle timeout", "connection timed out", "noprogress"],
                    }
                    for category, phrases in string_indicators.items():
                        for s in raw_strings[:500]:
                            s_lower = s.lower()
                            if any(phrase in s_lower for phrase in phrases):
                                if category not in function_name_census:
                                    function_name_census[category] = []
                                function_name_census[category].append(f"STRING: {s[:80]}")
                                break

                    # PHASE 2: Targeted decompilation of security-relevant functions
                    tier1_names = []
                    tier2_names = []
                    tier3_names = []
                    for f in all_functions:
                        name_lower = f.name.lower()
                        is_quic = any(kw in name_lower for kw in QUIC_KEYWORDS)
                        is_security = any(kw in name_lower for kw in SECURITY_KEYWORDS)
                        if is_quic and is_security:
                            tier1_names.append(f.name)
                        elif is_quic:
                            tier2_names.append(f.name)
                        elif is_security:
                            tier3_names.append(f.name)

                    max_funcs = 80
                    quic_func_names = tier1_names[:max_funcs]
                    remaining = max_funcs - len(quic_func_names)
                    if remaining > 0:
                        quic_func_names += tier2_names[:remaining]
                        remaining = max_funcs - len(quic_func_names)
                    if remaining > 0:
                        quic_func_names += tier3_names[:remaining]

                    tier1_set = set(tier1_names)
                    for fname in quic_func_names[:max_funcs]:
                        max_chars = 2500 if fname in tier1_set else 1500
                        enrichment = backend.enrich_function(fname, max_decompiled_chars=max_chars)
                        code = enrichment.get("decompiled_code", "")
                        if code:
                            quic_functions.append({
                                "name": fname,
                                "code": code,
                            })
                finally:
                    backend.close()
        except Exception as exc:
            pass  # Fall back to pre-enriched functions below

    # Step 2: If direct decompilation didn't work, fall back to pre-enriched
    if not quic_functions:
        enriched = sa.get("enriched_functions", [])
        for f in enriched:
            name = f.get("name", "").lower()
            if any(kw in name for kw in QUIC_KEYWORDS + SECURITY_KEYWORDS):
                code = f.get("decompiled_code", "")
                if code:
                    quic_functions.append({
                        "name": f.get("name"),
                        "code": code[:800],
                    })

    # Also check imports for QUIC-related APIs
    imports = sa.get("imports", [])
    quic_imports = [i for i in imports if any(kw in i.lower() for kw in ["quic", "h3", "http3", "ssl", "tls", "crypto"])]

    if not quic_functions and not quic_imports:
        nd["quic_binary_assessment"] = {"assessment": "No QUIC-specific code found in binary"}
        return _step(state, nd, "quic_binary_assessment", "No QUIC functions found in binary.")

    # Build function summaries — group by category for the LLM
    func_by_category = {
        "security_and_validation": [],
        "connection_management": [],
        "stream_and_flow_control": [],
        "crypto_and_tls": [],
        "other_quic": [],
    }
    for f in quic_functions:
        name_lower = f["name"].lower()
        if any(kw in name_lower for kw in ["flood", "limit", "rate", "throttle", "amplif", "retry", "token", "reject", "replay", "valid", "path_limit", "path_challenge", "path_response", "new_connection_id", "retire_connection_id", "new_sr_token", "new_token", "send_retry", "busy", "refuse", "max_conn", "max_half_open", "adjust_max", "incoming_client_initial", "overload"]):
            func_by_category["security_and_validation"].append(f)
        elif any(kw in name_lower for kw in ["close", "shutdown", "timeout", "idle", "migration", "init_connection", "finalize"]):
            func_by_category["connection_management"].append(f)
        elif any(kw in name_lower for kw in ["stream", "flow", "blocked", "max_data", "max_stream"]):
            func_by_category["stream_and_flow_control"].append(f)
        elif any(kw in name_lower for kw in ["crypto", "ssl", "tls", "handshake", "cipher", "encrypt", "decrypt", "seal", "key"]):
            func_by_category["crypto_and_tls"].append(f)
        else:
            func_by_category["other_quic"].append(f)

    # Build a condensed view — full code for security functions, shorter for others
    func_text_parts = []
    for cat, funcs in func_by_category.items():
        if not funcs:
            continue
        func_text_parts.append(f"\n=== {cat.upper()} ({len(funcs)} functions) ===")
        if cat == "security_and_validation":
            # Full code for ALL security-critical functions
            for f in funcs[:15]:
                func_text_parts.append(f"\n--- {f['name']} ---\n{f['code'][:1500]}")
        elif cat == "connection_management":
            for f in funcs[:8]:
                func_text_parts.append(f"\n--- {f['name']} ---\n{f['code'][:1000]}")
        elif cat == "stream_and_flow_control":
            # Stream limits are relevant to connection limits
            for f in funcs[:6]:
                func_text_parts.append(f"\n--- {f['name']} ---\n{f['code'][:800]}")
        else:
            # Names and short snippet for others
            for f in funcs[:5]:
                func_text_parts.append(f"\n--- {f['name']} ---\n{f['code'][:300]}")

    func_text = "\n".join(func_text_parts)[:12000]

    # Pre-compute census summary for the JSON template
    census_summary = {k: len(v) for k, v in function_name_census.items()}

    # Build traffic context for cross-domain reasoning
    traffic_context = ""
    if traffic_stats:
        total_conns = traffic_stats.get('total_connections', 0)
        capture_dur = traffic_stats.get('capture_duration_seconds', 0)
        total_pkts = traffic_stats.get('total_packets', 0)
        avg_pkts = traffic_stats.get('avg_packets_per_connection', 0)

        # For flooding attacks, estimate expected connections based on attack duration
        # Typical flooding sends ~20 connections/sec for 120 seconds = ~2400 attempts
        flood_context = ""
        if attack_type == "FLOODING_DOS" and capture_dur and total_conns:
            expected_conns = int(capture_dur * 20)  # ~20 attempts/sec is typical
            hs_rate = traffic_stats.get('handshake_completion_rate', 0) or 0
            completed = int(total_conns * hs_rate)
            failed_hs = total_conns - completed
            conn_accept_ratio = total_conns / max(expected_conns, 1)

            if conn_accept_ratio < 0.8:
                conn_level = f"CONNECTION-LEVEL REJECTION: {expected_conns - total_conns} of ~{expected_conns} expected attempts were dropped before appearing as flows ({(1 - conn_accept_ratio) * 100:.0f}% rejection)."
            else:
                conn_level = f"NO CONNECTION-LEVEL REJECTION: {total_conns} of ~{expected_conns} expected attempts were accepted as flows ({conn_accept_ratio * 100:.0f}%)."

            if hs_rate < 0.7:
                hs_level = f"HANDSHAKE-LEVEL REJECTION: only {completed} of {total_conns} accepted connections completed a handshake ({hs_rate * 100:.0f}%). {failed_hs} connections were established but then blocked mid-handshake — consistent with retry-token / path-validation enforcement that degrades attack success without refusing connections outright."
            else:
                hs_level = f"NO HANDSHAKE-LEVEL REJECTION: {completed} of {total_conns} connections completed the handshake ({hs_rate * 100:.0f}%). Mechanisms that typically degrade handshake completion (retry tokens, path validation) did not meaningfully activate."

            flood_context = f"""
- Flooding analysis (expected ~{expected_conns} attempts at 20/sec over {capture_dur:.0f}s):
  1. {conn_level}
  2. {hs_level}

RESILIENCE RUBRIC for FLOODING_DOS, apply strictly. Grades combine TRAFFIC evidence (connection acceptance and handshake completion) with BINARY evidence (the function name census below):
  * high     : connection-level rejection (<80% of expected attempts accepted) OR handshake completion below 30%. The server actively blocked the flood.
  * medium   : most connections accepted AND handshake completion between 30% and 70%. Mechanisms activated and degraded attack success without refusing connections.
  * low      : most connections accepted AND handshake completion >= 70%, AND the function name census shows flood-mitigation mechanisms exist in the binary (any of: rate_limiting, connection_limits, anti_amplification with non-zero counts). The mechanism is present in code but did not meaningfully activate against this attack.
  * none     : most connections accepted AND handshake completion >= 70%, AND the function name census shows NO flood-mitigation mechanisms (rate_limiting, connection_limits, and anti_amplification are all absent or zero). No relevant protection exists in the binary at all.
  The low-vs-none distinction is the cross-domain signal: traffic cannot separate them, the binary can."""

        traffic_context = f"""
TRAFFIC OBSERVATIONS (from the actual network capture):
- Total connections: {total_conns}
- Connections per second: {traffic_stats.get('connections_per_second', '?')}
- Handshake completion rate: {traffic_stats.get('handshake_completion_rate', '?')}
- Bidirectional flows: {traffic_stats.get('bidirectional_flows', '?')}
- Unidirectional flows: {traffic_stats.get('unidirectional_flows', '?')}
- Average packets per connection: {avg_pkts}
- Total packets: {total_pkts}
- Capture duration: {capture_dur:.1f} seconds{flood_context}
"""

    try:
        result = llm.query_json(
            system="""You are a security researcher performing cross-domain analysis: correlating what you see in the compiled QUIC binary with what actually happened in the network traffic.

You have TWO sources of evidence:
1. DECOMPILED CODE from the QUIC binary — showing what security mechanisms exist
2. TRAFFIC STATISTICS from a real attack — showing how the server actually behaved

Your job is to CORRELATE these: if the binary has anti-amplification code but the server still accepted all 2000+ flooding connections, then the mechanism exists but was NOT effective against this attack. If the server rejected connections (fewer connections than expected, or high packet count from rejections), then some mechanism DID activate.

CRITICAL REASONING RULES:
- "mechanism exists in code" does NOT mean "server is resilient to attack"
- A server that accepted ALL connections during flooding is NOT resilient, regardless of what code exists
- A server that rejected connections (lower connection count, "server busy" responses) IS partially resilient
- Anti-amplification protects against reflection attacks, NOT connection flooding — do not conflate them
- Retry tokens protect against IP spoofing, NOT connection flooding — do not conflate them
- For flooding resilience, look specifically for: connection count limits, rate limiting, or connection rejection logic

Look for these patterns in decompiled code:
- Connection count limits: comparisons of current connections against a max value
- Rate limiting: time-based throttling, packet rate comparisons
- Connection rejection: functions that send busy/reject responses or drop connections before completion
- Queue/busy packets: functions that generate rejection responses""",

            user=f"""ATTACK TYPE: {attack_type}
{traffic_context}
=== PHASE 1: FUNCTION NAME CENSUS (scanned ALL {len(sa.get('imports', []))} imports and all function names) ===
The following security mechanism categories were detected by scanning ALL function names in the binary.
If a category has matching function names, the mechanism DEFINITELY EXISTS — even if you can't see the code.

{json.dumps(function_name_census, indent=2, default=str) if function_name_census else "No mechanism indicators found in function names."}

=== PHASE 2: DECOMPILED CODE ({len(quic_functions)} functions) ===
Decompiled code from the most security-relevant QUIC functions:

{func_text}

QUIC/SSL imports ({len(quic_imports)}):
{json.dumps(quic_imports[:30])}

IMPORTANT: The function name census in Phase 1 is AUTHORITATIVE for mechanism existence.
If the census shows functions matching "connection_limits" (e.g., adjust_max_connections, queue_busy_packet),
then connection limits EXIST even if you can't see them in the decompiled code.
Only list a mechanism as MISSING if it has NO matching function names in the census AND no evidence in the code.

Correlate the binary findings with the traffic observations:
1. What security mechanisms exist? (use BOTH the function name census AND decompiled code)
2. Based on traffic statistics, which mechanisms actually ACTIVATED during this attack?
3. Which mechanisms exist but were NOT effective?
4. Is this implementation resilient to {attack_type}? Base this on TRAFFIC EVIDENCE.

Return JSON: {{
    "implementation_name": "name of QUIC library/server identified",
    "quic_functions_analyzed": {len(quic_functions)},
    "function_name_census_results": {json.dumps(census_summary, default=str)},
    "security_mechanisms_found": [
        {{"mechanism": "name", "function": "function_name", "evidence": "what the code or function name shows", "activated": true/false, "activation_evidence": "traffic evidence"}}
    ],
    "security_mechanisms_missing": [
        {{"mechanism": "name", "evidence": "why you believe it is missing — must have NO function name matches AND no code evidence"}}
    ],
    "attack_resilience": {{
        "attack_type": "{attack_type}",
        "resilience_level": "high|medium|low|none",
        "explanation": "correlate binary findings with traffic observations to explain resilience",
        "vulnerable_functions": ["functions that contribute to vulnerability"]
    }},
    "recommendations": ["specific improvements based on code analysis"]
}}""",
        )
        nd["quic_binary_assessment"] = result
        resilience = result.get("attack_resilience", {}).get("resilience_level", "unknown")
        return _step(state, nd, "quic_binary_assessment",
                     f"QUIC binary assessment done — resilience to {attack_type}: {resilience}.")
    except Exception as exc:
        nd["quic_binary_assessment"] = {"error": str(exc)}
        return _step(state, nd, "quic_binary_assessment", f"QUIC binary assessment failed: {exc}")


# ── Sub-graph builder ──────────────────────────────────────────

def should_continue(state: OrcaWorkflowState) -> str:
    plan = state.get("plan") or []
    step = state.get("current_step") or 0
    return plan[step] if step < len(plan) else END


def create_network_subgraph() -> StateGraph:
    g = StateGraph(OrcaWorkflowState)
    g.add_node("pcap_ingest_agent", pcap_ingest_agent)
    g.add_node("traffic_statistics_agent", traffic_statistics_agent)
    g.add_node("quic_handshake_agent", quic_handshake_agent)
    g.add_node("attack_classification_agent", attack_classification_agent)
    g.add_node("anomaly_detection_agent", anomaly_detection_agent)
    g.set_entry_point("pcap_ingest_agent")

    targets = {
        "pcap_ingest": "pcap_ingest_agent",
        "traffic_statistics": "traffic_statistics_agent",
        "quic_handshake": "quic_handshake_agent",
        "attack_classification": "attack_classification_agent",
        "anomaly_detection": "anomaly_detection_agent",
        END: END,
    }
    for n in targets.values():
        if n != END:
            g.add_conditional_edges(n, should_continue, targets)
    return g
