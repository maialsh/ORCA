"""
ORCA QLOG Parser

Parses QLOG (RFC 9161/9162) event logs from QUIC implementations.
QLOG provides structured event data about QUIC connections including:
  - Transport events (packet_sent, packet_received, packet_lost)
  - Recovery events (metrics_updated, congestion_state_updated)
  - Security events (key_updated, key_retired)
  - HTTP/3 events (frame_created, frame_parsed)

Supports: qlog JSON and SQLOG (sequential JSON lines) formats.
"""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from collections import Counter, defaultdict


class QlogParser:
    """Parse and analyse QLOG event traces."""

    def __init__(self, qlog_path: str):
        self.path = Path(qlog_path)
        self.events: List[Dict[str, Any]] = []
        self.trace_info: Dict[str, Any] = {}
        self._parse()

    def _parse(self):
        """Auto-detect format and parse."""
        text = self.path.read_text()
        if text.strip().startswith("{"):
            self._parse_json(text)
        else:
            self._parse_sqlog(text)

    def _parse_json(self, text: str):
        data = json.loads(text)
        # qlog draft-02+ format
        if "traces" in data:
            trace = data["traces"][0] if data["traces"] else {}
            self.trace_info = trace.get("common_fields", {})
            self.trace_info["vantage_point"] = trace.get("vantage_point", {})
            self.trace_info["title"] = trace.get("title", "")

            events_raw = trace.get("events", [])
            for evt in events_raw:
                if isinstance(evt, list) and len(evt) >= 3:
                    self.events.append({
                        "time": evt[0],
                        "category": evt[1] if len(evt) > 1 else "",
                        "type": evt[2] if len(evt) > 2 else "",
                        "data": evt[3] if len(evt) > 3 else {},
                    })
                elif isinstance(evt, dict):
                    self.events.append({
                        "time": evt.get("time", 0),
                        "category": evt.get("name", "").split(":")[0] if ":" in evt.get("name", "") else "",
                        "type": evt.get("name", "").split(":")[-1] if ":" in evt.get("name", "") else evt.get("name", ""),
                        "data": evt.get("data", {}),
                    })
        # qlog draft-01 format
        elif "events" in data:
            self.events = data["events"]

    def _parse_sqlog(self, text: str):
        for line in text.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if "header" in obj:
                    self.trace_info = obj["header"]
                elif "time" in obj or "name" in obj:
                    self.events.append(obj)
            except json.JSONDecodeError:
                continue

    # ── Analysis Methods ───────────────────────────────────────

    def get_event_summary(self) -> Dict[str, int]:
        """Count events by type."""
        counter = Counter()
        for evt in self.events:
            key = f"{evt.get('category', '')}:{evt.get('type', '')}"
            counter[key] += 1
        return dict(counter.most_common())

    def get_packet_loss_stats(self) -> Dict[str, Any]:
        """Analyse packet loss events."""
        sent = sum(1 for e in self.events if e.get("type") in ("packet_sent",))
        received = sum(1 for e in self.events if e.get("type") in ("packet_received",))
        lost = sum(1 for e in self.events if e.get("type") in ("packet_lost",))

        return {
            "packets_sent": sent,
            "packets_received": received,
            "packets_lost": lost,
            "loss_rate": round(lost / max(sent, 1), 4),
        }

    def get_handshake_duration(self) -> Optional[float]:
        """Calculate handshake duration from first Initial to first Handshake Done."""
        initial_time = None
        handshake_done_time = None

        for evt in self.events:
            data = evt.get("data", {})
            header = data.get("header", {}) if isinstance(data, dict) else {}
            pkt_type = header.get("packet_type", "")

            if pkt_type == "initial" and initial_time is None:
                initial_time = evt.get("time", 0)
            if evt.get("type") in ("handshake_done_received", "handshake_completed"):
                handshake_done_time = evt.get("time", 0)
                break

        if initial_time is not None and handshake_done_time is not None:
            return handshake_done_time - initial_time
        return None

    def get_congestion_events(self) -> List[Dict[str, Any]]:
        """Extract congestion-related events."""
        return [
            e for e in self.events
            if e.get("type") in ("congestion_state_updated", "metrics_updated", "loss_timer_updated")
        ]

    def get_key_events(self) -> List[Dict[str, Any]]:
        """Extract key update/rotation events (security-relevant)."""
        return [
            e for e in self.events
            if e.get("type") in ("key_updated", "key_retired", "key_discarded")
            or e.get("category") == "security"
        ]

    def get_stream_activity(self) -> Dict[str, Any]:
        """Analyse stream creation and data transfer."""
        streams: Dict[str, Dict] = defaultdict(lambda: {"bytes_sent": 0, "bytes_received": 0, "frames": 0})

        for evt in self.events:
            data = evt.get("data", {})
            if not isinstance(data, dict):
                continue
            stream_id = str(data.get("stream_id", ""))
            if not stream_id:
                frames = data.get("frames", [])
                if isinstance(frames, list):
                    for f in frames:
                        if isinstance(f, dict) and "stream_id" in f:
                            sid = str(f["stream_id"])
                            streams[sid]["frames"] += 1
                            if "length" in f:
                                streams[sid]["bytes_sent"] += f["length"]
                continue

            streams[stream_id]["frames"] += 1
            if "length" in data:
                streams[stream_id]["bytes_sent"] += data["length"]

        return {
            "total_streams": len(streams),
            "streams": dict(streams),
        }

    def detect_anomalies(self) -> List[Dict[str, str]]:
        """Flag suspicious patterns in QLOG events."""
        anomalies = []
        event_summary = self.get_event_summary()
        loss = self.get_packet_loss_stats()

        # High packet loss
        if loss["loss_rate"] > 0.1:
            anomalies.append({
                "type": "high_packet_loss",
                "description": f"Packet loss rate {loss['loss_rate']:.1%} exceeds 10% threshold",
                "severity": "medium",
            })

        # Excessive key rotations
        key_events = self.get_key_events()
        if len(key_events) > 20:
            anomalies.append({
                "type": "excessive_key_rotation",
                "description": f"{len(key_events)} key events detected — may indicate key confusion attack",
                "severity": "high",
            })

        # 0-RTT data
        zero_rtt_count = sum(1 for e in self.events
                            if isinstance(e.get("data", {}), dict)
                            and e.get("data", {}).get("header", {}).get("packet_type") == "0rtt")
        if zero_rtt_count > 0:
            anomalies.append({
                "type": "0rtt_data_detected",
                "description": f"{zero_rtt_count} 0-RTT packets — potential replay risk per RFC 9001 §9.2",
                "severity": "medium",
            })

        # Connection migration
        migration_events = [e for e in self.events if "migration" in str(e.get("type", "")).lower()]
        if len(migration_events) > 5:
            anomalies.append({
                "type": "frequent_migration",
                "description": f"{len(migration_events)} connection migrations — may indicate evasion",
                "severity": "medium",
            })

        return anomalies

    def to_dict(self) -> Dict[str, Any]:
        """Full analysis as a dict for LLM consumption."""
        return {
            "trace_info": self.trace_info,
            "total_events": len(self.events),
            "event_summary": self.get_event_summary(),
            "packet_loss": self.get_packet_loss_stats(),
            "handshake_duration_ms": self.get_handshake_duration(),
            "stream_activity": self.get_stream_activity(),
            "key_events_count": len(self.get_key_events()),
            "anomalies": self.detect_anomalies(),
        }
