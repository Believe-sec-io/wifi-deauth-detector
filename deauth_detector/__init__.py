"""wifi-deauth-detector: detect 802.11 deauthentication attacks from a capture.

Public surface::

    from deauth_detector import DeauthDetector, frames_from_pcap

    detector = DeauthDetector()
    detector.add_many(frames_from_pcap("capture.pcap"))
    report = detector.report("capture.pcap")

Core analysis uses only the standard library; live capture needs the optional
``scapy`` extra (``pip install wifi-deauth-detector[capture]``).
"""

from __future__ import annotations

from .capture import (
    frame_from_scapy,
    frames_from_packet,
    frames_from_pcap,
    live_capture,
)
from .detector import DeauthDetector, DetectorConfig
from .frames import frequency_to_channel, parse_frame, parse_radiotap
from .models import Alert, Dot11Frame, Report, Severity
from .pcap import PcapPacket, read_pcap, read_pcap_bytes, write_pcap
from .rules import Rule, list_rules, make_alert

__version__ = "1.0.0"

__all__ = [
    "Alert",
    "DeauthDetector",
    "DetectorConfig",
    "Dot11Frame",
    "PcapPacket",
    "Report",
    "Rule",
    "Severity",
    "frame_from_scapy",
    "frames_from_packet",
    "frames_from_pcap",
    "frequency_to_channel",
    "list_rules",
    "live_capture",
    "make_alert",
    "parse_frame",
    "parse_radiotap",
    "read_pcap",
    "read_pcap_bytes",
    "write_pcap",
    "__version__",
]
