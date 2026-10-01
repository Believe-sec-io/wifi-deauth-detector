"""Shared test helpers: synthetic 802.11 frames, radiotap headers and captures.

Everything is built by hand from the specification, so the suite needs neither
scapy nor a wireless card nor a committed binary fixture.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import List, Optional, Tuple

from deauth_detector.constants import (
    BROADCAST_ADDRESS,
    LINKTYPE_IEEE802_11_RADIOTAP,
    SUBTYPE_BEACON,
    SUBTYPE_DEAUTHENTICATION,
    SUBTYPE_DISASSOCIATION,
    TYPE_MANAGEMENT,
)
from deauth_detector.frames import parse_frame
from deauth_detector.models import Dot11Frame
from deauth_detector.pcap import write_pcap

ATTACKER = "aa:aa:aa:aa:aa:aa"
AP = "bb:bb:bb:bb:bb:bb"
VICTIMS: Tuple[str, ...] = (
    "cc:cc:cc:cc:cc:01",
    "cc:cc:cc:cc:cc:02",
    "cc:cc:cc:cc:cc:03",
    "cc:cc:cc:cc:cc:04",
    "cc:cc:cc:cc:cc:05",
    "cc:cc:cc:cc:cc:06",
)
BASE_TIME = 1_700_000_000.0


# ----------------------------------------------------------- frame assembly
def mac_bytes(mac: str) -> bytes:
    """Six bytes from a colon separated MAC address."""
    return bytes(int(part, 16) for part in mac.split(":"))


def management_frame(
    subtype: int,
    receiver: str,
    transmitter: str,
    bssid: str,
    body: bytes = b"",
) -> bytes:
    """A 24-byte 802.11 management header plus an optional body."""
    frame_control = ((subtype & 0x0F) << 4) | ((TYPE_MANAGEMENT & 0x03) << 2)
    return (
        struct.pack("<H", frame_control)
        + b"\x00\x00"  # duration
        + mac_bytes(receiver)
        + mac_bytes(transmitter)
        + mac_bytes(bssid)
        + b"\x00\x00"  # sequence control
        + body
    )


def deauth(
    receiver: str,
    transmitter: str = ATTACKER,
    bssid: str = AP,
    reason: int = 1,
) -> bytes:
    """A deauthentication frame carrying ``reason``."""
    return management_frame(
        SUBTYPE_DEAUTHENTICATION, receiver, transmitter, bssid, struct.pack("<H", reason)
    )


def disassoc(
    receiver: str,
    transmitter: str = ATTACKER,
    bssid: str = AP,
    reason: int = 8,
) -> bytes:
    """A disassociation frame carrying ``reason``."""
    return management_frame(
        SUBTYPE_DISASSOCIATION, receiver, transmitter, bssid, struct.pack("<H", reason)
    )


def beacon(
    receiver: str = BROADCAST_ADDRESS,
    transmitter: str = AP,
    bssid: str = AP,
) -> bytes:
    """A benign beacon (fixed parameters only: the detector ignores its body)."""
    return management_frame(SUBTYPE_BEACON, receiver, transmitter, bssid, b"\x00" * 12)


def radiotap(
    payload: bytes,
    rssi: Optional[int] = None,
    frequency: Optional[int] = None,
) -> bytes:
    """A radiotap header exposing ``dbm_antsignal`` and/or the channel."""
    present = 0
    body = bytearray()
    offset = 8
    if frequency is not None:
        present |= 1 << 3
        while offset % 2:  # channel field is 2-byte aligned
            body.append(0)
            offset += 1
        body += struct.pack("<HH", frequency, 0)  # channel flags are unused
        offset += 4
    if rssi is not None:
        present |= 1 << 5
        body.append(rssi & 0xFF)
        offset += 1
    return struct.pack("<BBHI", 0, 0, 8 + len(body), present) + bytes(body) + payload


# ------------------------------------------------------------------ objects
def make_frame(
    subtype: int = SUBTYPE_DEAUTHENTICATION,
    receiver: str = VICTIMS[0],
    transmitter: str = ATTACKER,
    bssid: str = AP,
    reason: Optional[int] = 1,
    timestamp: float = BASE_TIME,
    rssi: Optional[int] = -42,
    channel: Optional[int] = 6,
) -> Dot11Frame:
    """Build a :class:`Dot11Frame` directly (no bytes), for detector tests."""
    from deauth_detector.constants import REASON_CODES, SUBTYPE_NAMES

    return Dot11Frame(
        subtype=subtype,
        subtype_name=SUBTYPE_NAMES.get(subtype, f"management-{subtype}"),
        receiver=receiver,
        transmitter=transmitter,
        bssid=bssid,
        reason_code=reason,
        reason_text=REASON_CODES.get(reason, "") if reason is not None else "",
        rssi=rssi,
        channel=channel,
        timestamp=timestamp,
        length=26,
    )


def parse(raw: bytes, timestamp: float = BASE_TIME) -> Optional[Dot11Frame]:
    """Parse assembled bytes back into a frame."""
    return parse_frame(raw, timestamp)


def write_capture(path, packets, linktype: int = LINKTYPE_IEEE802_11_RADIOTAP) -> Path:
    """Write ``(timestamp, bytes)`` packets to ``path`` as a pcap file."""
    path = Path(path)
    write_pcap(path, packets, linktype=linktype)
    return path


# --------------------------------------------------------------- scenarios
def radio(
    raw: bytes,
    at: float,
    rssi: Optional[int] = -40,
    frequency: Optional[int] = 2437,
) -> Tuple[float, bytes]:
    """Wrap assembled bytes into a ``(timestamp, packet)`` radiotap packet."""
    return (at, radiotap(raw, rssi=rssi, frequency=frequency))


def beacon_traffic(count: int = 8, start: float = 0.0, step: float = 1.0):
    """Benign beacons from the real access point."""
    return [
        radio(beacon(), BASE_TIME + start + index * step, rssi=-55)
        for index in range(count)
    ]


def deauth_burst(
    count: int = 12,
    start: float = 0.0,
    step: float = 0.1,
    receiver: str = VICTIMS[0],
    reason: int = 1,
    transmitter: str = ATTACKER,
):
    """``count`` deauth frames to a single victim."""
    return [
        radio(
            deauth(receiver, transmitter=transmitter, reason=reason),
            BASE_TIME + start + index * step,
        )
        for index in range(count)
    ]


def broadcast_deauth(count: int = 3, start: float = 0.0, step: float = 0.2,
                     transmitter: str = ATTACKER):
    """Deauth frames addressed to the broadcast address."""
    return [
        radio(deauth(BROADCAST_ADDRESS, transmitter=transmitter), BASE_TIME + start + index * step)
        for index in range(count)
    ]


def sweep(victims=None, start: float = 0.0, step: float = 0.05, reason: int = 1):
    """One deauth per distinct victim: the multi-target sweep signature."""
    victims = list(victims if victims is not None else VICTIMS)
    return [
        radio(deauth(victim, reason=reason), BASE_TIME + start + index * step)
        for index, victim in enumerate(victims)
    ]


def disassoc_burst(count: int = 12, start: float = 0.0, step: float = 0.1,
                   receiver: str = VICTIMS[0]):
    """``count`` disassociation frames to a single victim."""
    return [
        radio(disassoc(receiver), BASE_TIME + start + index * step)
        for index in range(count)
    ]


def attack_capture() -> List[Tuple[float, bytes]]:
    """A full synthetic capture mixing benign traffic with an attack."""
    packets: List[Tuple[float, bytes]] = []
    packets += beacon_traffic()
    packets += broadcast_deauth()
    packets += sweep()
    packets += deauth_burst(count=14, start=2.0, receiver=VICTIMS[0])
    packets += beacon_traffic(count=3, start=6.0)
    packets.sort(key=lambda item: item[0])
    return packets


def quiet_capture() -> List[Tuple[float, bytes]]:
    """A capture without any teardown frame."""
    return beacon_traffic()


__all__ = [
    "AP",
    "ATTACKER",
    "BASE_TIME",
    "VICTIMS",
    "attack_capture",
    "beacon",
    "beacon_traffic",
    "broadcast_deauth",
    "deauth",
    "deauth_burst",
    "disassoc",
    "disassoc_burst",
    "mac_bytes",
    "make_frame",
    "management_frame",
    "parse",
    "quiet_capture",
    "radio",
    "radiotap",
    "sweep",
    "write_capture",
]

