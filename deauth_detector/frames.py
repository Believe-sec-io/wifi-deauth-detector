"""Parsing of 802.11 management frames and of the radiotap header.

Only the standard library is used: the detector has to run on a bare sensor
host, from a saved capture or straight off the wire.
"""

from __future__ import annotations

from typing import Optional, Tuple

from .constants import (
    REASON_CODES,
    SUBTYPE_DISASSOCIATION,
    SUBTYPE_DEAUTHENTICATION,
    SUBTYPE_NAMES,
    TYPE_MANAGEMENT,
)
from .models import Dot11Frame

#: radiotap fields the detector knows how to skip while walking the header.
#: bit index -> (name, size in bytes, alignment in bytes)
_RADIOTAP_FIELDS = {
    0: ("tsft", 8, 8),
    1: ("flags", 1, 1),
    2: ("rate", 1, 1),
    3: ("channel", 4, 2),
    4: ("fhss", 2, 2),
    5: ("dbm_antsignal", 1, 1),
    6: ("dbm_antnoise", 1, 1),
}

RADIOTAP_EXTENDED_BIT = 31


def mac_to_str(raw: bytes) -> str:
    """Format six bytes as a lower-case colon separated MAC address."""
    return ":".join(f"{byte:02x}" for byte in raw)


def frequency_to_channel(frequency_mhz: int) -> Optional[int]:
    """Map a centre frequency to its Wi-Fi channel number."""
    if 2412 <= frequency_mhz <= 2484:
        if frequency_mhz == 2484:
            return 14
        return (frequency_mhz - 2407) // 5
    if 5000 <= frequency_mhz <= 5900:
        return (frequency_mhz - 5000) // 5
    if 5955 <= frequency_mhz <= 7115:  # 6 GHz (Wi-Fi 6E)
        return (frequency_mhz - 5950) // 5
    return None


def parse_radiotap(data: bytes) -> Tuple[bytes, Optional[int], Optional[int]]:
    """Split a radiotap packet into ``(802.11 payload, rssi, channel)``.

    The 802.11 payload always starts at the offset stored in the header length
    field, so a header we cannot fully walk still yields the frame; only the
    optional ``rssi`` / ``channel`` come back as ``None``.
    """
    if len(data) < 8:
        raise ValueError("radiotap header truncated")
    length = int.from_bytes(data[2:4], "little")
    if length < 8 or length > len(data):
        raise ValueError("invalid radiotap length")
    payload = data[length:]
    present = int.from_bytes(data[4:8], "little")
    if present & (1 << RADIOTAP_EXTENDED_BIT):
        return payload, None, None  # extended present words: skip metadata

    offset = 8
    rssi: Optional[int] = None
    channel: Optional[int] = None
    for bit in range(0, RADIOTAP_EXTENDED_BIT):
        if not present & (1 << bit):
            continue
        field = _RADIOTAP_FIELDS.get(bit)
        if field is None:
            return payload, None, None  # unknown field: cannot keep walking
        name, size, align = field
        offset = (offset + (align - 1)) & ~(align - 1)
        if offset + size > len(data):
            return payload, None, None
        if name == "dbm_antsignal":
            rssi = int.from_bytes(data[offset:offset + 1], "little", signed=True)
        elif name == "channel":
            frequency = int.from_bytes(data[offset:offset + 2], "little")
            channel = frequency_to_channel(frequency)
        offset += size
    return payload, rssi, channel


def parse_frame(
    data: bytes,
    timestamp: float = 0.0,
    rssi: Optional[int] = None,
    channel: Optional[int] = None,
) -> Optional[Dot11Frame]:
    """Parse one 802.11 frame; return ``None`` when it is not a management frame.

    A management frame is 24 bytes of fixed header (frame control, duration and
    the three addresses) followed, for deauth/disassoc, by a 2-byte reason code.
    """
    if len(data) < 24:
        return None
    frame_control = int.from_bytes(data[0:2], "little")
    frame_type = (frame_control >> 2) & 0x03
    if frame_type != TYPE_MANAGEMENT:
        return None
    subtype = (frame_control >> 4) & 0x0F

    reason: Optional[int] = None
    if subtype in (SUBTYPE_DISASSOCIATION, SUBTYPE_DEAUTHENTICATION) and len(data) >= 26:
        reason = int.from_bytes(data[24:26], "little")

    return Dot11Frame(
        subtype=subtype,
        subtype_name=SUBTYPE_NAMES.get(subtype, f"management-{subtype}"),
        receiver=mac_to_str(data[4:10]),
        transmitter=mac_to_str(data[10:16]),
        bssid=mac_to_str(data[16:22]),
        reason_code=reason,
        reason_text=REASON_CODES.get(reason, "") if reason is not None else "",
        rssi=rssi,
        channel=channel,
        timestamp=float(timestamp),
        length=len(data),
    )


__all__ = ["frequency_to_channel", "mac_to_str", "parse_frame", "parse_radiotap"]
