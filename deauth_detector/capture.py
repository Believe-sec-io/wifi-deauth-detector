"""Turn a capture into :class:`Dot11Frame` objects.

Two sources are supported: a saved ``.pcap`` file (standard library only) and a
live interface through *scapy* (optional dependency, needs monitor mode and
privileges).
"""

from __future__ import annotations

from typing import Iterator, List, Optional

from .constants import (
    LINKTYPE_IEEE802_11,
    LINKTYPE_IEEE802_11_RADIOTAP,
    REASON_CODES,
    SUBTYPE_NAMES,
    SUPPORTED_LINKTYPES,
    TEARDOWN_SUBTYPES,
    TYPE_MANAGEMENT,
)
from .frames import parse_frame, parse_radiotap
from .models import Dot11Frame
from .pcap import PcapPacket, read_pcap

_CAPTURE_EXTRA = "pip install wifi-deauth-detector[capture]"


# ------------------------------------------------------------------- pcap
def frames_from_packet(packet: PcapPacket) -> Iterator[Dot11Frame]:
    """Yield the management frames contained in one captured packet."""
    if packet.linktype == LINKTYPE_IEEE802_11_RADIOTAP:
        payload, rssi, channel = parse_radiotap(packet.data)
        frame = parse_frame(payload, packet.timestamp, rssi, channel)
    elif packet.linktype == LINKTYPE_IEEE802_11:
        frame = parse_frame(packet.data, packet.timestamp)
    else:
        return
    if frame is not None:
        yield frame


def frames_from_pcap(path) -> Iterator[Dot11Frame]:
    """Yield every management frame found in a pcap file on disk."""
    for packet in read_pcap(path):
        if packet.linktype not in SUPPORTED_LINKTYPES:
            raise ValueError(
                f"unsupported pcap link type {packet.linktype}; the detector reads "
                f"802.11 ({LINKTYPE_IEEE802_11}) and radiotap "
                f"({LINKTYPE_IEEE802_11_RADIOTAP}) captures"
            )
        yield from frames_from_packet(packet)


# ------------------------------------------------------------------- live
def frame_from_scapy(packet) -> Optional[Dot11Frame]:
    """Convert one scapy packet into a :class:`Dot11Frame` (management only)."""
    from scapy.all import Dot11, Dot11Deauth, Dot11Disas  # imported lazily

    if not packet.haslayer(Dot11):
        return None
    dot11 = packet[Dot11]
    if int(getattr(dot11, "type", -1)) != TYPE_MANAGEMENT:
        return None

    subtype = int(getattr(dot11, "subtype", 0))
    reason: Optional[int] = None
    if subtype in TEARDOWN_SUBTYPES:
        if packet.haslayer(Dot11Deauth):
            reason = int(packet[Dot11Deauth].reason)
        elif packet.haslayer(Dot11Disas):
            reason = int(packet[Dot11Disas].reason)

    rssi = getattr(packet, "dBm_AntSignal", None)
    channel = getattr(packet, "Channel", None)

    return Dot11Frame(
        subtype=subtype,
        subtype_name=SUBTYPE_NAMES.get(subtype, f"management-{subtype}"),
        receiver=str(getattr(dot11, "addr1", "") or "").lower(),
        transmitter=str(getattr(dot11, "addr2", "") or "").lower(),
        bssid=str(getattr(dot11, "addr3", "") or "").lower(),
        reason_code=reason,
        reason_text=REASON_CODES.get(reason, "") if reason is not None else "",
        rssi=int(rssi) if isinstance(rssi, int) else None,
        channel=int(channel) if isinstance(channel, int) else None,
        timestamp=float(getattr(packet, "time", 0.0) or 0.0),
        length=len(bytes(packet)),
    )


def live_capture(
    interface: str,
    *,
    count: int = 0,
    timeout: Optional[float] = None,
    channel: Optional[int] = None,
) -> List[Dot11Frame]:
    """Capture frames live on ``interface`` and return the management frames.

    Requires the optional *scapy* dependency and an interface in monitor mode.
    """
    try:
        from scapy.all import sniff
    except ImportError as error:  # pragma: no cover - depends on the environment
        raise ImportError(
            f"live capture needs scapy: {_CAPTURE_EXTRA}"
        ) from error

    collected: List[Dot11Frame] = []

    def handle(packet) -> None:  # pragma: no cover - exercised on real hardware
        frame = frame_from_scapy(packet)
        if frame is not None:
            collected.append(frame)

    if channel is not None:  # pragma: no cover - hardware only
        try:
            from scapy.all import set_iface_channel
            set_iface_channel(interface, channel)
        except Exception:  # noqa: BLE001 - best effort channel selection
            pass

    sniff(  # pragma: no cover - hardware only
        iface=interface,
        prn=handle,
        store=False,
        count=count or 0,
        timeout=timeout,
    )
    return collected


__all__ = [
    "frame_from_scapy",
    "frames_from_packet",
    "frames_from_pcap",
    "live_capture",
]
