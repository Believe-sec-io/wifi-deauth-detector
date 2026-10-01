"""Reader and writer for the classic libpcap (``.pcap``) file format.

Implemented from the format description so the detector has no dependency: a
saved monitor-mode capture can be analysed on any machine, which is also what
makes the tool testable without a wireless card.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Tuple

from .constants import LINKTYPE_IEEE802_11_RADIOTAP

#: magic bytes -> (struct endianness prefix, sub-second divisor).
_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),      # little endian, microseconds
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),      # big endian, microseconds
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),  # little endian, nanoseconds
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),  # big endian, nanoseconds
}

_GLOBAL_HEADER_SIZE = 24
_RECORD_HEADER_SIZE = 16


@dataclass(frozen=True)
class PcapPacket:
    """One packet read from a capture: its timestamp, bytes and link type."""

    timestamp: float
    data: bytes
    linktype: int


def read_pcap_bytes(blob: bytes) -> Iterator[PcapPacket]:
    """Yield every packet of an in-memory classic pcap file."""
    if len(blob) < _GLOBAL_HEADER_SIZE:
        raise ValueError("pcap file is shorter than its global header")
    magic = blob[0:4]
    if magic not in _MAGICS:
        raise ValueError("not a classic pcap file (unrecognised magic number)")
    endian, subsecond = _MAGICS[magic]
    linktype = struct.unpack_from(endian + "I", blob, 20)[0]

    offset = _GLOBAL_HEADER_SIZE
    total = len(blob)
    while offset + _RECORD_HEADER_SIZE <= total:
        ts_sec, ts_frac, captured, _original = struct.unpack_from(
            endian + "IIII", blob, offset
        )
        offset += _RECORD_HEADER_SIZE
        if offset + captured > total:
            break  # truncated capture: stop cleanly instead of raising
        data = blob[offset:offset + captured]
        offset += captured
        yield PcapPacket(timestamp=ts_sec + ts_frac / subsecond, data=data, linktype=linktype)


def read_pcap(path) -> Iterator[PcapPacket]:
    """Yield every packet of a pcap file on disk."""
    return read_pcap_bytes(Path(path).read_bytes())


def write_pcap(
    path,
    packets: Iterable[Tuple[float, bytes]],
    linktype: int = LINKTYPE_IEEE802_11_RADIOTAP,
) -> None:
    """Write ``(timestamp, bytes)`` packets to a little-endian pcap file.

    Used by the demo and the tests to synthesise captures.
    """
    output = bytearray()
    output += b"\xd4\xc3\xb2\xa1"  # little endian, microsecond resolution
    output += struct.pack("<HHIIII", 2, 4, 0, 0, 262_144, linktype)
    for timestamp, data in packets:
        seconds = int(timestamp)
        microseconds = int(round((timestamp - seconds) * 1_000_000))
        output += struct.pack("<IIII", seconds, microseconds, len(data), len(data))
        output += data
    Path(path).write_bytes(bytes(output))


__all__ = ["PcapPacket", "read_pcap", "read_pcap_bytes", "write_pcap"]
