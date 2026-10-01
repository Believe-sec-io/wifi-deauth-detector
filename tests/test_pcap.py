"""The standard-library pcap reader and writer."""

from __future__ import annotations

import struct

import pytest

from deauth_detector.constants import LINKTYPE_IEEE802_11, LINKTYPE_IEEE802_11_RADIOTAP
from deauth_detector.pcap import read_pcap, read_pcap_bytes, write_pcap

from helpers import BASE_TIME


def _write(tmp_path, packets, linktype=LINKTYPE_IEEE802_11_RADIOTAP, name="cap.pcap"):
    """write_pcap returns None on purpose: the tests need the path back."""
    path = tmp_path / name
    write_pcap(path, packets, linktype=linktype)
    return path


def test_write_then_read_round_trip(tmp_path):
    packets = [(BASE_TIME, b"abc"), (BASE_TIME + 1.5, b"defg")]
    path = _write(tmp_path, packets, linktype=LINKTYPE_IEEE802_11)
    read_back = list(read_pcap(path))
    assert len(read_back) == 2
    assert read_back[0].data == b"abc"
    assert read_back[0].linktype == LINKTYPE_IEEE802_11
    assert read_back[1].data == b"defg"
    assert read_back[1].timestamp == pytest.approx(BASE_TIME + 1.5, abs=1e-6)


def test_default_linktype_is_radiotap(tmp_path):
    path = _write(tmp_path, [(BASE_TIME, b"x")])
    assert next(iter(read_pcap(path))).linktype == LINKTYPE_IEEE802_11_RADIOTAP


def test_empty_capture_yields_nothing(tmp_path):
    path = _write(tmp_path, [], name="empty.pcap")
    assert list(read_pcap(path)) == []


def test_file_shorter_than_the_global_header_raises(tmp_path):
    path = tmp_path / "short.pcap"
    path.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 5)
    with pytest.raises(ValueError, match="global header"):
        list(read_pcap(path))


def test_unknown_magic_raises(tmp_path):
    path = tmp_path / "bad.pcap"
    path.write_bytes(b"NOTPCAP" + b"\x00" * 40)
    with pytest.raises(ValueError, match="magic"):
        list(read_pcap(path))


def test_big_endian_capture_is_supported():
    blob = b"\xa1\xb2\xc3\xd4" + struct.pack(">HHIIII", 2, 4, 0, 0, 262_144, 105)
    blob += struct.pack(">IIII", 1_700_000_000, 250_000, 4, 4)
    blob += b"\xde\xad\xbe\xef"
    packet = next(iter(read_pcap_bytes(blob)))
    assert packet.timestamp == pytest.approx(1_700_000_000.25)
    assert packet.linktype == 105
    assert packet.data == b"\xde\xad\xbe\xef"


def test_nanosecond_resolution_capture_is_supported():
    blob = b"\x4d\x3c\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 262_144, 105)
    blob += struct.pack("<IIII", 100, 500_000_000, 3, 3)
    blob += b"abc"
    packet = next(iter(read_pcap_bytes(blob)))
    assert packet.timestamp == pytest.approx(100.5)


def test_truncated_record_stops_cleanly(tmp_path):
    path = _write(tmp_path, [(BASE_TIME, b"one"), (BASE_TIME + 1, b"two")], name="cut.pcap")
    blob = path.read_bytes()
    cut = blob.rfind(b"two") + 3  # drop the tail of the second packet
    truncated = blob[:cut - 1]
    assert [p.data for p in read_pcap_bytes(truncated)] == [b"one"]


def test_trailing_partial_record_header_is_ignored(tmp_path):
    path = _write(tmp_path, [(BASE_TIME, b"one")], name="one.pcap")
    blob = path.read_bytes() + b"\x01\x02\x03"
    assert [p.data for p in read_pcap_bytes(blob)] == [b"one"]
