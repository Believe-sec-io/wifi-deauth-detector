"""Turning captures into frames: pcap files and the optional live path."""

from __future__ import annotations

import pytest

from deauth_detector.capture import (
    frame_from_scapy,
    frames_from_packet,
    frames_from_pcap,
    live_capture,
)
from deauth_detector.constants import (
    LINKTYPE_ETHERNET,
    LINKTYPE_IEEE802_11,
    LINKTYPE_IEEE802_11_RADIOTAP,
)
from deauth_detector.pcap import PcapPacket

from helpers import (
    BASE_TIME,
    VICTIMS,
    attack_capture,
    deauth,
    quiet_capture,
    radiotap,
    write_capture,
)


def test_frames_from_a_radiotap_capture(tmp_path):
    path = write_capture(tmp_path / "attack.pcap", attack_capture())
    frames = list(frames_from_pcap(path))
    assert frames
    assert all(frame.subtype_name for frame in frames)
    assert any(frame.is_deauth for frame in frames)
    assert any(frame.is_broadcast for frame in frames)
    assert all(frame.rssi is not None for frame in frames)  # every packet carries one
    assert all(frame.channel == 6 for frame in frames)  # 2437 MHz
    assert any(frame.rssi == -40 for frame in frames)  # attack frames
    assert any(frame.rssi == -55 for frame in frames)  # beacons use another power
    assert frames[0].timestamp >= BASE_TIME


def test_frames_from_a_raw_802_11_capture(tmp_path):
    packets = [(BASE_TIME + index, deauth(VICTIMS[0])) for index in range(3)]
    path = write_capture(tmp_path / "raw.pcap", packets, linktype=LINKTYPE_IEEE802_11)
    frames = list(frames_from_pcap(path))
    assert len(frames) == 3
    assert frames[0].rssi is None
    assert frames[0].channel is None
    assert frames[0].is_deauth


def test_quiet_capture_only_yields_beacons(tmp_path):
    path = write_capture(tmp_path / "quiet.pcap", quiet_capture())
    frames = list(frames_from_pcap(path))
    assert frames
    assert not any(frame.is_teardown for frame in frames)


def test_unsupported_link_type_raises_a_clear_error(tmp_path):
    path = write_capture(
        tmp_path / "eth.pcap", [(BASE_TIME, b"\x00" * 60)], linktype=LINKTYPE_ETHERNET
    )
    with pytest.raises(ValueError) as excinfo:
        list(frames_from_pcap(path))
    message = str(excinfo.value)
    assert "unsupported pcap link type" in message
    assert str(LINKTYPE_ETHERNET) in message


def test_frames_from_packet_skips_unsupported_linktypes():
    packet = PcapPacket(timestamp=BASE_TIME, data=b"anything", linktype=LINKTYPE_ETHERNET)
    assert list(frames_from_packet(packet)) == []


def test_frames_from_packet_reads_rssi_and_channel():
    packet = PcapPacket(
        timestamp=BASE_TIME + 5,
        data=radiotap(deauth(VICTIMS[2]), rssi=-71, frequency=2437),
        linktype=LINKTYPE_IEEE802_11_RADIOTAP,
    )
    frame = next(iter(frames_from_packet(packet)))
    assert frame.rssi == -71
    assert frame.channel == 6
    assert frame.timestamp == BASE_TIME + 5
    assert frame.receiver == VICTIMS[2]


def test_frames_from_packet_skips_non_management_frames():
    packet = PcapPacket(
        timestamp=BASE_TIME, data=b"\x08\x01" + b"\x00" * 30, linktype=LINKTYPE_IEEE802_11
    )
    assert list(frames_from_packet(packet)) == []


def test_corrupt_radiotap_raises_instead_of_hiding_the_error():
    packet = PcapPacket(timestamp=BASE_TIME, data=b"\x00\x00\xff\xff", linktype=127)
    with pytest.raises(ValueError):
        list(frames_from_packet(packet))


def test_missing_capture_extra_points_at_the_right_extras_name():
    import deauth_detector.capture as capture_module

    assert capture_module._CAPTURE_EXTRA == "pip install wifi-deauth-detector[capture]"


@pytest.mark.skipif(
    __import__("importlib").util.find_spec("scapy") is not None,
    reason="scapy installed: live capture path is exercised for real",
)
def test_live_capture_without_scapy_raises_import_error():
    with pytest.raises(ImportError, match=r"wifi-deauth-detector\[capture\]"):
        live_capture("wlan0mon")


@pytest.mark.skipif(
    __import__("importlib").util.find_spec("scapy") is not None,
    reason="scapy installed: frame_from_scapy is exercised for real",
)
def test_frame_from_scapy_without_scapy_raises_import_error():
    with pytest.raises(ImportError):
        frame_from_scapy(object())
