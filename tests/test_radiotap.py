"""The radiotap header walker."""

from __future__ import annotations

import pytest

from deauth_detector.frames import parse_frame, parse_radiotap

from helpers import VICTIMS, deauth, radiotap


def test_header_only_yields_empty_payload():
    payload, rssi, channel = parse_radiotap(b"\x00\x00\x08\x00\x00\x00\x00\x00")
    assert payload == b""
    assert rssi is None and channel is None


def test_rssi_is_read():
    frame = deauth(VICTIMS[0])
    payload, rssi, channel = parse_radiotap(radiotap(frame, rssi=-63))
    assert payload == frame
    assert rssi == -63
    assert channel is None


def test_channel_is_read_from_frequency():
    frame = deauth(VICTIMS[0])
    payload, rssi, channel = parse_radiotap(radiotap(frame, frequency=2437))
    assert payload == frame
    assert channel == 6
    assert rssi is None


def test_both_fields_with_alignment_padding():
    frame = deauth(VICTIMS[0])
    raw = radiotap(frame, rssi=-30, frequency=5180)  # channel first, 2-byte aligned
    payload, rssi, channel = parse_radiotap(raw)
    assert payload == frame
    assert rssi == -30
    assert channel == 36


def test_payload_parses_into_a_frame():
    frame = deauth(VICTIMS[0])
    payload, rssi, channel = parse_radiotap(radiotap(frame, rssi=-40, frequency=2437))
    parsed = parse_frame(payload, rssi=rssi, channel=channel)
    assert parsed is not None
    assert parsed.is_deauth
    assert parsed.rssi == -40
    assert parsed.channel == 6


def test_truncated_header_raises():
    with pytest.raises(ValueError, match="truncated"):
        parse_radiotap(b"\x00\x00\x08")


def test_zero_length_field_raises():
    with pytest.raises(ValueError, match="length"):
        parse_radiotap(b"\x00\x00\x00\x00\x00\x00\x00\x00")


def test_length_longer_than_packet_raises():
    with pytest.raises(ValueError, match="length"):
        parse_radiotap(b"\x00\x00\xff\xff\x00\x00\x00\x00")


def test_extended_present_word_skips_metadata():
    import struct

    raw = struct.pack("<BBHI", 0, 0, 8, 1 << 31) + b"body"
    payload, rssi, channel = parse_radiotap(raw)
    assert payload == b"body"
    assert rssi is None and channel is None


def test_unknown_field_bit_still_returns_payload():
    import struct

    raw = struct.pack("<BBHI", 0, 0, 8, 1 << 7) + b"body"
    payload, rssi, channel = parse_radiotap(raw)
    assert payload == b"body"
    assert rssi is None and channel is None


def test_field_running_past_the_header_still_returns_payload():
    import struct

    # claims the channel field (4 bytes) but stops right after the header
    raw = struct.pack("<BBHI", 0, 0, 8, 1 << 3)
    payload, rssi, channel = parse_radiotap(raw)
    assert payload == b""
    assert rssi is None and channel is None
