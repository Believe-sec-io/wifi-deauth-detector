"""Parsing of 802.11 management frames and of the radiotap header."""

from __future__ import annotations

import pytest

from deauth_detector.constants import (
    BROADCAST_ADDRESS,
    REASON_NONASSOCIATED,
    SUBTYPE_BEACON,
    SUBTYPE_DEAUTHENTICATION,
    SUBTYPE_DISASSOCIATION,
)
from deauth_detector.frames import (
    frequency_to_channel,
    mac_to_str,
    parse_frame,
    parse_radiotap,
)

from helpers import AP, ATTACKER, VICTIMS, deauth, disassoc, make_frame, radiotap


def test_mac_to_str_formats_six_bytes():
    assert mac_to_str(bytes.fromhex("aabbccddeeff")) == "aa:bb:cc:dd:ee:ff"


def test_mac_to_str_zero_padding():
    assert mac_to_str(b"\x00\x01\x02\x03\x04\x05") == "00:01:02:03:04:05"


@pytest.mark.parametrize(
    ("frequency", "channel"),
    [
        (2412, 1),
        (2437, 6),
        (2462, 11),
        (2472, 13),
        (2484, 14),
        (5180, 36),
        (5745, 149),
        (5955, 1),
        (6135, 37),
        (2400, None),
        (1000, None),
        (0, None),
    ],
)
def test_frequency_to_channel(frequency, channel):
    assert frequency_to_channel(frequency) == channel


def test_parse_deauth_addresses_and_reason():
    raw = deauth(VICTIMS[0], reason=REASON_NONASSOCIATED)
    frame = parse_frame(raw, timestamp=1234.5)
    assert frame is not None
    assert frame.subtype == SUBTYPE_DEAUTHENTICATION
    assert frame.subtype_name == "deauthentication"
    assert frame.receiver == VICTIMS[0]
    assert frame.transmitter == ATTACKER
    assert frame.bssid == AP
    assert frame.reason_code == REASON_NONASSOCIATED
    assert frame.reason_text.startswith("Class 3 frame")
    assert frame.timestamp == 1234.5
    assert frame.length == len(raw)


def test_parse_disassoc_is_teardown_but_not_deauth():
    frame = parse_frame(disassoc(VICTIMS[1]))
    assert frame is not None
    assert frame.subtype == SUBTYPE_DISASSOCIATION
    assert frame.is_disassoc and frame.is_teardown and not frame.is_deauth


def test_parse_beacon_has_no_reason_code():
    from helpers import beacon

    frame = parse_frame(beacon())
    assert frame is not None
    assert frame.subtype == SUBTYPE_BEACON
    assert frame.subtype_name == "beacon"
    assert frame.reason_code is None
    assert not frame.is_teardown


def test_parse_data_frame_returns_none():
    data = bytes([0x08, 0x01]) + b"\x00" * 30  # type = data
    assert parse_frame(data) is None


def test_parse_short_buffer_returns_none():
    assert parse_frame(b"\xc0\x00\x00") is None


def test_parse_unknown_management_subtype_keeps_a_name():
    raw = bytes([13 << 4, 0x00]) + bytes(22)
    frame = parse_frame(raw)
    assert frame is not None
    assert frame.subtype == 13
    assert frame.subtype_name == "management-13"


def test_deauth_shorter_than_reason_bytes_has_no_reason():
    raw = deauth(VICTIMS[0])[:-1]  # 25 bytes: reason truncated
    frame = parse_frame(raw)
    assert frame is not None
    assert frame.reason_code is None
