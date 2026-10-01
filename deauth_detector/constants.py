"""802.11 and pcap constants shared by the whole detector."""

from __future__ import annotations

from typing import Dict, Tuple

# ------------------------------------------------------------------ 802.11
#: Frame types (the low nibble of the frame control field, bits 2-3).
TYPE_MANAGEMENT = 0
TYPE_CONTROL = 1
TYPE_DATA = 2

#: Management subtypes (frame control bits 4-7).
SUBTYPE_ASSOCIATION_REQUEST = 0
SUBTYPE_ASSOCIATION_RESPONSE = 1
SUBTYPE_REASSOCIATION_REQUEST = 2
SUBTYPE_REASSOCIATION_RESPONSE = 3
SUBTYPE_PROBE_REQUEST = 4
SUBTYPE_PROBE_RESPONSE = 5
SUBTYPE_BEACON = 8
SUBTYPE_ATIM = 9
SUBTYPE_DISASSOCIATION = 10
SUBTYPE_AUTHENTICATION = 11
SUBTYPE_DEAUTHENTICATION = 12

SUBTYPE_NAMES: Dict[int, str] = {
    SUBTYPE_ASSOCIATION_REQUEST: "association-request",
    SUBTYPE_ASSOCIATION_RESPONSE: "association-response",
    SUBTYPE_REASSOCIATION_REQUEST: "reassociation-request",
    SUBTYPE_REASSOCIATION_RESPONSE: "reassociation-response",
    SUBTYPE_PROBE_REQUEST: "probe-request",
    SUBTYPE_PROBE_RESPONSE: "probe-response",
    SUBTYPE_BEACON: "beacon",
    SUBTYPE_ATIM: "atim",
    SUBTYPE_DISASSOCIATION: "disassociation",
    SUBTYPE_AUTHENTICATION: "authentication",
    SUBTYPE_DEAUTHENTICATION: "deauthentication",
}

#: The two management subtypes that tear an association down.
TEARDOWN_SUBTYPES: Tuple[int, ...] = (SUBTYPE_DISASSOCIATION, SUBTYPE_DEAUTHENTICATION)

#: Destination used by the crudest deauth floods (kicks every station at once).
BROADCAST_ADDRESS = "ff:ff:ff:ff:ff:ff"

# ------------------------------------------------------------------ reasons
#: IEEE 802.11 reason codes (the ones seen in practice).
REASON_CODES: Dict[int, str] = {
    0: "Reserved",
    1: "Unspecified reason",
    2: "Previous authentication no longer valid",
    3: "Deauthenticated because sending station is leaving",
    4: "Disassociated due to inactivity",
    5: "Disassociated because AP is unable to handle all associated stations",
    6: "Class 2 frame received from nonauthenticated station",
    7: "Class 3 frame received from nonassociated station",
    8: "Disassociated because sending station is leaving",
    9: "Station requesting reassociation is not authenticated",
    15: "4-way handshake timeout",
    16: "Group key handshake timeout",
}

#: A deauth carrying this reason proves the sender is not a party to the
#: association: a strong spoofing signal used by attack tools.
REASON_NONASSOCIATED = 7

#: Reason codes that appear in the great majority of deauth floods.
FLOOD_REASON_CODES: Tuple[int, ...] = (1, 2, 3, 6, 7)

# ------------------------------------------------------------------- pcap
#: Link-layer types (the ``network`` field of a pcap global header).
LINKTYPE_ETHERNET = 1
LINKTYPE_IEEE802_11 = 105
LINKTYPE_IEEE802_11_RADIOTAP = 127
LINKTYPE_PRISM = 119

#: Link types whose payload the detector knows how to read.
SUPPORTED_LINKTYPES: Tuple[int, ...] = (LINKTYPE_IEEE802_11, LINKTYPE_IEEE802_11_RADIOTAP)

# --------------------------------------------------------------- defaults
#: Sliding window used to judge a burst, in seconds.
DEFAULT_WINDOW_SECONDS = 10.0
#: Teardown frames from one transmitter inside the window that mark a flood.
DEFAULT_FLOOD_THRESHOLD = 10
#: Distinct victims from one transmitter inside the window that mark a sweep.
DEFAULT_DISTINCT_VICTIM_THRESHOLD = 5


__all__ = [
    "BROADCAST_ADDRESS",
    "DEFAULT_DISTINCT_VICTIM_THRESHOLD",
    "DEFAULT_FLOOD_THRESHOLD",
    "DEFAULT_WINDOW_SECONDS",
    "FLOOD_REASON_CODES",
    "LINKTYPE_ETHERNET",
    "LINKTYPE_IEEE802_11",
    "LINKTYPE_IEEE802_11_RADIOTAP",
    "LINKTYPE_PRISM",
    "REASON_CODES",
    "REASON_NONASSOCIATED",
    "SUBTYPE_NAMES",
    "SUPPORTED_LINKTYPES",
    "TEARDOWN_SUBTYPES",
    "TYPE_CONTROL",
    "TYPE_DATA",
    "TYPE_MANAGEMENT",
]
