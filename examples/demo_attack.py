"""Generate a synthetic deauthentication attack and analyse it end to end.

Standard library only, so it also runs as a CI smoke test::

    python examples/demo_attack.py

The produced ``examples/attack.pcap`` is committed to the repository, which
makes the README command work out of the box::

    python main.py examples/attack.pcap
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from deauth_detector import DeauthDetector, frames_from_pcap, write_pcap  # noqa: E402
from deauth_detector import reporters  # noqa: E402

ATTACKER = "aa:aa:aa:aa:aa:aa"
AP = "bb:bb:bb:bb:bb:bb"
VICTIMS = (
    "cc:cc:cc:cc:cc:01",
    "cc:cc:cc:cc:cc:02",
    "cc:cc:cc:cc:cc:03",
    "cc:cc:cc:cc:cc:04",
    "cc:cc:cc:cc:cc:05",
    "cc:cc:cc:cc:cc:06",
)
BROADCAST = "ff:ff:ff:ff:ff:ff"
BASE = 1_700_000_000.0
CHANNEL_FREQUENCY = 2437  # channel 6


def mac(raw: str) -> bytes:
    return bytes(int(part, 16) for part in raw.split(":"))


def management(subtype: int, receiver: str, transmitter: str, bssid: str, body: bytes) -> bytes:
    frame_control = ((subtype & 0x0F) << 4) | (0 << 2)  # type = management
    return (
        struct.pack("<H", frame_control)
        + b"\x00\x00"
        + mac(receiver)
        + mac(transmitter)
        + mac(bssid)
        + b"\x00\x00"
        + body
    )


def deauth(receiver: str, reason: int = 1) -> bytes:
    return management(12, receiver, ATTACKER, AP, struct.pack("<H", reason))


def disassoc(receiver: str, reason: int = 8) -> bytes:
    return management(10, receiver, ATTACKER, AP, struct.pack("<H", reason))


def beacon() -> bytes:
    return management(8, BROADCAST, AP, AP, b"\x00" * 12)


def packet(raw: bytes, at: float, rssi: int = -42) -> tuple:
    """One radiotap-tagged packet: the present word exposes signal and channel."""
    fields = struct.pack("<HH", CHANNEL_FREQUENCY, 0) + bytes([rssi & 0xFF])
    present = (1 << 3) | (1 << 5)
    header = struct.pack("<BBHI", 0, 0, 8 + len(fields), present)
    return (at, header + fields + raw)


def build_capture() -> list:
    """A quiet cell that gets swept, flooded and swept again."""
    packets = []
    packets += [packet(beacon(), BASE + index * 1.0, rssi=-55) for index in range(6)]
    # 1. every station of the cell kicked at once -> DE-002
    packets += [packet(deauth(BROADCAST), BASE + 6.0 + index * 0.2) for index in range(3)]
    # 2. one deauth per client -> DE-003
    packets += [packet(deauth(victim), BASE + 6.5 + index * 0.05) for index, victim in enumerate(VICTIMS)]
    # 3. repeated teardown of a single client -> DE-001
    packets += [packet(deauth(VICTIMS[0]), BASE + 7.0 + index * 0.1) for index in range(14)]
    # 4. disassociation flood -> DE-004
    packets += [packet(disassoc(VICTIMS[1]), BASE + 8.5 + index * 0.05) for index in range(12)]
    # 5. reason code 7: a station that is not part of the association -> DE-005
    packets.append(packet(deauth(VICTIMS[2], reason=7), BASE + 9.2))
    packets.sort(key=lambda item: item[0])
    return packets


def main() -> int:
    path = Path(__file__).resolve().parent / "attack.pcap"
    packets = build_capture()
    write_pcap(path, packets)
    print(f"wrote {path.name}: {len(packets)} packets\n")

    detector = DeauthDetector()
    detector.add_many(frames_from_pcap(path))
    report = detector.report(target=path.name)
    print(reporters.render(report, "console", use_color=False))
    print(f"risk score: {report.risk_score()}/100 (grade {report.grade()})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
