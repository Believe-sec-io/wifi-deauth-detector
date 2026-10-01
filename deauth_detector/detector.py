"""The stateful detection engine.

It keeps a sliding window of teardown frames per transmitter and turns counts
and patterns into alerts. A rule fires once per transmitter while its condition
holds, then re-arms when the condition clears, so a sustained attack yields one
alert instead of one per frame.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, List, Optional, Set, Tuple

from . import rules
from .constants import (
    BROADCAST_ADDRESS,
    DEFAULT_DISTINCT_VICTIM_THRESHOLD,
    DEFAULT_FLOOD_THRESHOLD,
    DEFAULT_WINDOW_SECONDS,
    REASON_NONASSOCIATED,
    SUBTYPE_DEAUTHENTICATION,
    SUBTYPE_DISASSOCIATION,
)
from .models import Alert, Dot11Frame, Report

#: One observed teardown frame: (timestamp, receiver, subtype, reason).
_Event = Tuple[float, str, int, Optional[int]]


@dataclass
class DetectorConfig:
    """Tunable thresholds (mirrored on the command line)."""

    window: float = DEFAULT_WINDOW_SECONDS
    flood_threshold: int = DEFAULT_FLOOD_THRESHOLD
    distinct_victim_threshold: int = DEFAULT_DISTINCT_VICTIM_THRESHOLD


class DeauthDetector:
    """Feed it frames, read the alerts it produces."""

    def __init__(self, config: Optional[DetectorConfig] = None) -> None:
        self.config = config or DetectorConfig()
        self._events: Dict[str, Deque[_Event]] = defaultdict(deque)
        self._fired: Dict[str, Set[str]] = defaultdict(set)
        self._alerts: List[Alert] = []
        self.frames_seen = 0
        self.teardown_frames = 0

    # ------------------------------------------------------------------ input
    def add(self, frame: Dot11Frame) -> List[Alert]:
        """Feed one frame; return the new alerts it triggered (possibly empty)."""
        self.frames_seen += 1
        if not frame.is_teardown:
            return []

        self.teardown_frames += 1
        events = self._events[frame.transmitter]
        events.append(
            (frame.timestamp, frame.receiver, frame.subtype, frame.reason_code)
        )
        self._prune(events, frame.timestamp)

        new_alerts = self._evaluate(frame, events)
        self._alerts.extend(new_alerts)
        return new_alerts

    def add_many(self, frames) -> List[Alert]:
        """Feed an iterable of frames and return every alert raised."""
        collected: List[Alert] = []
        for frame in frames:
            collected.extend(self.add(frame))
        return collected

    # ----------------------------------------------------------------- output
    @property
    def alerts(self) -> List[Alert]:
        return list(self._alerts)

    def report(
        self, target: str = "", metadata: Optional[Dict[str, object]] = None
    ) -> Report:
        """Package everything observed into a :class:`~deauth_detector.models.Report`."""
        report = Report(
            target=target,
            frames_seen=self.frames_seen,
            teardown_frames=self.teardown_frames,
        )
        report.extend(list(self._alerts))
        report.sort_alerts()
        report.metadata.update(
            {
                "window_seconds": self.config.window,
                "flood_threshold": self.config.flood_threshold,
                "distinct_victim_threshold": self.config.distinct_victim_threshold,
            }
        )
        if metadata:
            report.metadata.update(metadata)
        return report

    # ----------------------------------------------------------------- intern
    def _prune(self, events: Deque[_Event], newest: float) -> None:
        """Drop events older than the window, relative to the newest timestamp."""
        cutoff = newest - self.config.window
        while events and events[0][0] < cutoff:
            events.popleft()

    def _emit(
        self,
        frame: Dot11Frame,
        rule_id: str,
        condition: bool,
        *,
        message: str,
        evidence: str,
        count: int,
        receiver: str = "",
        first_timestamp: float = 0.0,
        last_timestamp: float = 0.0,
    ) -> Optional[Alert]:
        """Fire ``rule_id`` once per transmitter while ``condition`` stays true."""
        fired = self._fired[frame.transmitter]
        if not condition:
            fired.discard(rule_id)  # re-arm for the next episode
            return None
        if rule_id in fired:
            return None
        fired.add(rule_id)
        return rules.make_alert(
            rule_id,
            message=message,
            transmitter=frame.transmitter,
            bssid=frame.bssid,
            receiver=receiver,
            count=count,
            window=self.config.window,
            evidence=evidence,
            first_timestamp=first_timestamp,
            last_timestamp=last_timestamp,
        )

    def _evaluate(self, frame: Dot11Frame, events: Deque[_Event]) -> List[Alert]:
        config = self.config
        deauth_count = sum(
            1 for _, _, subtype, _ in events if subtype == SUBTYPE_DEAUTHENTICATION
        )
        disassoc_count = sum(
            1 for _, _, subtype, _ in events if subtype == SUBTYPE_DISASSOCIATION
        )
        victims = {receiver for _, receiver, _, _ in events}
        has_broadcast = any(
            receiver == BROADCAST_ADDRESS and subtype == SUBTYPE_DEAUTHENTICATION
            for _, receiver, subtype, _ in events
        )
        has_nonassociated = any(
            reason == REASON_NONASSOCIATED for _, _, _, reason in events
        )
        first_timestamp = events[0][0]
        last_timestamp = events[-1][0]

        out: List[Alert] = []

        def consider(rule_id: str, condition: bool, message: str, evidence: str,
                     count: int, receiver: str = "") -> None:
            alert = self._emit(
                frame,
                rule_id,
                condition,
                message=message,
                evidence=evidence,
                count=count,
                receiver=receiver,
                first_timestamp=first_timestamp,
                last_timestamp=last_timestamp,
            )
            if alert is not None:
                out.append(alert)

        consider(
            "DE-001",
            deauth_count >= config.flood_threshold,
            f"{deauth_count} deauthentication frames from one transmitter "
            f"within {config.window:g}s.",
            f"count={deauth_count} window={config.window:g}s",
            deauth_count,
        )
        consider(
            "DE-002",
            has_broadcast,
            "Deauthentication addressed to the broadcast address "
            "(every station of the cell is disconnected).",
            f"receiver={BROADCAST_ADDRESS}",
            deauth_count,
            receiver=BROADCAST_ADDRESS,
        )
        consider(
            "DE-003",
            len(victims) >= config.distinct_victim_threshold,
            f"{len(victims)} distinct stations targeted by one transmitter "
            f"within {config.window:g}s.",
            f"victims={len(victims)} "
            f"distinct_threshold={config.distinct_victim_threshold}",
            len(victims),
        )
        consider(
            "DE-004",
            disassoc_count >= config.flood_threshold,
            f"{disassoc_count} disassociation frames from one transmitter "
            f"within {config.window:g}s.",
            f"count={disassoc_count} window={config.window:g}s",
            disassoc_count,
        )
        consider(
            "DE-005",
            has_nonassociated,
            "Teardown frame carries reason code 7 "
            "('Class 3 frame received from nonassociated station').",
            f"reason={REASON_NONASSOCIATED}",
            1,
        )
        return out


__all__ = ["DeauthDetector", "DetectorConfig"]

