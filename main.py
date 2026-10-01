#!/usr/bin/env python3
"""Entry point of the Wi-Fi deauthentication detector.

Examples::

    python main.py capture.pcap
    python main.py capture.pcap --format json -o report.json
    python main.py capture.pcap --fail-on high --no-color
    python main.py --interface wlan0mon --flood-threshold 5
    python main.py --list-rules
"""

from __future__ import annotations

import sys

from deauth_detector.cli import main

if __name__ == "__main__":
    sys.exit(main())
