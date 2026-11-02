#!/usr/bin/env python3
"""Privileged passive-capture helper; emits one JSON object per event."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
from typing import Any

from scapy.all import sniff

from wifi_analyzer import (
    SUPPORTED_CHANNELS,
    load_oui_database,
    manufacturer_for_bssid,
    parse_management_frame,
)


def emit(event: dict[str, Any]) -> None:
    print(json.dumps(event, ensure_ascii=True), flush=True)


def parse_channels(value: str) -> list[int]:
    channels = [int(channel) for channel in value.split(",") if channel]
    if not channels or any(channel not in SUPPORTED_CHANNELS for channel in channels):
        raise ValueError("Selected channels must be supported 2.4 GHz or 5 GHz Wi-Fi channels.")
    return channels


def main() -> int:
    if len(sys.argv) != 3:
        emit({"type": "error", "message": "Usage: capture_worker.py INTERFACE CHANNELS"})
        return 2
    interface = sys.argv[1]
    try:
        channels = parse_channels(sys.argv[2])
    except ValueError as error:
        emit({"type": "error", "message": str(error)})
        return 2

    try:
        result = subprocess.run(
            ["iw", "dev", interface, "info"],
            check=True,
            capture_output=True,
            text=True,
            timeout=3,
        )
    except (OSError, subprocess.SubprocessError) as error:
        emit({"type": "error", "message": f"Could not check interface {interface}: {error}"})
        return 1
    if "type monitor" not in result.stdout:
        emit({"type": "error", "message": f"Interface {interface} is not in monitor mode."})
        return 1

    iw_path = shutil.which("iw")
    if iw_path is None:
        emit({"type": "error", "message": "The `iw` command is not installed."})
        return 1
    oui_database = load_oui_database()
    warned_channels: set[int] = set()
    emit({"type": "ready", "interface": interface})

    def handle_packet(packet: Any) -> None:
        observation = parse_management_frame(packet)
        if observation is None:
            return
        bssid = observation["bssid"]
        observation["manufacturer"] = manufacturer_for_bssid(bssid, oui_database)
        emit(observation)

    while True:
        for channel in channels:
            try:
                subprocess.run(
                    [iw_path, "dev", interface, "set", "channel", str(channel)],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=3,
                )
            except (OSError, subprocess.SubprocessError) as error:
                if channel not in warned_channels:
                    message = str(error)
                    if isinstance(error, subprocess.CalledProcessError) and error.stderr:
                        message = error.stderr.strip()
                    emit({
                        "type": "warning",
                        "message": f"Could not scan channel {channel}: {message}",
                    })
                    warned_channels.add(channel)
                continue
            emit({"type": "channel", "channel": channel})
            try:
                sniff(
                    iface=interface,
                    prn=handle_packet,
                    store=False,
                    timeout=1.2,
                    monitor=True,
                )
            except Exception as error:
                emit({"type": "error", "message": f"Packet capture error: {error}"})
                return 1
        if len(warned_channels) == len(channels):
            emit({
                "type": "error",
                "message": "The adapter could not set any selected channel; check the regulatory domain and driver.",
            })
            return 1
        time.sleep(0.05)


if __name__ == "__main__":
    raise SystemExit(main())
