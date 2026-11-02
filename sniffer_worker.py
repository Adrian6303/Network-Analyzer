#!/usr/bin/env python3
"""Capture raw link-layer frames and emit manually parsed packet records."""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import time
from typing import Any

from raw_packet_parser import parse_raw_frame

ETH_P_ALL = 0x0003


def emit(event: dict[str, Any]) -> None:
    print(json.dumps(event, ensure_ascii=True), flush=True)


def open_capture_socket(interface: str) -> socket.socket:
    capture_socket = socket.socket(
        socket.AF_PACKET,
        socket.SOCK_RAW,
        socket.htons(ETH_P_ALL),
    )
    try:
        # The socket is already configured for ETH_P_ALL; zero keeps that
        # protocol while binding it to this interface.
        capture_socket.bind((interface, 0))
        capture_socket.settimeout(0.5)
    except OSError:
        capture_socket.close()
        raise
    return capture_socket


def interface_mode(interface: str) -> str:
    result = subprocess.run(
        ["iw", "dev", interface, "info"],
        check=True,
        capture_output=True,
        text=True,
        timeout=3,
    )
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("type "):
            mode = stripped.partition(" ")[2]
            if mode == "monitor":
                return "monitor"
            if mode == "managed":
                return "managed"
            raise ValueError(f"Unsupported interface type: {mode}. Use managed or monitor mode.")
    raise ValueError(f"Could not determine the mode of interface {interface}.")


def main() -> int:
    if len(sys.argv) != 2 or not sys.argv[1]:
        emit({"type": "error", "message": "Usage: sniffer_worker.py INTERFACE"})
        return 2
    interface = sys.argv[1]
    try:
        mode = interface_mode(interface)
        capture_socket = open_capture_socket(interface)
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        emit({"type": "error", "message": f"Could not start capture on {interface}: {error}"})
        return 1

    emit({"type": "ready", "interface": interface, "mode": mode})
    try:
        while True:
            try:
                frame, _ = capture_socket.recvfrom(65535)
            except socket.timeout:
                continue
            captured_at = time.time()
            try:
                packet = parse_raw_frame(frame, mode)
            except ValueError as error:
                packet = {
                    "timestamp": captured_at,
                    "mode": mode,
                    "length": len(frame),
                    "link": {},
                    "ip": None,
                    "transport": None,
                    "http_ascii": None,
                    "parse_note": str(error),
                    "summary": "Malformed or truncated frame",
                }
            packet["timestamp"] = captured_at
            packet["type"] = "packet"
            emit(packet)
    except OSError as error:
        emit({"type": "error", "message": f"Packet capture stopped: {error}"})
        return 1
    finally:
        capture_socket.close()


if __name__ == "__main__":
    raise SystemExit(main())
