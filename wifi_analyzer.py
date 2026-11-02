"""802.11 management-frame parsing and Wi-Fi metadata helpers."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp, RadioTap


def signal_color(signal_dbm: int | None) -> str:
    if signal_dbm is None:
        return "#667085"
    if signal_dbm >= -50:
        return "#35d39a"
    if signal_dbm >= -70:
        return "#f5c451"
    return "#ff647c"


def frequency_for_channel(channel: int) -> int | None:
    if 1 <= channel <= 13:
        return 2407 + channel * 5
    if channel == 14:
        return 2484
    if 32 <= channel <= 177:
        return 5000 + channel * 5
    return None


def channel_for_frequency(frequency_mhz: int | None) -> int | None:
    if frequency_mhz is None:
        return None
    if frequency_mhz == 2484:
        return 14
    if 2412 <= frequency_mhz <= 2472:
        return (frequency_mhz - 2407) // 5
    if 5000 <= frequency_mhz <= 5885 and frequency_mhz % 5 == 0:
        return (frequency_mhz - 5000) // 5
    if 5955 <= frequency_mhz <= 7115 and frequency_mhz % 5 == 0:
        return (frequency_mhz - 5950) // 5
    return None


def load_oui_database() -> dict[str, str]:
    candidates = (
        Path("/usr/share/ieee-data/oui.txt"),
        Path("/usr/share/wireshark/manuf"),
        Path("/usr/share/misc/oui.txt"),
    )
    manufacturers: dict[str, str] = {}
    for path in candidates:
        if not path.is_file():
            continue
        try:
            with path.open(encoding="utf-8", errors="replace") as oui_file:
                for line in oui_file:
                    parts = line.strip().split(maxsplit=1)
                    if len(parts) != 2:
                        continue
                    prefix = parts[0].upper().replace("-", ":")
                    if len(prefix) == 8 and prefix.count(":") == 2:
                        manufacturers[prefix] = parts[1].strip()
            if manufacturers:
                return manufacturers
        except OSError:
            continue
    return manufacturers


def manufacturer_for_bssid(bssid: str, database: dict[str, str]) -> str:
    prefix = ":".join(bssid.upper().split(":")[:3])
    return database.get(prefix, "Unknown")


def _information_elements(packet: Any) -> list[tuple[int, bytes]]:
    elements: list[tuple[int, bytes]] = []
    element = packet.getlayer(Dot11Elt)
    visited: set[int] = set()
    while isinstance(element, Dot11Elt) and id(element) not in visited:
        visited.add(id(element))
        element_id = getattr(element, "ID", None)
        info = getattr(element, "info", None)
        if isinstance(element_id, int) and isinstance(info, bytes):
            elements.append((element_id, info))
        element = element.payload.getlayer(Dot11Elt)
    return elements


def _rsn_security(info: bytes, prefix: bytes = b"") -> str | None:
    if len(info) < len(prefix) + 2:
        return None
    data = info[len(prefix):]
    if len(data) < 8:
        return None
    group_cipher = data[2:6]
    offset = 2 + 4
    if len(data) < offset + 2:
        return None
    pairwise_count = int.from_bytes(data[offset:offset + 2], "little")
    offset += 2
    pairwise_ciphers = [
        data[index:index + 4]
        for index in range(offset, min(len(data), offset + pairwise_count * 4), 4)
        if len(data[index:index + 4]) == 4
    ]
    offset += pairwise_count * 4
    if len(data) < offset + 2:
        return None
    akm_count = int.from_bytes(data[offset:offset + 2], "little")
    offset += 2
    akms = [
        data[index:index + 4]
        for index in range(offset, min(len(data), offset + akm_count * 4), 4)
        if len(data[index:index + 4]) == 4
    ]
    suite_types = {
        suite[3] for suite in akms
        if suite[:3] in (b"\x00\x0f\xac", b"\x00\x50\xf2")
    }
    if 8 in suite_types or 9 in suite_types or 18 in suite_types:
        protocol = "WPA3"
    elif prefix:
        protocol = "WPA"
    else:
        protocol = "WPA2"
    cipher_names = {
        1: "WEP40",
        2: "TKIP",
        4: "CCMP",
        5: "WEP104",
        6: "BIP",
        8: "GCMP",
        9: "GCMP-256",
        10: "CCMP-256",
    }
    ciphers = {
        cipher_names[suite[3]]
        for suite in [group_cipher, *pairwise_ciphers]
        if suite[:3] in (b"\x00\x0f\xac", b"\x00\x50\xf2")
        and suite[3] in cipher_names
    }
    return f"{protocol} · {'/'.join(sorted(ciphers))}" if ciphers else protocol


def _security_for_packet(packet: Any, elements: list[tuple[int, bytes]]) -> str:
    if any(element_id == 48 for element_id, _ in elements):
        rsn = next(info for element_id, info in elements if element_id == 48)
        return _rsn_security(rsn) or "WPA2"
    wpa_element = next(
        (
            info for element_id, info in elements
            if element_id == 221 and info.startswith(b"\x00\x50\xf2\x01")
        ),
        None,
    )
    if wpa_element is not None:
        return _rsn_security(wpa_element, b"\x00\x50\xf2\x01") or "WPA"
    beacon = packet.getlayer(Dot11Beacon) or packet.getlayer(Dot11ProbeResp)
    capabilities = getattr(beacon, "cap", None)
    privacy = getattr(capabilities, "privacy", False)
    return "WEP" if privacy else "Open"


def parse_management_frame(packet: Any) -> dict[str, Any] | None:
    """Return one AP observation for a Beacon or Probe Response, otherwise None."""
    dot11 = packet.getlayer(Dot11)
    beacon = packet.getlayer(Dot11Beacon) or packet.getlayer(Dot11ProbeResp)
    if dot11 is None or beacon is None or dot11.addr3 is None:
        return None
    elements = _information_elements(packet)
    ssid_bytes = next((info for element_id, info in elements if element_id == 0), b"")
    try:
        ssid = ssid_bytes.decode("utf-8", errors="replace").strip("\x00")
    except AttributeError:
        ssid = ""
    channel = next(
        (info[0] for element_id, info in elements if element_id in (3, 61) and info),
        None,
    )
    radio = packet.getlayer(RadioTap)
    frequency = radio.fields.get("ChannelFrequency") if radio else None
    if isinstance(frequency, int) and frequency > 0:
        channel = channel_for_frequency(frequency) or channel
    if channel is None:
        channel = getattr(beacon, "network_stats", lambda: {})().get("channel")
    if isinstance(frequency, int) and frequency > 0:
        frequency_mhz = frequency
    else:
        frequency_mhz = frequency_for_channel(int(channel)) if channel is not None else None
    signal = radio.fields.get("dBm_AntSignal") if radio else None
    if not isinstance(signal, int):
        signal = None
    bssid = str(dot11.addr3).upper()
    return {
        "type": "network",
        "ssid": ssid or None,
        "bssid": bssid,
        "signal_dbm": signal,
        "channel": int(channel) if channel is not None else None,
        "frequency_mhz": int(frequency_mhz) if frequency_mhz is not None else None,
        "security": _security_for_packet(packet, elements),
        "timestamp": time.time(),
    }
