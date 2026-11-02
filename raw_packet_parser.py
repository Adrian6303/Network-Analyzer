"""Manual parsers for Ethernet and monitor-mode 802.11 packet captures."""

from __future__ import annotations

import ipaddress
import time
from typing import Any


ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
ETH_P_8021Q = 0x8100
ETH_P_8021AD = 0x88A8
LLC_SNAP = b"\xaa\xaa\x03"


def _mac(data: bytes) -> str:
    return ":".join(f"{octet:02x}" for octet in data)


def _require(data: bytes, offset: int, length: int, label: str) -> None:
    if offset < 0 or length < 0 or offset + length > len(data):
        raise ValueError(f"Truncated {label}.")


def _internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(int.from_bytes(data[index:index + 2], "big") for index in range(0, len(data), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _parse_ethernet(frame: bytes) -> tuple[dict[str, Any], int, int]:
    _require(frame, 0, 14, "Ethernet header")
    destination = _mac(frame[0:6])
    source = _mac(frame[6:12])
    ether_type = int.from_bytes(frame[12:14], "big")
    offset = 14
    vlans: list[dict[str, int]] = []
    while ether_type in (ETH_P_8021Q, ETH_P_8021AD):
        _require(frame, offset, 4, "VLAN header")
        tci = int.from_bytes(frame[offset:offset + 2], "big")
        vlans.append({
            "id": tci & 0x0FFF,
            "priority": (tci >> 13) & 0x7,
            "drop_eligible": (tci >> 12) & 0x1,
        })
        ether_type = int.from_bytes(frame[offset + 2:offset + 4], "big")
        offset += 4
    return {
        "format": "Ethernet",
        "source_mac": source,
        "destination_mac": destination,
        "ether_type": f"0x{ether_type:04x}",
        "vlans": vlans,
    }, offset, ether_type


def _parse_dot11(frame: bytes) -> tuple[dict[str, Any], int, int | None, bool]:
    _require(frame, 0, 8, "Radiotap header")
    radiotap_length = int.from_bytes(frame[2:4], "little")
    if frame[0] != 0 or radiotap_length < 8 or radiotap_length > len(frame):
        raise ValueError("Invalid Radiotap header.")
    _require(frame, radiotap_length, 2, "802.11 frame control")
    frame_control = int.from_bytes(frame[radiotap_length:radiotap_length + 2], "little")
    protocol_version = frame_control & 0x3
    frame_type = (frame_control >> 2) & 0x3
    subtype = (frame_control >> 4) & 0xF
    flags = (frame_control >> 8) & 0xFF
    to_ds = bool(flags & 0x01)
    from_ds = bool(flags & 0x02)
    protected = bool(flags & 0x40)
    header_offset = radiotap_length + 2
    _require(frame, header_offset, 2, "802.11 duration")
    duration = int.from_bytes(frame[header_offset:header_offset + 2], "little")
    header_offset += 2

    addresses: list[str] = []
    if frame_type in (0, 2):
        address_count = 4 if frame_type == 2 and to_ds and from_ds else 3
        _require(frame, header_offset, address_count * 6 + 2, "802.11 addresses")
        addresses = [
            _mac(frame[header_offset + index * 6:header_offset + (index + 1) * 6])
            for index in range(address_count)
        ]
        header_offset += address_count * 6
        sequence_control = int.from_bytes(frame[header_offset:header_offset + 2], "little")
        header_offset += 2
        sequence_number = sequence_control >> 4
        fragment_number = sequence_control & 0xF
        qos_control = None
        if frame_type == 2 and subtype & 0x8:
            _require(frame, header_offset, 2, "802.11 QoS control")
            qos_control = int.from_bytes(frame[header_offset:header_offset + 2], "little")
            header_offset += 2
        if address_count == 4:
            source_mac, destination_mac = addresses[3], addresses[2]
        elif to_ds:
            source_mac, destination_mac = addresses[1], addresses[2]
        elif from_ds:
            source_mac, destination_mac = addresses[2], addresses[0]
        else:
            destination_mac, source_mac = addresses[0], addresses[1]
    else:
        sequence_number = None
        fragment_number = None
        qos_control = None
        source_mac = addresses[1] if len(addresses) > 1 else None
        destination_mac = addresses[0] if addresses else None

    type_names = ("management", "control", "data", "extension")
    dot11 = {
        "format": "IEEE 802.11",
        "radiotap_length": radiotap_length,
        "protocol_version": protocol_version,
        "type": type_names[frame_type],
        "subtype": subtype,
        "to_ds": to_ds,
        "from_ds": from_ds,
        "protected": protected,
        "retry": bool(flags & 0x08),
        "more_fragments": bool(flags & 0x04),
        "power_management": bool(flags & 0x10),
        "more_data": bool(flags & 0x20),
        "duration_id": duration,
        "addresses": addresses,
        "source_mac": source_mac,
        "destination_mac": destination_mac,
        "sequence_number": sequence_number,
        "fragment_number": fragment_number,
        "qos_control": qos_control,
    }

    if frame_type != 2 or protected:
        return dot11, header_offset, None, protected
    _require(frame, header_offset, 8, "802.11 LLC/SNAP header")
    if frame[header_offset:header_offset + 3] != LLC_SNAP:
        return dot11, header_offset, None, False
    ether_type = int.from_bytes(frame[header_offset + 6:header_offset + 8], "big")
    return dot11, header_offset + 8, ether_type, False


def _parse_ipv4(data: bytes, offset: int) -> tuple[dict[str, Any], int, int, int]:
    _require(data, offset, 20, "IPv4 header")
    version_ihl = data[offset]
    version = version_ihl >> 4
    header_length = (version_ihl & 0xF) * 4
    if version != 4 or header_length < 20:
        raise ValueError("Invalid IPv4 header.")
    _require(data, offset, header_length, "IPv4 options")
    total_length = int.from_bytes(data[offset + 2:offset + 4], "big")
    if total_length < header_length:
        raise ValueError("Invalid IPv4 total length.")
    packet_end = min(len(data), offset + total_length)
    flags_fragment = int.from_bytes(data[offset + 6:offset + 8], "big")
    ip_header = {
        "version": version,
        "header_length": header_length,
        "type_of_service": data[offset + 1],
        "total_length": total_length,
        "identification": int.from_bytes(data[offset + 4:offset + 6], "big"),
        "flags": {
            "reserved": bool(flags_fragment & 0x8000),
            "dont_fragment": bool(flags_fragment & 0x4000),
            "more_fragments": bool(flags_fragment & 0x2000),
        },
        "fragment_offset": flags_fragment & 0x1FFF,
        "ttl": data[offset + 8],
        "protocol_number": data[offset + 9],
        "header_checksum": f"0x{int.from_bytes(data[offset + 10:offset + 12], 'big'):04x}",
        "checksum_valid": _internet_checksum(data[offset:offset + header_length]) == 0,
        "source_ip": str(ipaddress.IPv4Address(data[offset + 12:offset + 16])),
        "destination_ip": str(ipaddress.IPv4Address(data[offset + 16:offset + 20])),
        "options_hex": data[offset + 20:offset + header_length].hex(),
    }
    return ip_header, offset + header_length, packet_end, data[offset + 9]


def _parse_ipv6(data: bytes, offset: int) -> tuple[dict[str, Any], int, int, int]:
    _require(data, offset, 40, "IPv6 header")
    first_word = int.from_bytes(data[offset:offset + 4], "big")
    version = first_word >> 28
    if version != 6:
        raise ValueError("Invalid IPv6 header.")
    payload_length = int.from_bytes(data[offset + 4:offset + 6], "big")
    packet_end = min(len(data), offset + 40 + payload_length)
    ip_header = {
        "version": 6,
        "traffic_class": (first_word >> 20) & 0xFF,
        "flow_label": first_word & 0xFFFFF,
        "payload_length": payload_length,
        "next_header": data[offset + 6],
        "hop_limit": data[offset + 7],
        "source_ip": str(ipaddress.IPv6Address(data[offset + 8:offset + 24])),
        "destination_ip": str(ipaddress.IPv6Address(data[offset + 24:offset + 40])),
        "extension_headers": [],
    }
    cursor = offset + 40
    next_header = ip_header["next_header"]
    while next_header in (0, 43, 44, 51, 60):
        _require(data[:packet_end], cursor, 2, "IPv6 extension header")
        extension_type = next_header
        following_header = data[cursor]
        if extension_type == 44:
            extension_length = 8
        elif extension_type == 51:
            extension_length = (data[cursor + 1] + 2) * 4
        else:
            extension_length = (data[cursor + 1] + 1) * 8
        _require(data[:packet_end], cursor, extension_length, "IPv6 extension header")
        ip_header["extension_headers"].append({
            "type": extension_type,
            "length": extension_length,
        })
        if extension_type == 44:
            fragment_field = int.from_bytes(data[cursor + 2:cursor + 4], "big")
            ip_header["fragment_offset"] = (fragment_field >> 3) & 0x1FFF
            ip_header["more_fragments"] = bool(fragment_field & 0x1)
        cursor += extension_length
        next_header = following_header
    ip_header["transport_protocol_number"] = next_header
    return ip_header, cursor, packet_end, next_header


def _parse_transport(
    data: bytes, offset: int, packet_end: int, protocol_number: int
) -> tuple[dict[str, Any] | None, bytes]:
    bounded = data[:packet_end]
    if protocol_number == 6:
        _require(bounded, offset, 20, "TCP header")
        data_offset = (bounded[offset + 12] >> 4) * 4
        if data_offset < 20:
            raise ValueError("Invalid TCP data offset.")
        _require(bounded, offset, data_offset, "TCP options")
        flags_byte = bounded[offset + 13]
        ns_flag = bounded[offset + 12] & 1
        flags = {
            "NS": bool(ns_flag),
            "CWR": bool(flags_byte & 0x80),
            "ECE": bool(flags_byte & 0x40),
            "URG": bool(flags_byte & 0x20),
            "ACK": bool(flags_byte & 0x10),
            "PSH": bool(flags_byte & 0x08),
            "RST": bool(flags_byte & 0x04),
            "SYN": bool(flags_byte & 0x02),
            "FIN": bool(flags_byte & 0x01),
        }
        transport = {
            "protocol": "TCP",
            "source_port": int.from_bytes(bounded[offset:offset + 2], "big"),
            "destination_port": int.from_bytes(bounded[offset + 2:offset + 4], "big"),
            "sequence_number": int.from_bytes(bounded[offset + 4:offset + 8], "big"),
            "acknowledgment_number": int.from_bytes(bounded[offset + 8:offset + 12], "big"),
            "header_length": data_offset,
            "flags": flags,
            "window_size": int.from_bytes(bounded[offset + 14:offset + 16], "big"),
            "checksum": f"0x{int.from_bytes(bounded[offset + 16:offset + 18], 'big'):04x}",
            "urgent_pointer": int.from_bytes(bounded[offset + 18:offset + 20], "big"),
            "options_hex": bounded[offset + 20:offset + data_offset].hex(),
        }
        return transport, bounded[offset + data_offset:packet_end]
    if protocol_number == 17:
        _require(bounded, offset, 8, "UDP header")
        udp_length = int.from_bytes(bounded[offset + 4:offset + 6], "big")
        if udp_length < 8:
            raise ValueError("Invalid UDP length.")
        transport = {
            "protocol": "UDP",
            "source_port": int.from_bytes(bounded[offset:offset + 2], "big"),
            "destination_port": int.from_bytes(bounded[offset + 2:offset + 4], "big"),
            "length": udp_length,
            "checksum": f"0x{int.from_bytes(bounded[offset + 6:offset + 8], 'big'):04x}",
        }
        udp_end = min(packet_end, offset + udp_length)
        return transport, bounded[offset + 8:udp_end]
    return None, b""


def _ascii_payload(payload: bytes) -> str:
    return "".join(
        chr(byte) if byte in (9, 10, 13) or 32 <= byte <= 126 else f"\\x{byte:02x}"
        for byte in payload
    )


def parse_raw_frame(frame: bytes, mode: str) -> dict[str, Any]:
    """Parse a captured Ethernet or Radiotap/802.11 frame without packet libraries."""
    if mode not in ("managed", "monitor"):
        raise ValueError("Mode must be 'managed' or 'monitor'.")
    if not frame:
        raise ValueError("Empty frame.")

    packet: dict[str, Any] = {
        "timestamp": time.time(),
        "mode": mode,
        "length": len(frame),
        "link": {},
        "ip": None,
        "transport": None,
        "http_ascii": None,
        "parse_note": None,
    }

    if mode == "monitor":
        link, offset, ether_type, protected = _parse_dot11(frame)
        packet["link"] = link
        if protected:
            packet["parse_note"] = "Protected 802.11 payload; inner network headers are encrypted."
            packet["protocol"] = "802.11 protected"
            packet["summary"] = (
                f"802.11 protected {link.get('source_mac') or '—'} → "
                f"{link.get('destination_mac') or '—'}"
            )
            return packet
        if ether_type is None:
            packet["parse_note"] = "No LLC/SNAP network payload in this 802.11 frame."
            packet["protocol"] = f"802.11 {link['type']}"
            packet["summary"] = (
                f"802.11 {link['type']} {link.get('source_mac') or '—'} → "
                f"{link.get('destination_mac') or '—'}"
            )
            return packet
    else:
        link, offset, ether_type = _parse_ethernet(frame)
        packet["link"] = link

    if ether_type not in (ETH_P_IP, ETH_P_IPV6):
        packet["parse_note"] = f"Unsupported or non-IP EtherType 0x{ether_type:04x}."
        packet["protocol"] = "Ethernet"
        packet["summary"] = (
            f"{link.get('source_mac') or '—'} → {link.get('destination_mac') or '—'}"
        )
        return packet

    if ether_type == ETH_P_IP:
        ip_header, transport_offset, packet_end, protocol_number = _parse_ipv4(frame, offset)
    else:
        ip_header, transport_offset, packet_end, protocol_number = _parse_ipv6(frame, offset)
    packet["ip"] = ip_header
    packet["source_ip"] = ip_header["source_ip"]
    packet["destination_ip"] = ip_header["destination_ip"]

    if ip_header.get("fragment_offset", 0):
        packet["parse_note"] = "Non-initial IP fragment; transport header is not present."
        transport, payload = None, b""
    else:
        transport, payload = _parse_transport(frame, transport_offset, packet_end, protocol_number)
    packet["transport"] = transport
    packet["protocol"] = transport["protocol"] if transport else f"IP protocol {protocol_number}"
    if transport and transport["protocol"] == "TCP" and transport["destination_port"] == 80:
        packet["http_ascii"] = _ascii_payload(payload)

    source = ip_header["source_ip"]
    destination = ip_header["destination_ip"]
    if transport:
        packet["summary"] = (
            f"{transport['protocol']} {source}:{transport['source_port']} → "
            f"{destination}:{transport['destination_port']}"
        )
    else:
        packet["summary"] = f"IP {source} → {destination}"
    return packet
