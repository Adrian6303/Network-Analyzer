import struct
import unittest

from raw_packet_parser import parse_raw_frame


def ipv4_tcp_frame(payload: bytes = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n") -> bytes:
    source_ip = bytes((192, 0, 2, 10))
    destination_ip = bytes((198, 51, 100, 20))
    source_port = 43210
    destination_port = 80
    tcp = struct.pack(
        "!HHIIHHHH",
        source_port,
        destination_port,
        123456,
        654321,
        (5 << 12) | 0x18,
        4096,
        0x1234,
        0,
    )
    ip_total_length = 20 + len(tcp) + len(payload)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0x10,
        ip_total_length,
        0x3344,
        0x4000,
        64,
        6,
        0,
        source_ip,
        destination_ip,
    )
    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    return ethernet + ip + tcp + payload


def ipv4_udp_frame() -> bytes:
    source_ip = bytes((10, 0, 0, 2))
    destination_ip = bytes((10, 0, 0, 1))
    udp = struct.pack("!HHHH", 5353, 53, 8, 0x4321)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 28, 1, 0, 32, 17, 0, source_ip, destination_ip,
    )
    return bytes.fromhex("00112233445566778899aabb0800") + ip + udp


def ipv6_tcp_frame() -> bytes:
    source_ip = bytes.fromhex("20010db8000000000000000000000001")
    destination_ip = bytes.fromhex("20010db8000000000000000000000002")
    tcp = struct.pack("!HHIIHHHH", 1234, 443, 1, 2, 0x5002, 1024, 0, 0)
    ipv6 = struct.pack(
        "!IHBB16s16s",
        6 << 28,
        len(tcp),
        6,
        32,
        source_ip,
        destination_ip,
    )
    return bytes.fromhex("00112233445566778899aabb86dd") + ipv6 + tcp


def monitor_tcp_frame(payload: bytes = b"GET / HTTP/1.0\r\n\r\n") -> bytes:
    source_ip = bytes((192, 0, 2, 1))
    destination_ip = bytes((203, 0, 113, 5))
    tcp = struct.pack(
        "!HHIIHHHH",
        50000, 80, 10, 20, (5 << 12) | 0x18, 2048, 0, 0,
    )
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 20 + len(tcp) + len(payload), 2, 0, 64, 6, 0,
        source_ip, destination_ip,
    )
    llc_snap = bytes.fromhex("aaaa030000000800")
    destination = bytes.fromhex("001122334455")
    source = bytes.fromhex("66778899aabb")
    bssid = bytes.fromhex("aabbccddeeff")
    dot11 = struct.pack("<HH", 0x0008, 0) + destination + source + bssid + b"\x10\x00"
    radiotap = b"\x00\x00\x08\x00\x00\x00\x00\x00"
    return radiotap + dot11 + llc_snap + ip + tcp + payload


class RawPacketParserTests(unittest.TestCase):
    def test_managed_ethernet_ipv4_tcp_and_http_payload(self):
        packet = parse_raw_frame(ipv4_tcp_frame(), "managed")
        self.assertEqual(packet["link"]["source_mac"], "66:77:88:99:aa:bb")
        self.assertEqual(packet["link"]["destination_mac"], "00:11:22:33:44:55")
        self.assertEqual(packet["ip"]["source_ip"], "192.0.2.10")
        self.assertEqual(packet["ip"]["destination_ip"], "198.51.100.20")
        self.assertEqual(packet["ip"]["ttl"], 64)
        self.assertEqual(packet["transport"]["protocol"], "TCP")
        self.assertEqual(packet["transport"]["source_port"], 43210)
        self.assertEqual(packet["transport"]["destination_port"], 80)
        self.assertTrue(packet["transport"]["flags"]["ACK"])
        self.assertIn("GET / HTTP/1.1", packet["http_ascii"])

    def test_managed_ethernet_ipv4_udp(self):
        packet = parse_raw_frame(ipv4_udp_frame(), "managed")
        self.assertEqual(packet["transport"]["protocol"], "UDP")
        self.assertEqual(packet["transport"]["source_port"], 5353)
        self.assertEqual(packet["transport"]["destination_port"], 53)
        self.assertIsNone(packet["http_ascii"])

    def test_managed_ethernet_ipv6_tcp(self):
        packet = parse_raw_frame(ipv6_tcp_frame(), "managed")
        self.assertEqual(packet["ip"]["version"], 6)
        self.assertEqual(packet["ip"]["source_ip"], "2001:db8::1")
        self.assertEqual(packet["ip"]["destination_ip"], "2001:db8::2")
        self.assertEqual(packet["transport"]["source_port"], 1234)
        self.assertEqual(packet["transport"]["destination_port"], 443)
        self.assertIsNone(packet["http_ascii"])

    def test_managed_vlan_frame(self):
        frame = ipv4_udp_frame()
        frame = frame[:12] + bytes.fromhex("810000640800") + frame[14:]
        packet = parse_raw_frame(frame, "managed")
        self.assertEqual(packet["link"]["vlans"][0]["id"], 100)
        self.assertEqual(packet["transport"]["protocol"], "UDP")

    def test_monitor_radiotap_dot11_and_ip_tcp(self):
        packet = parse_raw_frame(monitor_tcp_frame(), "monitor")
        self.assertEqual(packet["link"]["format"], "IEEE 802.11")
        self.assertEqual(packet["link"]["source_mac"], "66:77:88:99:aa:bb")
        self.assertEqual(packet["link"]["destination_mac"], "00:11:22:33:44:55")
        self.assertEqual(packet["ip"]["source_ip"], "192.0.2.1")
        self.assertEqual(packet["transport"]["destination_port"], 80)
        self.assertIn("GET / HTTP/1.0", packet["http_ascii"])

    def test_malformed_and_truncated_frames_raise_clear_error(self):
        with self.assertRaisesRegex(ValueError, "Truncated Ethernet"):
            parse_raw_frame(b"\x00" * 10, "managed")
        with self.assertRaisesRegex(ValueError, "Radiotap"):
            parse_raw_frame(b"\x00" * 10, "monitor")

    def test_rejects_unknown_mode(self):
        with self.assertRaisesRegex(ValueError, "Mode must be"):
            parse_raw_frame(b"\x00", "unknown")


if __name__ == "__main__":
    unittest.main()
