import unittest

from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap

from wifi_analyzer import (
    channel_for_frequency,
    frequency_for_channel,
    manufacturer_for_bssid,
    parse_management_frame,
    signal_color,
)


class WifiAnalyzerTests(unittest.TestCase):
    def test_channel_frequency_conversion(self):
        self.assertEqual(frequency_for_channel(1), 2412)
        self.assertEqual(frequency_for_channel(13), 2472)
        self.assertEqual(channel_for_frequency(2412), 1)
        self.assertEqual(channel_for_frequency(5240), 48)

    def test_signal_color_thresholds(self):
        self.assertEqual(signal_color(-49), "#35d39a")
        self.assertEqual(signal_color(-60), "#f5c451")
        self.assertEqual(signal_color(-71), "#ff647c")
        self.assertEqual(signal_color(None), "#667085")

    def test_unknown_manufacturer_fallback_is_english(self):
        self.assertEqual(manufacturer_for_bssid("12:34:56:78:9a:bc", {}), "Unknown")

    def test_parses_beacon_metadata(self):
        packet = (
            RadioTap(ChannelFrequency=2412, dBm_AntSignal=-58)
            / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                    addr2="12:34:56:78:9a:bc", addr3="12:34:56:78:9a:bc")
            / Dot11Beacon(cap="ESS")
            / Dot11Elt(ID="SSID", info=b"Test WiFi")
            / Dot11Elt(ID="DSset", info=b"\x01")
        )
        observation = parse_management_frame(packet)
        self.assertIsNotNone(observation)
        assert observation is not None
        self.assertEqual(observation["ssid"], "Test WiFi")
        self.assertEqual(observation["bssid"], "12:34:56:78:9A:BC")
        self.assertEqual(observation["channel"], 1)
        self.assertEqual(observation["frequency_mhz"], 2412)
        self.assertEqual(observation["signal_dbm"], -58)
        self.assertEqual(observation["security"], "Open")

    def test_parses_wpa2_security(self):
        rsn = (
            b"\x01\x00"
            b"\x00\x0f\xac\x04"
            b"\x01\x00\x00\x0f\xac\x04"
            b"\x01\x00\x00\x0f\xac\x02"
        )
        packet = (
            RadioTap(ChannelFrequency=2437, dBm_AntSignal=-47)
            / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                    addr2="12:34:56:78:9a:bd", addr3="12:34:56:78:9a:bd")
            / Dot11Beacon(cap="ESS+privacy")
            / Dot11Elt(ID="SSID", info=b"Secure")
            / Dot11Elt(ID=48, info=rsn)
        )
        observation = parse_management_frame(packet)
        self.assertIsNotNone(observation)
        assert observation is not None
        self.assertEqual(observation["security"], "WPA2 · CCMP")
        self.assertEqual(observation["signal_dbm"], -47)

    def test_ignores_non_beacon_frames(self):
        packet = RadioTap() / Dot11(type=2, subtype=0)
        self.assertIsNone(parse_management_frame(packet))


if __name__ == "__main__":
    unittest.main()
