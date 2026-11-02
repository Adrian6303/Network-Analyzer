import unittest

from capture_worker import parse_channels
from wifi_analyzer import CHANNELS_5_GHZ


class CaptureWorkerTests(unittest.TestCase):
    def test_parses_24_and_5_ghz_channels(self):
        self.assertEqual(parse_channels("1,13,36,149,165"), [1, 13, 36, 149, 165])

    def test_parses_all_common_5_ghz_channels(self):
        self.assertEqual(
            parse_channels(",".join(str(channel) for channel in CHANNELS_5_GHZ)),
            list(CHANNELS_5_GHZ),
        )

    def test_rejects_empty_or_unsupported_channels(self):
        for value in ("", "0", "14", "177"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_channels(value)


if __name__ == "__main__":
    unittest.main()
