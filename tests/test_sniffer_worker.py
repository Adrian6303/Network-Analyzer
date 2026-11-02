import socket
import unittest
from unittest.mock import Mock, patch

from sniffer_worker import ETH_P_ALL, open_capture_socket


class SnifferWorkerTests(unittest.TestCase):
    @patch("sniffer_worker.socket.socket")
    def test_binds_all_protocol_socket_to_interface(self, socket_factory):
        capture_socket = Mock()
        socket_factory.return_value = capture_socket

        result = open_capture_socket("wlo1")

        socket_factory.assert_called_once_with(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.htons(ETH_P_ALL),
        )
        capture_socket.bind.assert_called_once_with(("wlo1", 0))
        capture_socket.settimeout.assert_called_once_with(0.5)
        self.assertIs(result, capture_socket)

    @patch("sniffer_worker.socket.socket")
    def test_closes_socket_if_interface_bind_fails(self, socket_factory):
        capture_socket = Mock()
        capture_socket.bind.side_effect = OSError("interface unavailable")
        socket_factory.return_value = capture_socket

        with self.assertRaisesRegex(OSError, "interface unavailable"):
            open_capture_socket("wlo1")

        capture_socket.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
