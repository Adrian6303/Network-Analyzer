# Network Analyzer (Linux)

Desktop application that passively scans nearby Wi-Fi networks by capturing
802.11 management frames with Scapy on a wireless interface in **Monitor**
mode, and captures/parses link-layer packets in **Monitor** or **Managed** mode.
It does not connect to networks or inject packets.

## Requirement check

| Requirement | Status |
|---|---|
| Monitor-mode capture and management-frame parsing | Implemented; reads Beacon and Probe Response frames, including Radiotap data. |
| SSID, access-point MAC (BSSID), signal, channel and frequency | Displayed when present in captured frames; unavailable values are shown as unknown/N/A. |
| Manufacturer | Looked up from a local OUI database if one is installed; otherwise shown as Unknown. |
| Security/encryption | Inferred from advertised information elements (for example Open, WEP, WPA2/CCMP). |
| Signal icon colored green/yellow/red | Implemented in the network list. Thresholds: green ≥ −50 dBm; yellow −70 to −51 dBm; red < −70 dBm. |
| Wi-Fi band and channel selection | Supports 2.4 GHz channels 1–13 and common 5 GHz channels. Availability depends on adapter support and the local regulatory domain. |
| Channel graph | Shows networks and signal strength on the selected band; it visualizes observed networks, not actual channel utilization. |
| Actual channel utilization | Not measured. The graph visualizes detected networks and channel overlap, not airtime or percentage utilization. Scanning is sequential, not simultaneous. |
| Packet Sniffer | Implemented in a separate tab. Captures raw link-layer frames with Linux `AF_PACKET` and manually parses Ethernet/802.11, IPv4/IPv6, TCP, UDP, and TCP destination-port 80 ASCII payloads. |

The application selects the USB adapter `wlx90de800c0cb6` by default. The
integrated adapter `wlo1` can remain connected to Wi-Fi while the USB adapter
is used for monitoring or packet capture. In the WiFi Analyzer tab, select the
2.4 GHz or 5 GHz band, then choose all channels in that band or an individual
channel. Channels unavailable to the adapter or prohibited by the regulatory
domain may be skipped during scanning.

## Install

On Ubuntu, install system packages and Python dependencies:

```bash
sudo apt update
sudo apt install python3 python3-venv python3-pip iw iproute2 libxcb-cursor0
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

`libxcb-cursor0` is required by the Qt `xcb` platform plugin on this system.

## Prepare the USB adapter

Check the interface name and confirm that the adapter supports Monitor mode:

```bash
iw dev
iw list
```

The monitoring adapter must be in Monitor mode and not associated with a Wi-Fi
network. The commands below use the USB adapter; replace its name if needed.
They may temporarily interrupt any connection using that adapter:

```bash
sudo nmcli device disconnect wlx90de800c0cb6
sudo nmcli device set wlx90de800c0cb6 managed no
sudo ip link set wlx90de800c0cb6 down
sudo iw dev wlx90de800c0cb6 set type monitor
sudo ip link set wlx90de800c0cb6 up
sudo iw dev wlx90de800c0cb6 set channel 1
iw dev wlx90de800c0cb6 info
```

Confirm the output contains `type monitor`. The adapter and driver must support
the channels being scanned, and the regulatory domain must permit them.

## Run

Launch from a terminal in the active desktop session. Do not start the
graphical application with `sudo`; capture workers use elevated privileges.

```bash
sudo -v
source .venv/bin/activate
python main.py
```

If capture reports that a password is required, run `sudo -v` again in the
terminal and restart the scan. In the application, select the interface and
either scan channels 1–13 or choose one channel, then press **Start scan**.
Press **Stop** to end capture.

## Packet Sniffer

Open the **Packet Sniffer** tab, choose a wireless interface, and press
**Start capture**. The sniffer detects whether the interface is in Managed or
Monitor mode. It displays captured packets in the table; select a row to view
the manually parsed headers and payload details.

- **Managed mode:** Linux normally provides Ethernet frames after Wi-Fi
  decapsulation. The displayed MAC addresses are Ethernet addresses, not the
  original 802.11 header addresses. Capture is limited to packets visible to
  the host/interface.
- **Monitor mode:** Radiotap and 802.11 headers are parsed. Unprotected data
  frames with LLC/SNAP and IPv4/IPv6 payloads can be decoded. Protected
  (encrypted) Wi-Fi payloads cannot be decoded, so inner IP/TCP/UDP headers
  are unavailable unless decryption is separately implemented. Management
  frames such as beacons are still valid captured packets, but do not contain
  IP or transport headers; “No LLC/SNAP network payload” is expected for them.
- IPv4/IPv6 and TCP/UDP fields are decoded from captured bytes. TCP payload is
  shown as escaped ASCII only when the destination port is 80. HTTPS payloads
  are encrypted and are not readable as HTTP text.
- Capture is live and not saved to disk. The table retains up to 2,000 recent
  packets.
- If **Start capture** reports that administrator authorization is missing,
  run `sudo -v` in a terminal and retry. The app checks authorization before
  starting the worker. If capture is active but no rows appear, check that the
  selected interface is receiving traffic and, in Monitor mode, is tuned to a
  channel with nearby activity. In Managed mode, generate traffic on this
  computer (for example, open a web page). The status indicates when capture
  is active but no packets have arrived.

## Restore the USB adapter

After scanning, return the USB adapter to Managed mode and let NetworkManager
manage it again:

```bash
sudo ip link set wlx90de800c0cb6 down
sudo iw dev wlx90de800c0cb6 set type managed
sudo ip link set wlx90de800c0cb6 up
sudo nmcli device set wlx90de800c0cb6 managed yes
nmcli device status
```

The integrated adapter `wlo1` is not changed by these commands.

## Tests

Run the test suite with:

```bash
.venv/bin/python -m unittest discover -s tests -v
```
