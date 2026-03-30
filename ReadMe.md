# JamX 🔴

```
     ██╗ █████╗ ███╗   ███╗██╗  ██╗
     ██║██╔══██╗████╗ ████║╚██╗██╔╝
     ██║███████║██╔████╔██║ ╚███╔╝
██   ██║██╔══██║██║╚██╔╝██║ ██╔██╗
╚█████╔╝██║  ██║██║ ╚═╝ ██║██╔╝ ██╗
 ╚════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝

  ⚡ Multi-Target WiFi Deauth Tool ⚡
   Built by : bxbySAMRAT
  [ Auto Monitor Mode | Scapy-Powered ]
       FOR AUTHORIZED USE ONLY 🔴
```

**Multi-Target WiFi Deauthentication Tool with Auto Monitor Mode**

⚠️ **For authorized penetration testing and lab environments ONLY.**

Unauthorized use against networks you do not own or have explicit written permission to test is **illegal** under the Computer Fraud and Abuse Act (CFAA), IT Act 2000, and equivalent laws worldwide.

---

## 📌 Overview

**JamX** is a Python-based wireless deauthentication tool that automates the full attack pipeline:

- Automatically enables **monitor mode** on the target interface
- Hops across all **13 Wi-Fi channels** to discover nearby access points
- Launches **concurrent multi-threaded deauth attacks** across all discovered networks
- **Restores** the interface to managed mode upon completion or interruption

Built with [Scapy](https://scapy.net/) and standard Linux wireless tooling (`airmon-ng`, `iw`, `iwconfig`).

---

## 🛠️ Requirements

### OS
- Kali Linux / Parrot OS / Any Debian-based Linux distro

### Hardware
- Wireless NIC with **monitor mode** and **packet injection** support
  - ✅ Alfa AWUS036ACH
  - ✅ Alfa AWUS036NHA
  - ✅ TP-Link TL-WN722N v1

### System Dependencies

```bash
sudo apt update && sudo apt install -y aircrack-ng iw wireless-tools
```

### Python Dependencies

```bash
sudo apt install python3-scapy
```

---

## 📦 Installation

```bash
git clone https://github.com/bxbySAMRAT/jamx.git
cd jamx

```
---

## 🚀 Usage

```bash
sudo python3 jamx.py -i <interface> [options]
```

> ⚡ Must be run as **root**.

### Arguments

| Flag | Long Flag    | Default      | Description                              |
|------|-------------|--------------|------------------------------------------|
| `-i` | `--iface`   | *(required)* | Wireless interface (e.g., `wlan0`)       |
| `-s` | `--scan`    | `15`         | Scan duration in seconds                 |
| `-c` | `--count`   | `500`        | Deauth frames per AP                     |
| `-t` | `--interval`| `0.05`       | Interval between frames (seconds)        |
| `-T` | `--threads` | `10`         | Max concurrent attack threads            |

### Examples

```bash
# Basic run — default settings
sudo python3 jamx.py -i wlan0

# Extended scan (30s) with aggressive frame count
sudo python3 jamx.py -i wlan0 -s 30 -c 1000 -t 0.02

# Conservative attack with fewer threads
sudo python3 jamx.py -i wlan0 -s 20 -c 300 -T 5
```

---

## ⚙️ How It Works

### Attack Pipeline

**[1] Auto Monitor Mode**
- airmon-ng check kill → airmon-ng start <iface>
- Fallback 1: check <iface>mon via iwconfig
- Fallback 2: iw manual monitor mode

**[2] Channel Hopper (background thread)**
- Cycles CH 1–13 every 250ms during scan
- Enables discovery across all Wi-Fi channels

**[3] Beacon Sniffer**
- Sniffs Dot11Beacon frames
- Extracts SSID, BSSID, Channel → stored in ap_store

**[4] Multi-threaded Deauth**
- Semaphore-throttled workers (default: 10 threads)
- Sends Dot11Deauth (reason=7) broadcast frames per AP
- Concurrent attacks reduce detection risk

**[5] Auto Restore**
- airmon-ng stop → NetworkManager restart
- Leaves system in clean state

---

## 🗂️ Project Structure

```
jamx/
├── jamx.py           # Main tool
├── requirements.txt  # Python dependencies
└── README.md         # This file
```

---# JamX
