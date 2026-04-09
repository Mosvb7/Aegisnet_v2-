"""
netcapture.py  —  AegisNet Packet Capture Module
=================================================
Real-world replacement for packet_capture.py.

Key differences from the simulation version:
  - No longer sends a hardcoded packet_count=50 for every single packet.
  - Implements per-flow aggregation: packets are grouped by
    (src_ip, dst_ip, dst_port) over a configurable time window
    (default 5 seconds), then the aggregated stats are sent to the engine.
  - Tracks distinct destination ports per source — essential for port scan
    detection in realengine.py.
  - Reports real byte counts alongside packet counts.
  - Prints a live flow summary table every PRINT_INTERVAL seconds so you
    can see what's happening on the wire.

NOTE: This module is OPTIONAL in the real-world setup.
      realengine.py already runs its own internal sniffer thread.
      Use netcapture.py only if you want to run packet capture on a
      SEPARATE machine and forward flows to realengine.py over the network
      (e.g. a dedicated sensor VM pointing at a remote engine IP).

Run:
    sudo python netcapture.py

Dependencies:
    pip install scapy requests
"""

import time
import threading
import requests
from collections import defaultdict
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP

# ──────────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────────

# Address of realengine.py Flask API
ENGINE_URL = "http://127.0.0.1:5000/inject"

# Network interface to capture on (None = default interface)
# Examples: "eth0", "wlan0", "en0"
INTERFACE = 'en0'

# How many seconds to aggregate packets before sending a flow report
FLOW_WINDOW = 5  # seconds

# Print live flow table every N seconds (0 to disable)
PRINT_INTERVAL = 10

# ──────────────────────────────────────────────
# FLOW TABLE
# ──────────────────────────────────────────────
#
# Key:   (src_ip, dst_ip, dst_port)
# Value: {
#           "pkt_count": int,
#           "byte_count": int,
#           "ports":      set of dst_ports seen from src_ip,
#           "start":      float (epoch of first packet in this window)
#        }

_flows: dict = defaultdict(lambda: {
    "pkt_count":  0,
    "byte_count": 0,
    "ports":      set(),
    "start":      time.time()
})
_flow_lock = threading.Lock()
_stats = {"total_pkts": 0, "total_flows_sent": 0}


def handle_packet(pkt):
    """Called by Scapy for every captured IP packet."""
    if not pkt.haslayer(IP):
        return

    src_ip   = pkt[IP].src
    dst_ip   = pkt[IP].dst
    pkt_len  = len(pkt)
    dst_port = 0

    if pkt.haslayer(TCP):
        dst_port = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        dst_port = pkt[UDP].dport

    key = (src_ip, dst_ip, dst_port)

    with _flow_lock:
        _flows[key]["pkt_count"]  += 1
        _flows[key]["byte_count"] += pkt_len
        _flows[key]["ports"].add(dst_port)
        _stats["total_pkts"] += 1


# ──────────────────────────────────────────────
# FLOW FLUSHER THREAD
# ──────────────────────────────────────────────

def flush_flows():
    """
    Every FLOW_WINDOW seconds, collect all aged flows, send them to the
    engine, then clear them from the table.
    """
    while True:
        time.sleep(FLOW_WINDOW)
        now = time.time()

        aged = {}
        with _flow_lock:
            aged_keys = [
                k for k, v in _flows.items()
                if now - v["start"] >= FLOW_WINDOW
            ]
            for k in aged_keys:
                aged[k] = _flows.pop(k)

        for (src_ip, dst_ip, dst_port), data in aged.items():
            payload = {
                "source_ip":      src_ip,
                "destination_ip": dst_ip,
                "dst_port":       dst_port,
                "packet_count":   data["pkt_count"],
                "byte_count":     data["byte_count"],
                "duration":       FLOW_WINDOW,
                "port_count":     len(data["ports"]),
                # failed_logins cannot be derived from raw packets;
                # the engine defaults it to 0 and correlates auth logs
                # separately if integrated with syslog/auth.log
                "failed_logins":  0,
            }
            try:
                requests.post(ENGINE_URL, json=payload, timeout=2)
                _stats["total_flows_sent"] += 1
            except requests.exceptions.ConnectionError:
                print("[WARN] Engine unreachable — flow dropped")
            except Exception as exc:
                print(f"[ERROR] Sending flow: {exc}")


# ──────────────────────────────────────────────
# LIVE STATS PRINTER
# ──────────────────────────────────────────────

def print_stats():
    """Print a periodic summary so you know the capture is alive."""
    while True:
        time.sleep(PRINT_INTERVAL)
        ts = datetime.now().strftime("%H:%M:%S")

        with _flow_lock:
            active_flows = len(_flows)

        print(
            f"[{ts}]  active flows={active_flows:>4}  "
            f"total pkts={_stats['total_pkts']:>8}  "
            f"flows sent={_stats['total_flows_sent']:>6}"
        )

        # Also print top-5 talkers by packet count
        with _flow_lock:
            top = sorted(
                _flows.items(),
                key=lambda x: x[1]["pkt_count"],
                reverse=True
            )[:5]

        if top:
            print(f"  {'SOURCE IP':<18} {'DST IP':<18} {'PORT':>6} {'PKTS':>8} {'BYTES':>10}")
            for (src, dst, port), data in top:
                print(f"  {src:<18} {dst:<18} {port:>6} "
                      f"{data['pkt_count']:>8} {data['byte_count']:>10}")


# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────

def start():
    iface_str = INTERFACE if INTERFACE else "default"
    print("=" * 50)
    print("  AegisNet Packet Capture  —  netcapture.py")
    print("=" * 50)
    print(f"  Interface   : {iface_str}")
    print(f"  Engine URL  : {ENGINE_URL}")
    print(f"  Flow window : {FLOW_WINDOW}s")
    print("=" * 50)

    # Start the flow flusher thread
    threading.Thread(target=flush_flows, daemon=True, name="flusher").start()

    # Start the stats printer thread
    if PRINT_INTERVAL > 0:
        threading.Thread(target=print_stats, daemon=True, name="printer").start()

    print(f"[SNIFF] Listening on interface: {iface_str}  (Ctrl+C to stop)\n")
    try:
        sniff(
            iface=INTERFACE,
            filter="ip",
            prn=handle_packet,
            store=False
        )
    except KeyboardInterrupt:
        print("\n[SHUTDOWN] netcapture.py stopped.")
    except PermissionError:
        print("[ERROR] Permission denied — run with:  sudo python netcapture.py")
    except Exception as exc:
        print(f"[ERROR] Sniffer crashed: {exc}")


if __name__ == "__main__":
    start()
