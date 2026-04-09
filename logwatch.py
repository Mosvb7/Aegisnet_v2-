#!/usr/bin/env python3
"""
logwatch.py  -  AegisNet Auth Log Watcher
==========================================
Tails /var/log/auth.log (Linux/Ubuntu) in real time.
When a failed SSH / sudo / PAM login is detected, it POSTs the
source IP to realengine.py's /login_fail endpoint so the engine
can track brute-force attempts with real data instead of always 0.

Supported log patterns:
  SSH password failure  : Failed password for <user> from <ip> port ...
  SSH invalid user      : Invalid user <user> from <ip> port ...
  PAM auth failure      : pam_unix(sshd:auth): auth failure ... rhost=<ip>
  sudo failure          : sudo: <user>: authentication failure
  FTP (vsftpd) failure  : FAIL LOGIN: Client <ip>

Run alongside realengine.py in a separate terminal:
    sudo python logwatch.py

Dependencies: requests (already installed)
"""

import re
import time
import requests
import sys
import os
from datetime import datetime

# ── CONFIGURATION ─────────────────────────────────────────────────────────────

ENGINE_URL    = "http://127.0.0.1:5001/login_fail"
LOG_FILES     = [
    "/var/log/auth.log",      # Ubuntu / Debian / Raspberry Pi
    "/var/log/secure",        # CentOS / RHEL / Fedora
    "/var/log/system.log",    # macOS / Generic BSD fallback
]
POLL_INTERVAL = 0.5           # seconds between reads

# ── LOG PATTERNS ─────────────────────────────────────────────────────────────
# Each pattern must capture named groups: ip, optionally user and service.

PATTERNS = [
    # SSH: Failed password for root from 1.2.3.4 port 22 ssh2
    (re.compile(
        r"Failed password for (?:invalid user )?(?P<user>\S+) from "
        r"(?P<ip>\d+\.\d+\.\d+\.\d+)"
    ), "ssh"),

    # SSH: Invalid user admin from 1.2.3.4 port 22
    (re.compile(
        r"Invalid user (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
    ), "ssh"),

    # PAM: pam_unix(sshd:auth): authentication failure; ... rhost=1.2.3.4
    (re.compile(
        r"pam_unix\((?P<service>\S+):auth\):.*rhost=(?P<ip>\d+\.\d+\.\d+\.\d+)"
        r"(?:.*user=(?P<user>\S+))?"
    ), "pam"),

    # vsftpd: FAIL LOGIN: Client "1.2.3.4"
    (re.compile(
        r'FAIL LOGIN: Client "(?P<ip>\d+\.\d+\.\d+\.\d+)"'
    ), "ftp"),

    # Generic auth failure with rhost= (catchall for PAM services)
    (re.compile(
        r"authentication failure.*rhost=(?P<ip>\d+\.\d+\.\d+\.\d+)"
    ), "pam"),
]

# ── HELPERS ───────────────────────────────────────────────────────────────────

def find_log() -> str | None:
    """Return the first log file that exists on this system or from args."""
    # Check if a custom log path was provided as a CLI argument
    if len(sys.argv) > 1:
        custom_path = sys.argv[1]
        if os.path.exists(custom_path):
            return custom_path
        else:
            print(f"[ERROR] Specified log file not found: {custom_path}")
            sys.exit(1)

    # Otherwise search default locations
    for f in LOG_FILES:
        if os.path.exists(f):
            return f
    return None

def parse_line(line: str) -> dict | None:
    """
    Try every pattern against the line.
    Returns {"ip": ..., "service": ..., "user": ...} or None.
    """
    for pattern, default_service in PATTERNS:
        m = pattern.search(line)
        if m:
            groups = m.groupdict()
            return {
                "source_ip": groups.get("ip", ""),
                "service":   groups.get("service", default_service),
                "username":  groups.get("user", ""),
            }
    return None

def send_to_engine(event: dict):
    try:
        r = requests.post(ENGINE_URL, json=event, timeout=2)
        ts = datetime.now().strftime("%H:%M:%S")
        data = r.json()
        print(f"[{ts}] LOGIN FAIL  {event['source_ip']:<18}"
              f"  svc={event['service']:<6}"
              f"  user={event['username']:<12}"
              f"  total={data.get('total', '?')}")
    except requests.exceptions.ConnectionError:
        print("[WARN] Engine unreachable — event dropped")
    except Exception as e:
        print(f"[ERR] {e}")

# ── MAIN TAIL LOOP ────────────────────────────────────────────────────────────

def tail(log_path: str):
    """Tail log_path indefinitely, parsing and forwarding failed-login lines."""
    print(f"[WATCH] Tailing {log_path}")
    with open(log_path, "r") as f:
        # Jump to end of file so we only process new lines
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(POLL_INTERVAL)
                continue
            line = line.strip()
            if not line:
                continue
            event = parse_line(line)
            if event and event["source_ip"]:
                send_to_engine(event)

def start():
    print("=" * 50)
    print("  AegisNet Auth Log Watcher  —  logwatch.py")
    print("=" * 50)
    log = find_log()
    if not log:
        print("[ERROR] No auth log found. Tried default paths:", ", ".join(LOG_FILES))
        print("        To specify a custom log file, run:  python logwatch.py /path/to/logfile")
        print("        On macOS, you might want to create a mock log for testing.")
        return

    print(f"[OK]  Engine: {ENGINE_URL}")
    print(f"[OK]  Log:    {log}")
    print("       Watching for failed logins... (Ctrl+C to stop)\n")
    try:
        tail(log)
    except PermissionError:
        print(f"[ERROR] Cannot read {log} — run with:  sudo python logwatch.py")
    except KeyboardInterrupt:
        print("\n[SHUTDOWN] logwatch.py stopped.")

if __name__ == "__main__":
    start()




# geoipupdate -f GeoIP.conf -d geoip.db --> run before running logwatch.py + to update the db 
# to run: sudo python3 /Users/dr.saeedhamadalhassani/Desktop/Aegisnet_ll/logwatch.py