# AegisNet SOC — Setup & Run Guide

A real-world mini Security Operations Centre built in Python.  
Detects port scans, DDoS, brute-force attacks, and suspicious traffic.  
Blocks threats automatically via `iptables`. Maps attackers on a live geo dashboard.

---

## File Overview

| File | Role | Replaces |
|------|------|----------|
| `realengine.py` | Core IDS/IPS engine — sniffs packets, analyses flows, blocks IPs | `realtime_engine.py` |
| `scandash.py` | Streamlit SOC dashboard — live alerts, geo map, device table | `dashboard.py` |
| `logwatch.py` | Tails `auth.log` → feeds real brute-force data to engine | *(new)* |
| `netcapture.py` | Optional remote sensor — captures packets on a separate machine | `packet_capture.py` |
| `requirements.txt` | All Python dependencies | — |
| *(deleted)* | `attack_simulator.py` — not needed in real-world mode | — |
| *(deleted)* | `port_scan_detector.py` — merged into `realengine.py` | — |

---

## System Requirements

| Requirement | Details |
|-------------|---------|
| OS | Linux — Ubuntu 22.04 / 24.04 recommended. macOS works but `iptables` blocking is disabled. Windows is not supported (Scapy raw sockets require Linux/macOS). |
| Python | 3.11 or higher |
| Privileges | `sudo` / root required for packet sniffing and `iptables` |
| Network | Must be on the same LAN segment you want to monitor |
| Internet | Needed for `ip-api.com` geolocation (optional if using MaxMind offline DB) |

---

## Installation

```bash
# 1. Clone or copy all files into one folder
mkdir aegisnet && cd aegisnet

# 2. (Recommended) Create a virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install all dependencies
pip install -r requirements.txt

# 4. Verify Scapy can see your network interface
sudo python3 -c "from scapy.all import get_if_list; print(get_if_list())"
```

---

## Before You Run — Configuration Checklist

Open `realengine.py` and edit the CONFIG section at the top:

```python
# ── REQUIRED: set your actual network interface ──────────────────
SNIFF_INTERFACE = "any"           # or "eth0", "wlan0", "ens33", etc.

# ── REQUIRED: set your LAN subnet for ARP device discovery ───────
LAN_SUBNET = "192.168.1.0/24"    # change to match your network

# ── REQUIRED: whitelist your gateway so it is never auto-blocked ─
IP_WHITELIST = {
    "127.0.0.1",
    "192.168.1.1",    # <-- your router/gateway IP
    "192.168.1.255",  # broadcast
}

# ── OPTIONAL: offline geolocation (faster, no rate limit) ────────
GEOIP_DB_PATH = None   # set to "/opt/GeoLite2-City.mmdb" if downloaded

# ── OPTIONAL: tune detection thresholds ──────────────────────────
PORT_SCAN_THRESHOLD   = 10    # distinct ports in 5 s → port scan alert
DDOS_PKT_THRESHOLD    = 1000  # packets per 5 s window → DDoS alert
BRUTE_FORCE_THRESHOLD = 5     # failed logins in 60 s → brute force alert
```

> **Find your interface name:**  
> `ip a` on Linux — look for `eth0`, `ens33`, `wlan0`, `wlp2s0`, etc.  
> `ifconfig` on macOS — look for `en0`, `en1`.

---

## How to Run

Run each component in a **separate terminal**, in this order:

### Terminal 1 — Core Engine (always required)

```bash
sudo python realengine.py
```

Starts:
- Scapy packet sniffer (reads live traffic from your interface)
- Flow aggregator (batches packets into 5-second windows)
- TCP flag scan detector (SYN / FIN / XMAS / NULL / ACK)
- ARP scanner (discovers LAN devices every 60 s)
- IPS auto-blocker (adds `iptables DROP` rules for High-severity sources)
- Flask REST API on `http://0.0.0.0:5000`

### Terminal 2 — Auth Log Watcher (for brute-force detection)

```bash
sudo python logwatch.py
```

Tails `/var/log/auth.log` (Ubuntu) or `/var/log/secure` (CentOS/RHEL).  
Sends each failed SSH / PAM / FTP login to the engine's `/login_fail` endpoint.  
Once an IP accumulates 5 failures in 60 seconds, the engine raises a Brute Force alert.

> **Note:** Without `logwatch.py` running, brute-force detection is disabled
> because raw packets alone cannot tell you whether a login succeeded or failed.

### Terminal 3 — SOC Dashboard

```bash
streamlit run scandash.py
```

Open your browser at **http://localhost:8501**

Shows:
- Live alert feed with severity colour coding
- Threat timeline (alerts per minute)
- Attack type + scan type breakdown charts
- Real attacker geolocation map (Plotly + Mapbox)
- LAN device table with OS fingerprint + hostname
- Auth log event table (brute force feed)
- Admin panel: manual block/unblock, whitelist management

### Terminal 4 — Remote Sensor (optional)

Only needed if you want to capture traffic on a **different machine**
and forward flows to a central engine.

```bash
# On the sensor machine — edit ENGINE_URL in netcapture.py first
sudo python netcapture.py
```

---

## Detection Capabilities

| Attack | How detected | Severity | Auto-blocked |
|--------|-------------|----------|--------------|
| SYN Scan | TCP flags = 0x02 (half-open), ≥10 distinct ports in 5 s | High | Yes |
| FIN Scan | TCP flags = 0x01, ≥10 ports in 5 s | High | Yes |
| XMAS Scan | TCP flags = FIN+PSH+URG, ≥10 ports in 5 s | High | Yes |
| NULL Scan | TCP flags = 0x00, ≥10 ports in 5 s | High | Yes |
| ACK Scan | TCP flags = 0x10, ≥10 ports in 5 s | High | Yes |
| Port Scan (generic) | ≥10 distinct destination ports in 5 s | High | Yes |
| DDoS | ≥1000 packets from one IP in a 5 s window | High | Yes |
| Brute Force | ≥5 failed logins in 60 s (from `logwatch.py`) | High | Yes |
| Suspicious Activity | IsolationForest anomaly (AI model) | Medium | No |

---

## API Endpoints (realengine.py)

All endpoints are on `http://localhost:5000`.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/status` | Engine health, config, queue size, whitelist |
| `GET` | `/alerts?limit=200` | Recent alerts from DB |
| `GET` | `/devices` | LAN devices from latest ARP scan |
| `GET` | `/scan_types` | Scan type summary (SYN/FIN/XMAS counts) |
| `GET` | `/whitelist` | Current whitelist entries |
| `POST` | `/block_ip` | Manually block `{"ip": "1.2.3.4"}` |
| `POST` | `/unblock_ip` | Manually unblock `{"ip": "1.2.3.4"}` |
| `POST` | `/login_fail` | Record a failed login (used by `logwatch.py`) |
| `POST` | `/whitelist` | Add IP to whitelist `{"ip": "1.2.3.4"}` |
| `DELETE` | `/whitelist` | Remove IP from whitelist `{"ip": "1.2.3.4"}` |
| `POST` | `/inject` | Manual test packet injection (demo/testing only) |

---

## Database

SQLite file: `alert.db` (created automatically in the working directory)

| Table | Contents |
|-------|----------|
| `alerts` | All detected threats — timestamp, IPs, attack type, severity, risk score, lat/lon, ISP/ASN/OS JSON |
| `blocked_ips` | IPs currently blocked (auto + manual) |
| `devices` | LAN devices found by ARP scan — IP, MAC, hostname, OS guess |
| `login_events` | Failed login records from `logwatch.py` — source IP, service, username |

View the database directly:
```bash
sqlite3 alert.db
.tables
SELECT * FROM alerts ORDER BY id DESC LIMIT 10;
SELECT * FROM devices;
.quit
```

---

## Geolocation

Two backends — configured by `GEOIP_DB_PATH` in `realengine.py`:

### ip-api.com (default)
- Free, no API key needed
- Returns: lat, lon, country, ISP, ASN
- Rate limit: 45 requests/minute (results are cached in memory)
- Requires internet access

### MaxMind GeoLite2 (recommended for demo/production)
- Fully offline after initial download
- No rate limit
- More accurate than ip-api.com

```bash
# 1. Register for a free account at https://dev.maxmind.com
# 2. Download GeoLite2-City.mmdb
# 3. Place it anywhere, e.g. /opt/GeoLite2-City.mmdb
# 4. Set in realengine.py:
GEOIP_DB_PATH = "/opt/GeoLite2-City.mmdb"
```

---

## iptables Reference

```bash
# View all active DROP rules added by the engine
sudo iptables -L INPUT -n --line-numbers

# Remove a specific block rule by line number
sudo iptables -D INPUT <line_number>

# Clear ALL INPUT rules (use with caution)
sudo iptables -F INPUT

# Make rules survive reboots (Ubuntu)
sudo apt install iptables-persistent
sudo netfilter-persistent save
```

---

## Troubleshooting

**"Permission denied" on packet capture**
```bash
# Always run the engine and logwatch with sudo
sudo python realengine.py
sudo python logwatch.py
```

**"No module named scapy"**
```bash
pip install -r requirements.txt
# If still failing inside a venv:
sudo venv/bin/pip install -r requirements.txt
```

**Dashboard shows "Engine offline"**
- Make sure `realengine.py` is running and Flask started (`[OK] API → http://0.0.0.0:5000`)
- Check that port 5000 is not blocked by a local firewall

**No devices appearing in the device tab**
- Engine must be running as root for ARP scan to work
- Check `LAN_SUBNET` matches your actual network (e.g. `10.0.0.0/24` not `192.168.1.0/24`)

**Geo map shows all pins at 0,0**
- ip-api.com may be rate-limited — wait 1 minute and refresh
- Private/LAN IPs always map to your local coordinates (this is correct)
- Consider switching to MaxMind offline DB

**logwatch.py says "No auth log found"**
```bash
# Ubuntu — enable logging if missing
sudo apt install rsyslog
sudo systemctl start rsyslog

# Check which log file exists on your system
ls /var/log/auth.log /var/log/secure 2>/dev/null
```

**iptables blocking not working**
- Check `IPTABLES_ENABLED: true` in the `/status` endpoint
- If false, the engine is not running as root — restart with `sudo`

---

## Graduation Demo Tips

1. Run everything on a Linux VM or laptop connected to your university network
2. Use MaxMind GeoLite2 so geolocation works without internet dependency
3. Open a second terminal and run `nmap -sS <your_machine_ip>` from another machine to trigger a live SYN scan alert during the demo
4. Use `ssh root@<your_machine_ip>` with wrong passwords repeatedly to trigger a brute-force alert via `logwatch.py`
5. The `/status` endpoint makes a good "system health" slide — `curl http://localhost:5000/status | python3 -m json.tool`
