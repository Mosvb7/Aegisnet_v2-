"""
realengine.py  —  AegisNet Core IDS/IPS Engine  (v2)
=====================================================
Run:   sudo python realengine.py

New in v2 vs v1:
  [IDS] TCP flag scan detection: SYN / FIN / XMAS / NULL / ACK scans
  [IDS] Brute force: real failed_logins fed by logwatch.py via /login_fail
  [IDS] OS fingerprinting from IP TTL + TCP window size
  [IDS] ISP + ASN enrichment from ip-api.com
  [IPS] IP whitelist — whitelisted IPs are NEVER auto-blocked
  [IPS] Block rate-limiter — prevents duplicate iptables rules
  [NET] ARP enriched with hostname (reverse DNS) + OS guess
  [DB]  New tables: devices, login_events; extra JSON column in alerts
  [API] New endpoints: /login_fail  /scan_types  /whitelist

Dependencies:
  pip install flask scapy scikit-learn pandas numpy requests geoip2
"""

import os, sys, time, socket, logging, sqlite3, threading, subprocess, json, ipaddress
from queue import Queue, Empty
from collections import defaultdict
from datetime import datetime

import numpy as np
import pandas as pd
import requests
from flask import Flask, request, jsonify
from scapy.all import sniff, IP, TCP, UDP, ARP, Ether, srp
from sklearn.ensemble import IsolationForest

# ── CONFIGURATION ────────────────────────────────────────────────────────────

SNIFF_INTERFACE       = "en0"           # active macOS interface / depend on current OS
LAN_SUBNET            = "" # local network subnet
GEOIP_DB_PATH          = "geoip_db/GeoLite2-City.mmdb"  # Local project database path
FLOW_WINDOW           = 5               # seconds per flow bucket
PORT_SCAN_THRESHOLD   = 10              # distinct ports → scan alert
PORT_SCAN_INTERVAL    = 5               # window for port scan tracker (s)
DDOS_PKT_THRESHOLD    = 1000            # packets per FLOW_WINDOW → DDoS
BRUTE_FORCE_THRESHOLD = 5              # failed logins in BRUTE_WINDOW s
BRUTE_WINDOW          = 60
BLOCK_COOLDOWN        = 60              # seconds before re-blocking same IP
API_PORT              = 5050  # was 5000

# IMPORTANT: Edit this list before running on your network.
# Any IP here will NEVER be auto-blocked by the engine.
IP_WHITELIST: set = {
    "127.0.0.1",
    "192.168.0.170",     # <- your gateway / local network IP
}
# "10.39.1.1",      # <- your gateway / local network IP
    # "10.39.1.255",    # broadcast

# ── BOOT ─────────────────────────────────────────────────────────────────────

print("=" * 58)
print("  AegisNet IDS/IPS Engine  v2  —  realengine.py")
print("=" * 58)

IPTABLES_ENABLED = (os.geteuid() == 0)
print("[OK]  iptables blocking:", "ENABLED" if IPTABLES_ENABLED
      else "DISABLED (restart with sudo)")

app = Flask(__name__)
logging.getLogger("werkzeug").setLevel(logging.ERROR)

# ── DATABASE ─────────────────────────────────────────────────────────────────

DB_PATH = "alert.db"
conn    = sqlite3.connect(DB_PATH, check_same_thread=False)
db_lock = threading.Lock()

with db_lock:
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT, source_ip TEXT, destination_ip TEXT,
        attack_type TEXT, severity TEXT, risk_score INTEGER,
        lat REAL, lon REAL,
        extra TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS blocked_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT UNIQUE, reason TEXT, timestamp TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS devices (
        ip TEXT PRIMARY KEY, mac TEXT, hostname TEXT,
        os_guess TEXT, risk_score INTEGER DEFAULT 0,
        lat REAL, lon REAL, last_seen TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS login_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT, source_ip TEXT, service TEXT, username TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS browsing_activity (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        source_ip TEXT,
        domain TEXT,
        query_type TEXT,
        dst_ip TEXT,
        dst_port INTEGER,
        protocol TEXT,
        url_hint TEXT
    )""")
    conn.commit()
print("[OK]  Database ready:", DB_PATH)

# ── WHITELIST ─────────────────────────────────────────────────────────────────

def is_whitelisted(ip_str):
    """Checks if an IP is in the whitelist or part of a whitelisted subnet."""
    try:
        ip = ipaddress.ip_address(ip_str)
        for entry in IP_WHITELIST:
            if "/" in entry:
                if ip in ipaddress.ip_network(entry, strict=False):
                    return True
            elif ip_str == entry:
                return True
    except ValueError:
        pass
    return False

# ── GEOLOCATION ───────────────────────────────────────────────────────────────

_geo_cache = {}
_geo_lock  = threading.Lock()

_maxmind = None
if GEOIP_DB_PATH and os.path.exists(GEOIP_DB_PATH):
    try:
        import geoip2.database
        _maxmind = geoip2.database.Reader(GEOIP_DB_PATH)
        print("[OK]  MaxMind GeoLite2 loaded")
    except Exception as e:
        print(f"[WARN] MaxMind: {e}")

try:
    _s = requests.get("https://ipinfo.io/json", timeout=5).json()
    SELF_LAT, SELF_LON = map(float, _s["loc"].split(","))
    print(f"[OK]  Local coords: {SELF_LAT:.4f}, {SELF_LON:.4f}")
except Exception:
    SELF_LAT, SELF_LON = 0.0, 0.0

_PRIVATE = ("10.","192.168.","172.16.","172.17.","172.18.",
            "172.19.","172.2","127.","169.254.","::1")

def _is_private(ip): return any(ip.startswith(p) for p in _PRIVATE)

def geolocate(ip: str) -> dict:
    if _is_private(ip):
        return {"lat":SELF_LAT,"lon":SELF_LON,
                "country":"LAN","isp":"Local","asn":""}
    with _geo_lock:
        if ip in _geo_cache: return _geo_cache[ip]
    r = {"lat":0.0,"lon":0.0,"country":"","isp":"","asn":""}
    if _maxmind:
        try:
            rec = _maxmind.city(ip)
            r["lat"] = float(rec.location.latitude  or 0)
            r["lon"] = float(rec.location.longitude or 0)
            r["country"] = rec.country.name or ""
        except Exception: pass
    if r["lat"] == 0.0:
        try:
            resp = requests.get(
                f"http://ip-api.com/json/{ip}?fields=status,lat,lon,country,isp,as",
                timeout=4).json()
            if resp.get("status") == "success":
                r["lat"]     = float(resp.get("lat", 0))
                r["lon"]     = float(resp.get("lon", 0))
                r["country"] = resp.get("country","")
                r["isp"]     = resp.get("isp","")
                r["asn"]     = resp.get("as","")
        except Exception: pass
    with _geo_lock: _geo_cache[ip] = r
    return r

# ── OS FINGERPRINTING ─────────────────────────────────────────────────────────

def guess_os(ttl: int, win: int) -> str:
    if ttl > 128:   base = 255
    elif ttl > 64:  base = 128
    elif ttl > 32:  base = 64
    else:           base = 32
    if base == 128:
        return "Windows" if win in (8192,65535,64240) else "Windows (generic)"
    if base == 64:
        if win in (5840,14600,29200,65495): return "Linux"
        if win in (65535,4096):             return "macOS / FreeBSD"
        return "Linux / Unix"
    if base == 255: return "Cisco / Network device"
    return "Unknown"

# ── AI MODEL ─────────────────────────────────────────────────────────────────

_model = IsolationForest(contamination=0.3, random_state=42)
_model.fit(pd.DataFrame([
    [10,5,1],[30,5,2],[20,5,1],[15,5,1],[8,5,1],
    [1200,5,1],[2000,5,1],[3000,5,30],[500,5,50],[800,5,80],
], columns=["packet_count","duration","port_count"]))
print("[OK]  IsolationForest model trained")

# ── TCP FLAG SCAN DETECTOR ───────────────────────────────────────────────────
# Inspects raw TCP flags per packet to identify:
#   SYN scan  (flag=0x02) — Nmap default half-open
#   FIN scan  (flag=0x01) — evades stateless firewalls
#   XMAS scan (flag=0x29) — FIN+PSH+URG
#   NULL scan (flag=0x00) — no flags at all
#   ACK scan  (flag=0x10) — maps firewall rules

_F_SYN,_F_ACK,_F_FIN,_F_PSH,_F_URG = 0x02,0x10,0x01,0x08,0x20

def _classify_flags(flags: int) -> str | None:
    f = flags & 0x3F
    if f == _F_SYN:                       return "SYN Scan"
    if f == _F_FIN:                       return "FIN Scan"
    if f == (_F_FIN | _F_PSH | _F_URG):  return "XMAS Scan"
    if f == 0:                            return "NULL Scan"
    if f == _F_ACK:                       return "ACK Scan"
    return None

_flag_track = defaultdict(list)   # ip -> [(scan_type, port, time), ...]
_flag_lock  = threading.Lock()

def detect_flag_scan(src_ip: str, flags: int, port: int) -> str | None:
    st = _classify_flags(flags)
    if not st: return None
    now = time.time()
    with _flag_lock:
        _flag_track[src_ip].append((st, port, now))
        _flag_track[src_ip] = [
            x for x in _flag_track[src_ip]
            if now - x[2] < PORT_SCAN_INTERVAL
        ]
        for t in {x[0] for x in _flag_track[src_ip]}:
            ports = {x[1] for x in _flag_track[src_ip] if x[0] == t}
            if len(ports) >= PORT_SCAN_THRESHOLD:
                return t
    return None

# ── PORT SCAN TRACKER (port-count fallback) ──────────────────────────────────

_scan_track = defaultdict(list)
_scan_lock  = threading.Lock()

def detect_port_scan(ip: str, port: int) -> bool:
    now = time.time()
    with _scan_lock:
        _scan_track[ip].append((port, now))
        _scan_track[ip] = [(p,t) for p,t in _scan_track[ip]
                           if now-t < PORT_SCAN_INTERVAL]
        return len({p for p,t in _scan_track[ip]}) >= PORT_SCAN_THRESHOLD

# ── BRUTE FORCE TRACKER (fed by logwatch.py → /login_fail) ──────────────────

_login_fails = defaultdict(list)
_login_lock  = threading.Lock()

def record_login_fail(ip: str, svc: str="", user: str=""):
    now = time.time()
    ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _login_lock:
        _login_fails[ip].append(now)
        _login_fails[ip] = [t for t in _login_fails[ip]
                            if now-t < BRUTE_WINDOW]
    with db_lock:
        conn.cursor().execute(
            "INSERT INTO login_events(timestamp,source_ip,service,username)"
            " VALUES(?,?,?,?)", (ts,ip,svc,user))
        conn.commit()

def get_login_fails(ip: str) -> int:
    now = time.time()
    with _login_lock:
        _login_fails[ip] = [t for t in _login_fails[ip]
                            if now-t < BRUTE_WINDOW]
        return len(_login_fails[ip])

# ── FLOW AGGREGATOR ───────────────────────────────────────────────────────────

def flow_factory():
    return {
        "count": 0, "bytes": 0, "ports": set(),
        "flags": [], "ttl": 0, "tcp_window": 0, "start": time.time()
    }

_flows = defaultdict(flow_factory)
_flow_lock  = threading.Lock()
_anal_queue = Queue()

def add_to_flow(src: str, dst: str, port: int,
                size=0, flags=0, ttl=0, win=0):
    with _flow_lock:
        e = _flows[(src,dst)]
        e["count"] = int(e["count"]) + 1
        e["bytes"] = int(e["bytes"]) + size
        if isinstance(e["ports"], set):
            e["ports"].add(port)
        if flags and isinstance(e["flags"], list):
            e["flags"].append(flags)
        if ttl  and not e.get("ttl"):        e["ttl"]        = ttl
        if win  and not e.get("tcp_window"): e["tcp_window"] = win

def flow_flusher():
    while True:
        time.sleep(FLOW_WINDOW)
        now = time.time()
        batch = []
        with _flow_lock:
            aged = [k for k,v in _flows.items()
                    if now-v["start"] >= FLOW_WINDOW]
            for k in aged:
                batch.append((k, _flows.pop(k)))
        for (src,dst), e in batch:
            _anal_queue.put({
                "source_ip":src,"destination_ip":dst,
                "packet_count":e["count"],"byte_count":e["bytes"],
                "duration":FLOW_WINDOW,"port_count":len(e["ports"]),
                "ports":list(e["ports"]),"flags":e["flags"],
                "ttl":e["ttl"],"tcp_window":e["tcp_window"],
                "dst_port":next(iter(e["ports"]),0),
            })

# ── IPTABLES ──────────────────────────────────────────────────────────────────

_block_times = {}

def iptables_block(ip: str):
    if not IPTABLES_ENABLED or is_whitelisted(ip): return
    now = time.time()
    if now - _block_times.get(ip,0) < BLOCK_COOLDOWN: return
    _block_times[ip] = now
    try:
        chk = subprocess.run(
            ["iptables","-C","INPUT","-s",ip,"-j","DROP"],
            capture_output=True)
        if chk.returncode != 0:
            subprocess.run(
                ["iptables","-A","INPUT","-s",ip,"-j","DROP"], check=True)
            print(f"[IPTABLES] DROP  {ip}")
    except Exception as e:
        print(f"[IPTABLES ERR] {e}")

def iptables_unblock(ip: str):
    if not IPTABLES_ENABLED: return
    try:
        subprocess.run(
            ["iptables","-D","INPUT","-s",ip,"-j","DROP"],
            capture_output=True)
        print(f"[IPTABLES] ALLOW {ip}")
    except Exception as e:
        print(f"[IPTABLES ERR] {e}")

# ── CORE ANALYSIS ─────────────────────────────────────────────────────────────

def analyse_flow(flow: dict):
    src        = flow.get("source_ip","")
    dst        = flow.get("destination_ip","")
    pkts       = int(flow.get("packet_count",1))
    port_count = int(flow.get("port_count",1))
    dst_port   = int(flow.get("dst_port",0))
    ports      = flow.get("ports",[dst_port])
    flags_list = flow.get("flags",[])
    ttl        = int(flow.get("ttl",0))
    tcp_win    = int(flow.get("tcp_window",0))

    if is_whitelisted(src): return

    geo      = geolocate(src)
    lat,lon  = geo["lat"], geo["lon"]
    os_guess = guess_os(ttl, tcp_win) if ttl else "Unknown"
    extra    = {"isp":geo.get("isp",""),"asn":geo.get("asn",""),
                "country":geo.get("country",""),"os_guess":os_guess}

    attack_type = None
    risk_score  = 0

    # 1. TCP flag-based scan (most specific)
    for f in flags_list:
        st = detect_flag_scan(src, f, dst_port)
        if st:
            attack_type = st
            risk_score  = 88
            extra["scan_type"] = st
            break

    # 2. Generic port-count scan fallback
    if not attack_type:
        for p in ports:
            if detect_port_scan(src, p):
                attack_type = "Port Scan"
                risk_score  = 82
                extra["scan_type"] = "port-count"
                break

    # 3. DDoS
    if not attack_type and pkts >= DDOS_PKT_THRESHOLD:
        attack_type = "DDoS"
        risk_score  = 95
        extra["pps"] = round(pkts / max(flow.get("duration",5), 1), 1)

    # 4. Brute force (auth log data from logwatch.py)
    if not attack_type:
        fails = get_login_fails(src)
        if fails >= BRUTE_FORCE_THRESHOLD:
            attack_type = "Brute Force"
            risk_score  = 90
            extra["login_fails"] = fails

    # 5. AI anomaly catch-all
    if not attack_type:
        sample = np.array([[pkts, flow.get("duration",5), port_count]])
        if _model.predict(sample)[0] == -1:
            attack_type = "Suspicious Activity"
            risk_score  = 72
        else:
            return  # Normal traffic — do not log

    severity = ("High" if risk_score >= 88
                else "Medium" if risk_score >= 70
                else "Low")

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] {src:>17}  {attack_type:<22} ({severity})"
          f"  pkts={pkts}  ports={port_count}  os={os_guess}")

    with db_lock:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO alerts
            (timestamp,source_ip,destination_ip,attack_type,
             severity,risk_score,lat,lon,extra)
            VALUES (?,?,?,?,?,?,?,?,?)
        """, (ts,src,dst,attack_type,severity,risk_score,
              lat,lon,json.dumps(extra)))
        conn.commit()

    if severity == "High":
        with db_lock:
            cur = conn.cursor()
            try:
                cur.execute(
                    "INSERT INTO blocked_ips(ip_address,reason,timestamp)"
                    " VALUES(?,?,?)", (src,attack_type,ts))
                conn.commit()
            except sqlite3.IntegrityError: pass
        iptables_block(src)

# ── WORKER ────────────────────────────────────────────────────────────────────

def worker():
    while True:
        try:
            analyse_flow(_anal_queue.get(timeout=1))
            _anal_queue.task_done()
        except Empty: continue

# ── BROWSING TRACKER ─────────────────────────────────────────────────────────
#
# Captures two signals per LAN device:
#   DNS queries  → reveals every domain name the device resolves (port 53 UDP)
#   HTTP Host    → reveals the Host header from plain-HTTP requests (port 80)
#   HTTPS SNI    → reveals the SNI hostname from TLS ClientHello (port 443)
#
# Results are stored in the browsing_activity table and served via /browsing.
# Only traffic whose SOURCE IP belongs to LAN_SUBNET is tracked so we don't
# log external→external flows that transit the machine.

from scapy.all import DNS, DNSQR, Raw

# Pre-compute network object once for membership tests
try:
    _lan_net = ipaddress.ip_network(LAN_SUBNET, strict=False)
except Exception:
    _lan_net = None

def _is_lan_ip(ip: str) -> bool:
    if _lan_net is None:
        return False
    try:
        return ipaddress.ip_address(ip) in _lan_net
    except ValueError:
        return False

def _extract_sni(payload: bytes) -> str | None:
    """Extract SNI hostname from a TLS ClientHello record (best-effort)."""
    try:
        # TLS record must start with 0x16 (handshake), version bytes, then length
        if len(payload) < 5 or payload[0] != 0x16:
            return None
        # Handshake type 0x01 = ClientHello
        if payload[5] != 0x01:
            return None
        # Walk past: record header(5) + handshake header(4) + version(2) + random(32)
        pos = 5 + 4 + 2 + 32
        if len(payload) < pos + 1:
            return None
        # Session ID length
        sid_len = payload[pos]; pos += 1 + sid_len
        if len(payload) < pos + 2:
            return None
        # Cipher suites length
        cs_len = int.from_bytes(payload[pos:pos+2], "big"); pos += 2 + cs_len
        if len(payload) < pos + 1:
            return None
        # Compression methods length
        cm_len = payload[pos]; pos += 1 + cm_len
        if len(payload) < pos + 2:
            return None
        # Extensions length
        ext_len = int.from_bytes(payload[pos:pos+2], "big"); pos += 2
        end = pos + ext_len
        while pos + 4 <= end:
            ext_type  = int.from_bytes(payload[pos:pos+2], "big")
            ext_dlen  = int.from_bytes(payload[pos+2:pos+4], "big")
            pos += 4
            if ext_type == 0:  # server_name
                # SNI list length(2) + entry type(1) + name length(2) + name
                if ext_dlen >= 5:
                    name_len = int.from_bytes(payload[pos+3:pos+5], "big")
                    return payload[pos+5:pos+5+name_len].decode("ascii", errors="replace")
            pos += ext_dlen
    except Exception:
        pass
    return None

def _extract_http_host(payload: bytes) -> str | None:
    """Extract the Host: header from a raw HTTP request."""
    try:
        text = payload.decode("utf-8", errors="replace")
        for line in text.split("\r\n"):
            if line.lower().startswith("host:"):
                return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return None

_browse_lock = threading.Lock()

def _record_browse(src_ip: str, domain: str, protocol: str,
                   query_type: str = "", dst_ip: str = "",
                   dst_port: int = 0, url_hint: str = ""):
    """Write one browsing event to the DB (called from sniffer thread)."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with db_lock:
        conn.cursor().execute(
            "INSERT INTO browsing_activity"
            "(timestamp,source_ip,domain,query_type,dst_ip,dst_port,protocol,url_hint)"
            " VALUES(?,?,?,?,?,?,?,?)",
            (ts, src_ip, domain, query_type, dst_ip, dst_port, protocol, url_hint)
        )
        conn.commit()

def browsing_sniffer():
    """
    Separate sniffer thread dedicated to browsing visibility.
    Captures DNS (udp port 53), HTTP (tcp port 80), HTTPS/TLS SNI (tcp port 443).
    """
    print("[BROWSE] Browsing tracker started")

    def handle_browse(pkt):
        if not pkt.haslayer(IP):
            return
        src = pkt[IP].src
        dst = pkt[IP].dst

        # Only track traffic originating from OUR LAN
        if not _is_lan_ip(src):
            return

        # ── DNS ──────────────────────────────────────────────────────
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            try:
                qname = pkt[DNSQR].qname
                if isinstance(qname, bytes):
                    qname = qname.decode("utf-8", errors="replace").rstrip(".")
                qtype_map = {1:"A",28:"AAAA",5:"CNAME",15:"MX",16:"TXT",33:"SRV"}
                qtype_int = int(pkt[DNSQR].qtype)
                qtype = qtype_map.get(qtype_int, str(qtype_int))
                if qname and not qname.startswith("0."):
                    _record_browse(src, qname, "DNS", query_type=qtype, dst_ip=dst)
            except Exception:
                pass
            return

        # ── HTTP / HTTPS ─────────────────────────────────────────────
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            payload = bytes(pkt[Raw].load)
            dport   = pkt[TCP].dport
            sport   = pkt[TCP].sport

            # HTTP (port 80) — extract Host header + request path
            if dport == 80:
                host = _extract_http_host(payload)
                if host:
                    url_hint = ""
                    try:
                        first_line = payload.decode("utf-8","replace").split("\r\n")[0]
                        parts = first_line.split(" ")
                        if len(parts) >= 2:
                            url_hint = parts[1][:200]
                    except Exception:
                        pass
                    _record_browse(src, host, "HTTP",
                                   dst_ip=dst, dst_port=80, url_hint=url_hint)

            # HTTPS / TLS (port 443) — extract SNI from ClientHello
            elif dport == 443:
                sni = _extract_sni(payload)
                if sni:
                    _record_browse(src, sni, "HTTPS", dst_ip=dst, dst_port=443)

    try:
        sniff(
            iface=SNIFF_INTERFACE if SNIFF_INTERFACE != "any" else None,
            filter="udp port 53 or tcp port 80 or tcp port 443",
            prn=handle_browse,
            store=False
        )
    except Exception as e:
        print(f"[BROWSE ERR] Browsing sniffer failed: {e}")


# ── PACKET SNIFFER ────────────────────────────────────────────────────────────

def packet_sniffer():
    print(f"[SNIFF] Listening on: {SNIFF_INTERFACE}")
    def handle(pkt):
        if not pkt.haslayer(IP): return
        src      = pkt[IP].src
        dst      = pkt[IP].dst
        ttl      = pkt[IP].ttl
        size     = len(pkt)
        port,flags,win = 0,0,0
        if pkt.haslayer(TCP):
            port  = pkt[TCP].dport
            flags = int(pkt[TCP].flags)
            win   = pkt[TCP].window
        elif pkt.haslayer(UDP):
            port  = pkt[UDP].dport
        add_to_flow(src, dst, port, size=size, flags=flags, ttl=ttl, win=win)

    try:
        sniff(
            iface=SNIFF_INTERFACE if SNIFF_INTERFACE != "any" else None,
            filter="ip", prn=handle, store=False
        )
    except Exception as e:
        print(f"[ERROR] Sniffer failed on interface '{SNIFF_INTERFACE}': {e}")
        print("        Try changing SNIFF_INTERFACE in realengine.py to 'any' or your active interface.")
        if os.geteuid() != 0:
            print("        NOTE: Sniffing requires root privileges. Run with: sudo python realengine.py")

# ── ARP DEVICE DISCOVERY ─────────────────────────────────────────────────────

_arp_cache = []
_arp_lock  = threading.Lock()

def _rdns(ip):
    try: return socket.gethostbyaddr(ip)[0]
    except: return ""

def arp_scan():
    while True:
        try:
            ans,_ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=LAN_SUBNET),
                        timeout=3, verbose=False)
            found = []
            for _,rcv in ans:
                ip   = rcv[ARP].psrc
                mac  = rcv[Ether].src
                geo  = geolocate(ip)
                host = _rdns(ip)
                with db_lock:
                    row = conn.cursor().execute(
                        "SELECT risk_score,extra FROM alerts"
                        " WHERE source_ip=? ORDER BY id DESC LIMIT 1",(ip,)
                    ).fetchone()
                risk = 0; os_g = "Unknown"
                if row:
                    risk = row[0]
                    try: os_g = json.loads(row[1] or "{}").get("os_guess","Unknown")
                    except: pass
                ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                dev = {"ip":ip,"mac":mac,"hostname":host,"os_guess":os_g,
                       "risk_score":risk,"lat":geo["lat"],"lon":geo["lon"],
                       "last_seen":ts}
                found.append(dev)
                with db_lock:
                    conn.cursor().execute("""
                        INSERT INTO devices
                          (ip,mac,hostname,os_guess,risk_score,lat,lon,last_seen)
                        VALUES(?,?,?,?,?,?,?,?)
                        ON CONFLICT(ip) DO UPDATE SET
                          mac=excluded.mac,hostname=excluded.hostname,
                          os_guess=excluded.os_guess,
                          risk_score=excluded.risk_score,
                          last_seen=excluded.last_seen
                    """, (ip,mac,host,os_g,risk,geo["lat"],geo["lon"],ts))
                    conn.commit()
            with _arp_lock:
                _arp_cache.clear(); _arp_cache.extend(found)
            print(f"[ARP]  {len(found)} device(s) on {LAN_SUBNET}")
        except Exception as e:
            print(f"[ARP ERR] {e}")
        time.sleep(60)

# ── FLASK API ─────────────────────────────────────────────────────────────────

@app.route("/inject", methods=["POST"])
def inject():
    d = request.json or {}
    for _ in range(int(d.get("packet_count",1))):
        add_to_flow(d.get("source_ip",""), d.get("destination_ip",""),
                    int(d.get("dst_port",0)))
    return jsonify({"status":"injected"})

@app.route("/login_fail", methods=["POST"])
def login_fail():
    d = request.json or {}
    ip = d.get("source_ip","")
    if not ip: return jsonify({"status":"error","msg":"No IP"}),400
    record_login_fail(ip, d.get("service",""), d.get("username",""))
    return jsonify({"status":"recorded","total":get_login_fails(ip)})

@app.route("/block_ip", methods=["POST"])
def block_ip():
    ip = (request.json or {}).get("ip","")
    if not ip: return jsonify({"status":"error"}),400
    if is_whitelisted(ip):
        return jsonify({"status":"error","msg":f"{ip} is whitelisted"}),403
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with db_lock:
        try:
            conn.cursor().execute(
                "INSERT INTO blocked_ips(ip_address,reason,timestamp)"
                " VALUES(?,?,?)", (ip,"Manual Block",ts))
            conn.commit()
        except sqlite3.IntegrityError: pass
    iptables_block(ip)
    return jsonify({"status":"blocked","ip":ip})

@app.route("/unblock_ip", methods=["POST"])
def unblock_ip():
    ip = (request.json or {}).get("ip","")
    if not ip: return jsonify({"status":"error"}),400
    with db_lock:
        conn.cursor().execute(
            "DELETE FROM blocked_ips WHERE ip_address=?",(ip,))
        conn.commit()
    iptables_unblock(ip)
    return jsonify({"status":"unblocked","ip":ip})

@app.route("/browsing", methods=["GET"])
def browsing():
    """
    Returns recent browsing activity.
    Query params:
      ip     — filter to a specific source IP
      limit  — max rows (default 300)
      since  — ISO timestamp, return only rows after this time
    """
    ip    = request.args.get("ip","")
    lim   = int(request.args.get("limit", 300))
    since = request.args.get("since","")
    with db_lock:
        cur = conn.cursor()
        if ip and since:
            cur.execute(
                "SELECT * FROM browsing_activity"
                " WHERE source_ip=? AND timestamp>?"
                " ORDER BY id DESC LIMIT ?", (ip, since, lim))
        elif ip:
            cur.execute(
                "SELECT * FROM browsing_activity WHERE source_ip=?"
                " ORDER BY id DESC LIMIT ?", (ip, lim))
        elif since:
            cur.execute(
                "SELECT * FROM browsing_activity WHERE timestamp>?"
                " ORDER BY id DESC LIMIT ?", (since, lim))
        else:
            cur.execute(
                "SELECT * FROM browsing_activity ORDER BY id DESC LIMIT ?", (lim,))
        cols = [d[0] for d in cur.description]
        return jsonify([dict(zip(cols, r)) for r in cur.fetchall()])

@app.route("/devices_live", methods=["GET"])
def devices_live():
    """
    Returns each LAN device enriched with their last 10 browsed domains
    and a visit count, so the dashboard can show browsing activity per device.
    """
    with _arp_lock:
        devs = list(_arp_cache)
    with db_lock:
        cur = conn.cursor()
        for dev in devs:
            ip = dev["ip"]
            cur.execute(
                "SELECT domain, protocol, COUNT(*) as visits,"
                " MAX(timestamp) as last_visit"
                " FROM browsing_activity WHERE source_ip=?"
                " GROUP BY domain ORDER BY visits DESC LIMIT 10", (ip,))
            rows = cur.fetchall()
            dev["top_domains"] = [
                {"domain": r[0], "protocol": r[1],
                 "visits": r[2], "last_visit": r[3]}
                for r in rows
            ]
            cur.execute(
                "SELECT COUNT(*) FROM browsing_activity WHERE source_ip=?", (ip,))
            dev["total_requests"] = (cur.fetchone() or [0])[0]
    return jsonify(devs)



@app.route("/devices", methods=["GET"])
def devices():
    with _arp_lock: return jsonify(list(_arp_cache))


def alerts():
    lim = int(request.args.get("limit",200))
    with db_lock:
        cur = conn.cursor()
        cur.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (lim,))
        cols = [d[0] for d in cur.description]
        return jsonify([dict(zip(cols,r)) for r in cur.fetchall()])

@app.route("/scan_types", methods=["GET"])
def scan_types():
    with db_lock:
        cur = conn.cursor()
        cur.execute("""
            SELECT source_ip,attack_type,COUNT(*) hits,MAX(timestamp) last_seen
            FROM alerts WHERE attack_type LIKE '%Scan%'
            GROUP BY source_ip,attack_type ORDER BY hits DESC LIMIT 50
        """)
        cols = [d[0] for d in cur.description]
        return jsonify([dict(zip(cols,r)) for r in cur.fetchall()])

@app.route("/whitelist", methods=["GET","POST","DELETE"])
def whitelist():
    if request.method == "GET":
        return jsonify(sorted(IP_WHITELIST))
    ip = (request.json or {}).get("ip","")
    if not ip: return jsonify({"status":"error"}),400
    if request.method == "POST":
        IP_WHITELIST.add(ip)
        return jsonify({"status":"added","ip":ip})
    IP_WHITELIST.discard(ip)
    return jsonify({"status":"removed","ip":ip})

@app.route("/status", methods=["GET"])
def status():
    return jsonify({
        "engine":"realengine.py v2","iptables":IPTABLES_ENABLED,
        "interface":SNIFF_INTERFACE,"subnet":LAN_SUBNET,
        "flow_window":FLOW_WINDOW,"geo_backend":"MaxMind" if _maxmind else "ip-api.com",
        "queue_size":_anal_queue.qsize(),"cached_ips":len(_geo_cache),
        "arp_devices":len(_arp_cache),"whitelist":sorted(IP_WHITELIST),
    })

# ── MAIN ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    try:
        threading.Thread(target=worker,           daemon=True,name="worker").start()
        threading.Thread(target=flow_flusher,     daemon=True,name="flusher").start()
        threading.Thread(target=packet_sniffer,   daemon=True,name="sniffer").start()
        threading.Thread(target=browsing_sniffer, daemon=True,name="browse").start()
        if IPTABLES_ENABLED:
            threading.Thread(target=arp_scan,   daemon=True,name="arp").start()
        else:
            print("[ARP]  Skipped (not root)")
        threading.Thread(
            target=lambda: app.run(
                host="0.0.0.0",port=API_PORT,debug=False,use_reloader=False),
            daemon=True,name="flask").start()
        print(f"[OK]  API → http://0.0.0.0:{API_PORT}")
        print("[OK]  All threads running. Ctrl+C to stop.\n")
        while True: time.sleep(1)
    except KeyboardInterrupt:
        print("\n[SHUTDOWN] AegisNet stopped.")
        conn.close(); sys.exit(0)
    except Exception as ex:
        print(f"\n[CRITICAL] {ex}")
        conn.close(); sys.exit(1)





#MAXIDMINDPASS: Fearless##8882
#update geoipupdate -f GeoIP.conf before run the files to update the db 
