"""
scandash.py  —  AegisNet SOC Dashboard  (v2)
============================================
Run:   streamlit run scandash.py

New in v2:
  - Scan type breakdown panel (SYN/FIN/XMAS/NULL/ACK)
  - OS fingerprint column in device table
  - ISP + ASN columns in alert table (from extra JSON)
  - Login events tab (brute force feed from logwatch.py)
  - Whitelist management panel
  - Engine status shows whitelist entries

Dependencies:
  pip install streamlit streamlit-autorefresh streamlit-folium plotly folium requests pandas
"""

import json
import sqlite3

import folium
import pandas as pd
import plotly.express as px
import requests
import streamlit as st
from streamlit_autorefresh import st_autorefresh
from streamlit_folium import st_folium

# ── CONFIG ────────────────────────────────────────────────────────────────────

ENGINE  = "http://127.0.0.1:5000"
DB_PATH = "alert.db"

st.set_page_config(page_title="AegisNet SOC", page_icon="🛡️", layout="wide")
st_autorefresh(interval=5000, key="ar")

# ── DATA HELPERS ──────────────────────────────────────────────────────────────

def load_alerts() -> pd.DataFrame:
    try:
        con = sqlite3.connect(DB_PATH)
        df  = pd.read_sql_query(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT 500", con)
        con.close()
        # Expand the extra JSON column into readable columns
        if "extra" in df.columns:
            def _expand(v):
                try: return json.loads(v or "{}")
                except: return {}
            extra = df["extra"].apply(_expand).apply(pd.Series)
            for col in ["isp","asn","country","os_guess","scan_type","pps","login_fails"]:
                if col in extra.columns:
                    df[col] = extra[col]
        return df
    except Exception as e:
        st.error(f"DB error: {e}")
        return pd.DataFrame()

def load_blocked() -> pd.DataFrame:
    try:
        con = sqlite3.connect(DB_PATH)
        df  = pd.read_sql_query(
            "SELECT * FROM blocked_ips ORDER BY id DESC", con)
        con.close()
        return df
    except Exception as e:
        st.error(f"DB error: {e}")
        return pd.DataFrame()

def load_login_events() -> pd.DataFrame:
    try:
        con = sqlite3.connect(DB_PATH)
        df  = pd.read_sql_query(
            "SELECT * FROM login_events ORDER BY id DESC LIMIT 200", con)
        con.close()
        return df
    except Exception as e:
        return pd.DataFrame()

def eng(path: str, **kw):
    try:
        return requests.get(f"{ENGINE}{path}", timeout=3, **kw).json()
    except Exception:
        return {}

def eng_post(path: str, payload: dict):
    try:
        return requests.post(f"{ENGINE}{path}", json=payload, timeout=3).json()
    except Exception:
        return {}

# ── SEVERITY COLOUR ───────────────────────────────────────────────────────────

_SEV_COLOR = {
    "High":   "background-color:#7a1c1c;color:#ffd6d6",
    "Medium": "background-color:#5a3a00;color:#ffe4a0",
    "Low":    "background-color:#1a3a1a;color:#c6f0c6",
}
def colour_row(row):
    s = _SEV_COLOR.get(row.get("severity",""),"")
    return [s]*len(row)

# ── HEADER ────────────────────────────────────────────────────────────────────

st.markdown(
    "<h1 style='margin-bottom:0'>🛡️ AegisNet SOC Dashboard</h1>"
    "<p style='color:gray;margin-top:2px'>Real-time IDS/IPS  —  scandash.py v2</p>",
    unsafe_allow_html=True
)

status = eng("/status")
if status:
    iptables = "ON" if status.get("iptables") else "OFF (no root)"
    wl_count = len(status.get("whitelist",[]))
    st.success(
        f"Engine online  |  Interface: `{status.get('interface','?')}`  |  "
        f"Geo: `{status.get('geo_backend','?')}`  |  iptables: `{iptables}`  |  "
        f"Queue: `{status.get('queue_size',0)}`  |  "
        f"Devices: `{status.get('arp_devices',0)}`  |  "
        f"Whitelist: `{wl_count}` entries"
    )
else:
    st.error("Engine offline — start realengine.py first.")

# ── LOAD DATA ─────────────────────────────────────────────────────────────────

alerts_df     = load_alerts()
blocked_df    = load_blocked()
login_df      = load_login_events()
devices_raw   = eng("/devices") or []
devices_df    = pd.DataFrame(devices_raw) if devices_raw else pd.DataFrame()

# ── METRICS ───────────────────────────────────────────────────────────────────

st.subheader("📊 Live Summary")
c1,c2,c3,c4,c5 = st.columns(5)
if not alerts_df.empty:
    c1.metric("🚨 High",   len(alerts_df[alerts_df["severity"]=="High"]))
    c2.metric("⚠️ Medium", len(alerts_df[alerts_df["severity"]=="Medium"]))
    c3.metric("✅ Low",    len(alerts_df[alerts_df["severity"]=="Low"]))
else:
    c1.metric("🚨 High",0); c2.metric("⚠️ Medium",0); c3.metric("✅ Low",0)
c4.metric("🚫 Blocked IPs", len(blocked_df))
c5.metric("🖥️ LAN Devices",  len(devices_df))

# ── TABS ──────────────────────────────────────────────────────────────────────

t1,t2,t3,t4,t5 = st.tabs([
    "🚨 Alerts", "🌍 Geo Map", "🖥️ Devices", "🔐 Auth Logs", "🛠️ Admin"
])

# ── TAB 1: ALERTS ────────────────────────────────────────────────────────────

with t1:
    st.subheader("📈 Threat Timeline (alerts per minute)")
    if not alerts_df.empty and "timestamp" in alerts_df.columns:
        try:
            ts_df = alerts_df.copy()
            ts_df["timestamp"] = pd.to_datetime(ts_df["timestamp"])
            counts = (ts_df.set_index("timestamp")
                          .sort_index()
                          .resample("1min")["id"].count()
                          .reset_index())
            counts.columns = ["time","alerts"]
            st.line_chart(counts.set_index("time")["alerts"])
        except Exception:
            st.info("Not enough data yet.")

    col_a, col_b = st.columns(2)

    with col_a:
        st.subheader("⚔️ Attack Type Breakdown")
        if not alerts_df.empty:
            tc = alerts_df["attack_type"].value_counts()
            st.plotly_chart(
                px.pie(values=tc.values, names=tc.index,
                       color_discrete_sequence=px.colors.sequential.RdBu),
                use_container_width=True
            )

    with col_b:
        st.subheader("🔍 Scan Type Breakdown")
        scan_data = eng("/scan_types")
        if scan_data:
            sdf = pd.DataFrame(scan_data)
            if "attack_type" in sdf.columns and "hits" in sdf.columns:
                sc = sdf.groupby("attack_type")["hits"].sum()
                st.bar_chart(sc)
        else:
            if not alerts_df.empty and "attack_type" in alerts_df.columns:
                scans = alerts_df[alerts_df["attack_type"].str.contains(
                    "Scan", na=False)]
                if not scans.empty:
                    st.bar_chart(
                        scans.groupby("attack_type").size()
                        .sort_values(ascending=False)
                    )
                else:
                    st.info("No scan activity yet.")

    st.subheader("💻 Top Attacker IPs")
    if not alerts_df.empty:
        top = (alerts_df.groupby("source_ip").size()
                        .sort_values(ascending=False).head(10))
        st.bar_chart(top)

    st.subheader("📋 Alert Log")
    if alerts_df.empty:
        st.info("No alerts yet.")
    else:
        show_cols = [c for c in
            ["timestamp","source_ip","destination_ip","attack_type",
             "severity","risk_score","country","isp","asn",
             "os_guess","scan_type","lat","lon"]
            if c in alerts_df.columns]
        st.dataframe(
            alerts_df[show_cols].style.apply(colour_row, axis=1),
            use_container_width=True
        )

# ── TAB 2: GEO MAP ───────────────────────────────────────────────────────────

with t2:
    st.subheader("🌍 Real Attacker Geolocation Map")
    if not alerts_df.empty and "lat" in alerts_df.columns:
        geo_df = alerts_df.dropna(subset=["lat","lon"])
        geo_df = geo_df[(geo_df["lat"]!=0)|(geo_df["lon"]!=0)]
        if not geo_df.empty:
            hover = [c for c in ["attack_type","risk_score","timestamp",
                                  "isp","country","os_guess"]
                     if c in geo_df.columns]
            fig = px.scatter_mapbox(
                geo_df, lat="lat", lon="lon",
                color="severity", size="risk_score", size_max=18,
                hover_name="source_ip", hover_data=hover,
                color_discrete_map={"High":"red","Medium":"orange","Low":"green"},
                zoom=1, mapbox_style="carto-positron"
            )
            fig.update_layout(margin={"r":0,"t":0,"l":0,"b":0}, height=500)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("All IPs resolved to 0,0 — geolocation may be warming up.")
    else:
        st.info("No geo data yet.")

# ── TAB 3: DEVICES ───────────────────────────────────────────────────────────

with t3:
    st.subheader("🖥️ LAN Devices (ARP + OS Fingerprint)")
    if devices_df.empty:
        st.info("No devices found. Run realengine.py as root for ARP scan.")
    else:
        st.dataframe(devices_df, use_container_width=True)

        if "ip" in devices_df.columns and "risk_score" in devices_df.columns:
            st.subheader("⚠️ Device Risk Levels")
            st.bar_chart(devices_df.set_index("ip")["risk_score"])

        st.subheader("🗺️ Device Map")
        m = folium.Map(location=[20,0], zoom_start=2)
        for dev in devices_raw:
            lat  = dev.get("lat",0)
            lon  = dev.get("lon",0)
            risk = dev.get("risk_score",0)
            col  = "red" if risk>=70 else ("orange" if risk>=40 else "green")
            folium.CircleMarker(
                location=[lat,lon], radius=8,
                color=col, fill=True, fill_color=col,
                popup=(
                    f"IP: {dev.get('ip','?')}<br>"
                    f"MAC: {dev.get('mac','?')}<br>"
                    f"Host: {dev.get('hostname','?')}<br>"
                    f"OS: {dev.get('os_guess','?')}<br>"
                    f"Risk: {risk}"
                )
            ).add_to(m)
        st_folium(m, width=700, height=400)

# ── TAB 4: AUTH LOGS ─────────────────────────────────────────────────────────

with t4:
    st.subheader("🔐 Login Failure Events (from logwatch.py)")
    if login_df.empty:
        st.info(
            "No login events yet.\n\n"
            "Make sure logwatch.py is running:  `sudo python logwatch.py`"
        )
    else:
        st.caption(f"Last {len(login_df)} events (most recent first)")
        st.dataframe(login_df, use_container_width=True)

        st.subheader("🔑 Top Brute Force Sources")
        top_bf = (login_df.groupby("source_ip").size()
                          .sort_values(ascending=False).head(10))
        st.bar_chart(top_bf)

        if "service" in login_df.columns:
            st.subheader("🔌 Targeted Services")
            svc = login_df["service"].value_counts()
            st.bar_chart(svc)

# ── TAB 5: ADMIN ─────────────────────────────────────────────────────────────

with t5:
    st.subheader("🛠️ Manual IP Control")
    col_l, col_r = st.columns(2)

    with col_l:
        st.markdown("**Block an IP**")
        ip_b = st.text_input("IP to block", key="blk")
        if st.button("🚫 Block"):
            if ip_b:
                res = eng_post("/block_ip",{"ip":ip_b})
                if res.get("status")=="blocked":
                    st.success(f"Blocked {ip_b}")
                else:
                    st.error(res.get("msg","Error"))

    with col_r:
        st.markdown("**Unblock an IP**")
        ip_u = st.text_input("IP to unblock", key="ublk")
        if st.button("✅ Unblock"):
            if ip_u:
                res = eng_post("/unblock_ip",{"ip":ip_u})
                st.success(f"Unblocked {ip_u}") if res.get("status")=="unblocked" \
                    else st.error("Error")

    st.divider()
    st.subheader("🟢 IP Whitelist")
    st.caption("IPs on this list are never auto-blocked by the engine.")

    wl_data = eng("/whitelist")
    if isinstance(wl_data, list) and wl_data:
        wl_df = pd.DataFrame({"whitelisted_ip": wl_data})
        st.dataframe(wl_df, use_container_width=True)

    col_wa, col_wr = st.columns(2)
    with col_wa:
        wl_add = st.text_input("Add to whitelist", key="wla")
        if st.button("Add"):
            if wl_add:
                r = eng_post("/whitelist",{"ip":wl_add})
                st.success(f"Added {wl_add}") if r.get("status")=="added" \
                    else st.error("Error")
    with col_wr:
        wl_rm = st.text_input("Remove from whitelist", key="wlr")
        if st.button("Remove"):
            if wl_rm:
                try:
                    r = requests.delete(
                        f"{ENGINE}/whitelist",
                        json={"ip":wl_rm}, timeout=3).json()
                    st.success(f"Removed {wl_rm}") if r.get("status")=="removed" \
                        else st.error("Error")
                except Exception:
                    st.error("Engine unreachable")

    st.divider()
    st.subheader("🚫 Blocked IPs Table")
    if blocked_df.empty:
        st.success("No IPs currently blocked.")
    else:
        st.dataframe(blocked_df, use_container_width=True)

    st.divider()
    st.subheader("🔧 Engine Status (raw)")
    if status:
        st.json(status)
    else:
        st.warning("Engine offline.")
