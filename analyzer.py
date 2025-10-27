# analyzer.py
import sqlite3
from datetime import datetime, timedelta
import time
import argparse

DB_PATH = 'nids.db'

WINDOW_SECONDS = 10
PORT_SCAN_PORT_THRESHOLD = 20
FLOOD_PKT_THRESHOLD = 200

def get_recent_packets(since_ts, db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT ts, src_ip, dst_port FROM packets WHERE ts >= ?", (since_ts,))
    rows = c.fetchall()
    conn.close()
    return rows

def log_alert(alert_type, description, related_src_ip, db_path=DB_PATH):
    ts = datetime.utcnow().isoformat()
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("INSERT INTO alerts (ts, alert_type, description, related_src_ip) VALUES (?, ?, ?, ?)",
              (ts, alert_type, description, related_src_ip))
    conn.commit()
    conn.close()
    print(f"[ALERT {ts}] {alert_type} | {related_src_ip} | {description}")

def analyze(window_seconds=WINDOW_SECONDS):
    now = datetime.utcnow()
    since = (now - timedelta(seconds=window_seconds)).isoformat()
    rows = get_recent_packets(since)
    data = {}
    for ts, src_ip, dst_port in rows:
        if src_ip is None:
            continue
        data.setdefault(src_ip, []).append(dst_port)
    for src, ports in data.items():
        distinct_ports = len(set([p for p in ports if p is not None]))
        total_pkts = len(ports)
        if distinct_ports >= PORT_SCAN_PORT_THRESHOLD:
            desc = f"Port-scan: {distinct_ports} distinct dst ports in last {window_seconds}s"
            log_alert("PORT_SCAN", desc, src)
        elif total_pkts >= FLOOD_PKT_THRESHOLD:
            desc = f"Flooding: {total_pkts} packets in last {window_seconds}s"
            log_alert("FLOOD", desc, src)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--interval', type=int, default=5, help="seconds between checks")
    args = parser.parse_args()
    print("Starting analyzer. Press Ctrl+C to stop.")
    while True:
        try:
            analyze()
            time.sleep(args.interval)
        except KeyboardInterrupt:
            print("Stopping analyzer.")
            break
