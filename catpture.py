
import sqlite3
from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
import argparse

DB_PATH = 'nids.db'

def init_db(db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS packets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT,
                    src_ip TEXT,
                    src_port INTEGER,
                    dst_ip TEXT,
                    dst_port INTEGER,
                    protocol TEXT,
                    length INTEGER,
                    flags TEXT
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT,
                    alert_type TEXT,
                    description TEXT,
                    related_src_ip TEXT
                )''')
    conn.commit()
    conn.close()

def packet_to_row(pkt):
    ts = datetime.utcnow().isoformat()
    src_ip = None; dst_ip = None; proto = None; length = None; src_port = None; dst_port = None; flags = None
    if IP in pkt:
        ip = pkt[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        length = len(pkt)
    if TCP in pkt:
        tcp = pkt[TCP]
        src_port = tcp.sport
        dst_port = tcp.dport
        flags = str(tcp.flags)
        proto = 'TCP'
    elif UDP in pkt:
        udp = pkt[UDP]
        src_port = udp.sport
        dst_port = udp.dport
        proto = 'UDP'
    else:
        proto = proto or 'OTHER'
    return (ts, src_ip, src_port, dst_ip, dst_port, proto, length, flags)

def insert_packet(row, db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('''INSERT INTO packets (ts, src_ip, src_port, dst_ip, dst_port, protocol, length, flags)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)''', row)
    conn.commit()
    conn.close()

def on_packet(pkt):
    row = packet_to_row(pkt)
    if row[1] is None:
        return
    insert_packet(row)
    print(f"[{row[0]}] {row[1]}:{row[2]} -> {row[3]}:{row[4]} proto={row[5]} len={row[6]} flags={row[7]}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Live packet capture to sqlite")
    parser.add_argument('--iface', help="Interface to sniff (optional)", default=None)
    args = parser.parse_args()
    init_db()
    print("DB initialized (nids.db). To capture live packets run with Admin privileges.")
    # If user runs without admin or without Npcap, sniff will fail. For db init this is enough.
    try:
        sniff(prn=on_packet, store=False, iface=args.iface)
    except Exception as e:
        print("Live capture not started (likely no Npcap/Admin). You can use pcap_replay.py to populate the DB.")
        # ignore error — DB is created
