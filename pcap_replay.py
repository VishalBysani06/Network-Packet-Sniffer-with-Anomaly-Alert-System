# pcap_replay.py
import sqlite3
from scapy.all import rdpcap, IP, TCP, UDP
from datetime import datetime
import argparse

DB_PATH = 'nids.db'

def insert_packet(db_path, ts, src_ip, src_port, dst_ip, dst_port, proto, length, flags):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('''INSERT INTO packets (ts, src_ip, src_port, dst_ip, dst_port, protocol, length, flags)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
              (ts, src_ip, src_port, dst_ip, dst_port, proto, length, flags))
    conn.commit()
    conn.close()

def pkt_to_row(pkt):
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
    return ts, src_ip, src_port, dst_ip, dst_port, proto, length, flags

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('pcap', help="pcap file to replay")
    args = parser.parse_args()
    packets = rdpcap(args.pcap)
    count = 0
    for pkt in packets:
        row = pkt_to_row(pkt)
        if row[1] is None: continue
        insert_packet(DB_PATH, *row)
        count += 1
    print(f"Replayed {count} packets into {DB_PATH}")
