# file: sniffer.py
import argparse
from datetime import datetime
from scapy.all import sniff, PcapWriter, get_if_list
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Raw

def list_ifaces():
    print("Available interfaces:")
    for i, iface in enumerate(get_if_list()):
        print(f"  [{i}] {iface}")

def pkt_pretty_line(pkt):
    ts = datetime.fromtimestamp(pkt.time).strftime("%Y-%m-%d %H:%M:%S")
    src = dst = "-"
    if IP in pkt:
        src, dst = pkt[IP].src, pkt[IP].dst
    elif IPv6 in pkt:
        src, dst = pkt[IPv6].src, pkt[IPv6].dst

    proto = pkt.payload.name
    extra = ""
    if TCP in pkt:
        proto = "TCP"
        extra = f"{pkt[TCP].sport}->{pkt[TCP].dport} flags={pkt[TCP].flags}"
    elif UDP in pkt:
        proto = "UDP"
        extra = f"{pkt[UDP].sport}->{pkt[UDP].dport}"
    # Nice touch: show DNS queries
    if pkt.haslayer(DNS) and pkt[DNS].qd and pkt[DNS].qr == 0 and isinstance(pkt[DNS].qd, DNSQR):
        extra += f" DNS? {pkt[DNS].qd.qname.decode(errors='ignore').rstrip('.')}"

    # (Optional) peek at raw payload (truncate to avoid spam)
    if Raw in pkt:
        raw = bytes(pkt[Raw])[:24]
        extra += f" raw={raw!r}"

    length = len(pkt)
    return f"{ts} {src} -> {dst} [{proto}] {extra} len={length}"

def make_handler(writer):
    def handle(pkt):
        print(pkt_pretty_line(pkt))
        if writer:
            writer.write(pkt)
    return handle

def main():
    ap = argparse.ArgumentParser(description="Simple Python packet sniffer (Scapy)")
    ap.add_argument("-i", "--iface", help="Interface to sniff on (name). Use --list to see options.")
    ap.add_argument("-f", "--filter", default="ip or ip6", help="BPF filter (e.g., 'tcp', 'port 53', 'host 1.1.1.1')")
    ap.add_argument("-c", "--count", type=int, default=0, help="Stop after N packets (0 = infinite)")
    ap.add_argument("-o", "--out", help="Write capture to a .pcap file as packets arrive")
    ap.add_argument("--list", action="store_true", help="List interfaces and exit")
    args = ap.parse_args()

    if args.list:
        list_ifaces()
        return

    writer = PcapWriter(args.out, append=True, sync=True) if args.out else None
    try:
        sniff(
            iface=args.iface,
            filter=args.filter,
            prn=make_handler(writer),
            store=False,
            count=args.count,
        )
    except PermissionError:
        print("Permission denied. Try running as admin/sudo or install Npcap (Windows).")
    finally:
        if writer:
            writer.close()

if __name__ == "__main__":
    main()
