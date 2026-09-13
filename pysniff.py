#!/usr/bin/env python3
"""
pySniff - Advanced Network Packet Sniffer
Author: Ahmad
License: MIT
GitHub: https://github.com/Ahmiiii250/CodeAlpha_Basic-Network-Sniffer.git
"""

import argparse
import sys
import signal
import time
from datetime import datetime
from collections import Counter

try:
    from scapy.all import (
        sniff, IP, TCP, UDP, ICMP, DNS, Raw, wrpcap, conf, get_if_list
    )
except ImportError:
    print("[!] Scapy na lari. Run kawal: pip install scapy")
    sys.exit(1)


class PySniff:
    def __init__(self, iface, bpf_filter, count, timeout, verbose, output):
        self.iface = iface
        self.bpf_filter = bpf_filter
        self.count = count
        self.timeout = timeout
        self.verbose = verbose
        self.output = output
        self.captured_packets = []
        self.stats = Counter()
        self.credentials = []
        self.start_time = None

    # ---------------- Credential Detection ----------------
    def check_credentials(self, payload, src, dst, dport):
        """HTTP ya plain-text protocols la credentials detect kawal"""
        keywords = [b"user", b"pass", b"login", b"email", b"pwd",
                    b"auth", b"USER", b"PASS"]
        found = []
        for kw in keywords:
            if kw in payload.lower() or kw in payload:
                found.append(kw.decode())
        if found:
            cred = {
                "time": datetime.now().strftime("%H:%M:%S"),
                "src": src,
                "dst": f"{dst}:{dport}",
                "keywords": ", ".join(set(found)),
                "data": payload[:300].decode("utf-8", errors="replace")
            }
            self.credentials.append(cred)
            print(f"\n[***] POTENTIAL CREDENTIAL DETECTED [***]")
            print(f"    Time    : {cred['time']}")
            print(f"    Flow    : {cred['src']} -> {cred['dst']}")
            print(f"    Match   : {cred['keywords']}")
            print(f"    Data    : {cred['data'][:200]}")
            print(f"[***]{'*' * 40}\n")

    # ---------------- Packet Callback ----------------
    def packet_callback(self, packet):
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        if not packet.haslayer(IP):
            self.stats["Other"] += 1
            if self.verbose:
                print(f"[{timestamp}] Non-IP packet: {packet.summary()}")
            return

        src = packet[IP].src
        dst = packet[IP].dst
        size = len(packet)

        if packet.haslayer(TCP):
            proto = "TCP"
            sport, dport = packet[TCP].sport, packet[TCP].dport
            flags = str(packet[TCP].flags)
            self.stats["TCP"] += 1
        elif packet.haslayer(UDP):
            proto = "UDP"
            sport, dport = packet[UDP].sport, packet[UDP].dport
            flags = ""
            self.stats["UDP"] += 1
        elif packet.haslayer(ICMP):
            proto = "ICMP"
            sport, dport = "-", "-"
            flags = f"type={packet[ICMP].type}"
            self.stats["ICMP"] += 1
        else:
            proto = str(packet[IP].proto)
            sport, dport = "-", "-"
            flags = ""
            self.stats["Other"] += 1

        self.stats["Total"] += 1
        print(f"[{timestamp}] {src}:{sport} -> {dst}:{dport} "
              f"[{proto}] {flags} ({size} bytes)")

        # DNS query display
        if packet.haslayer(DNS) and packet[DNS].qr == 0:
            try:
                qname = packet[DNS].qd.qname.decode(errors="replace").rstrip(".")
                print(f"    DNS Query: {qname}")
            except Exception:
                pass

        # Payload analysis
        if packet.haslayer(Raw):
            payload = bytes(packet[Raw].load)
            self.check_credentials(payload, f"{src}:{sport}", dst, dport)
            if self.verbose:
                try:
                    text = payload.decode("utf-8", errors="replace")
                    for line in text.split("\n")[:5]:
                        print(f"    | {line}")
                except Exception:
                    print(f"    | {payload[:100].hex()}")

        print("-" * 70)

        if self.output:
            self.captured_packets.append(packet)

    # ---------------- Statistics ----------------
    def print_stats(self):
        elapsed = time.time() - self.start_time if self.start_time else 0
        print("\n" + "=" * 50)
        print("            CAPTURE SUMMARY")
        print("=" * 50)
        print(f"  Duration      : {elapsed:.1f} seconds")
        print(f"  Total Packets : {self.stats['Total']}")
        print(f"  TCP           : {self.stats['TCP']}")
        print(f"  UDP           : {self.stats['UDP']}")
        print(f"  ICMP          : {self.stats['ICMP']}")
        print(f"  Other         : {self.stats['Other']}")
        print(f"  Credentials   : {len(self.credentials)} found")
        if self.output:
            print(f"  PCAP File     : {self.output}")
        print("=" * 50 + "\n")

    # ---------------- Main Loop ----------------
    def run(self):
        self.start_time = time.time()
        print(f"[*] pySniff starting...")
        print(f"[*] Interface : {self.iface or 'default'}")
        print(f"[*] Filter    : {self.bpf_filter}")
        print(f"[*] Count     : {self.count or 'unlimited'}")
        print(f"[*] Output    : {self.output or 'none'}")
        print("[*] Press Ctrl+C to stop\n")

        kwargs = {
            "iface": self.iface,
            "filter": self.bpf_filter,
            "prn": self.packet_callback,
            "store": False,
        }
        if self.count:
            kwargs["count"] = self.count
        if self.timeout:
            kwargs["timeout"] = self.timeout

        try:
            sniff(**kwargs)
        except KeyboardInterrupt:
            pass
        except PermissionError:
            print("\n[!] Root privileges required: sudo python3 pysniff.py ...")
            sys.exit(1)
        except Exception as e:
            print(f"\n[!] Error: {e}")
            sys.exit(1)
        finally:
            if self.output and self.captured_packets:
                try:
                    wrpcap(self.output, self.captured_packets)
                    print(f"[*] {len(self.captured_packets)} packets saved to '{self.output}'")
                except Exception as e:
                    print(f"[!] Could not save pcap: {e}")
            self.print_stats()


def banner():
    print(r"""
  ██████╗ ██╗   ██╗███████╗███╗   ██╗██╗███████╗███████╗
  ██╔══██╗╚██╗ ██╔╝██╔════╝████╗  ██║██║██╔════╝██╔════╝
  ██████╔╝ ╚████╔╝ ███████╗██╔██╗ ██║██║███████╗█████╗
  ██╔═══╝   ╚██╔╝  ╚════██║██║╚██╗██║██║╚════██║██╔══╝
  ██║        ██║   ███████║██║ ╚████║██║███████║███████╗
  ╚═╝        ╚═╝   ╚══════╝╚═╝  ╚═══╝╚═╝╚══════╝╚══════╝
        Network Packet Sniffer v1.0
""")


def list_interfaces():
    print("\n[*] Available interfaces:")
    for i, iface in enumerate(get_if_list(), 1):
        print(f"    {i}. {iface}")
    print()


def main():
    banner()

    parser = argparse.ArgumentParser(
        description="pySniff - Network Packet Sniffer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 pysniff.py -i eth0
  sudo python3 pysniff.py -f "tcp port 80"
  sudo python3 pysniff.py -f "udp port 53" -v
  sudo python3 pysniff.py -c 100 -w capture.pcap
  python3 pysniff.py --list-interfaces
""")
    parser.add_argument("-i", "--iface", default=None, help="Interface (default: auto-detect)")
    parser.add_argument("-f", "--filter", default="ip", help="BPF filter (default: 'ip')")
    parser.add_argument("-c", "--count", type=int, default=0, help="Packets to capture (0 = unlimited)")
    parser.add_argument("-t", "--timeout", type=int, default=None, help="Stop after N seconds")
    parser.add_argument("-w", "--write", default=None, help="Save to pcap file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show payload data")
    parser.add_argument("--list-interfaces", action="store_true", help="List network interfaces")

    args = parser.parse_args()

    if args.list_interfaces:
        list_interfaces()
        sys.exit(0)

    sniffer = PySniff(
        iface=args.iface,
        bpf_filter=args.filter,
        count=args.count,
        timeout=args.timeout,
        verbose=args.verbose,
        output=args.write,
    )
    sniffer.run()


if __name__ == "__main__":
    main()
