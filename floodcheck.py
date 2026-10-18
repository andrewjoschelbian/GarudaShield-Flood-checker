#!/usr/bin/env python3
"""
GarudaShield Flood-check — deteksi apakah sebuah IP terkena flood/DDoS.
Pembuat: @andrewjoschelbian

Mode:
  monitor  — sniff trafik lokal (Linux, butuh root). Deteksi flood ke IP ini.
  probe    — cek kesehatan IP remote dari luar (latensi + loss + TCP timing).

Contoh:
  sudo python3 floodcheck.py monitor --thresh 2000
  sudo python3 floodcheck.py monitor --iface eth0 --top 15
  python3 floodcheck.py probe 10.0.0.5 --port 443 --count 20
"""

import argparse
import socket
import struct
import sys
import time
from collections import defaultdict

IP_PROTO = {1: "ICMP", 6: "TCP", 17: "UDP"}


def proto_name(p: int) -> str:
    return IP_PROTO.get(p, f"proto{p}")


# ---------------- mode: monitor (raw sniff, Linux) ----------------

def monitor(args) -> int:
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        if args.iface != "any":
            s.bind((args.iface, 0))
    except PermissionError:
        print("[!] butuh root: sudo python3 floodcheck.py monitor ...", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"[!] socket gagal: {e}", file=sys.stderr)
        return 1

    print(f"[+] monitoring interface '{args.iface}' — deteksi flood ke IP lokal")
    print(f"[+] alert threshold: {args.thresh} pps per sumber IP\n")
    print(f"{'IP sumber':<16} {'pps':>8} {'proto dominan':>14}  status")

    per_src = defaultdict(lambda: defaultdict(int))  # src -> proto -> count
    alerts = defaultdict(float)  # src -> last alert time
    window_start = time.monotonic()
    window = 1.0

    try:
        while True:
            pkt, addr = s.recvfrom(65535)
            now = time.monotonic()
            elapsed = now - window_start
            if elapsed >= window:
                # lapor jendela selesai
                rows = sorted(((sum(p.values()), src, max(p, key=p.get))
                               for src, p in per_src.items()),
                              reverse=True)[:args.top]
                if rows:
                    print(f"\x1b[2J\x1b[H", end="")  # clear screen
                    print(f"{'IP sumber':<16} {'pps':>8} {'proto dominan':>14}  status")
                    for cnt, src, dom in rows:
                        pps = cnt / elapsed
                        flag = ""
                        if pps >= args.thresh:
                            flag = "!!! FLOOD"
                        elif pps >= args.thresh / 5:
                            flag = "aneh"
                        if pps >= args.thresh and now - alerts[src] > 5:
                            alerts[src] = now
                            print(f"\a[!] FLOOD terdeteksi: {src} "
                                  f"{pps:,.0f} pps {proto_name(dom)} flood ke {args.iface}",
                                  file=sys.stderr)
                        print(f"{src:<16} {pps:>8,.0f} {proto_name(dom):>14}  {flag}")
                    print(f"\n(c)trl+C stop — window {elapsed:.1f}s, top {args.top} sumber")
                per_src.clear()
                window_start = now

            # parse ethernet + ipv4
            if len(pkt) < 14:
                continue
            eth_type = struct.unpack("!H", pkt[12:14])[0]
            if eth_type != 0x0800:
                continue
            ip = pkt[14:]
            if len(ip) < 20:
                continue
            ihl = (ip[0] & 0x0F) * 4
            proto = ip[9]
            src = socket.inet_ntoa(ip[12:16])
            dst = socket.inet_ntoa(ip[16:20])
            # hanya trafik INCOMING ke mesin ini (bukan yang kita kirim)
            if proto == 6:  # tcp: cuma hitung SYN
                if len(ip) < ihl + 14:
                    continue
                flags = ip[ihl + 13]
                if not (flags & 0x02 and not flags & 0x10):  # SYN tanpa ACK
                    continue
            per_src[src][proto] += 1
    except KeyboardInterrupt:
        print("\n[!] monitor berhenti")
    finally:
        s.close()
    return 0


# ---------------- mode: probe (cek remote dari luar) ----------------

def probe(args) -> int:
    print(f"[*] probe {args.ip} port {args.port} — {args.count}x (interval {args.interval}s)")

    # 1) ICMP echo via raw socket (butuh root); fallback TCP saja
    rtt_ping = []
    if args.ping:
        try:
            ps = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            ps.settimeout(args.timeout)
            ident = (int(time.time()) & 0xFFFF)
            for i in range(args.count):
                seq = i + 1
                payload = b"floodcheck" + struct.pack("!d", time.perf_counter())
                icmp = struct.pack("!BBHHH", 8, 0, 0, ident, seq) + payload
                cksum = checksum(icmp)
                icmp = struct.pack("!BBHHH", 8, 0, cksum, ident, seq) + payload
                t0 = time.perf_counter()
                ps.sendto(icmp, (args.ip, 0))
                try:
                    ps.recvfrom(1024)
                    rtt_ping.append((time.perf_counter() - t0) * 1000)
                except socket.timeout:
                    pass
                time.sleep(args.interval)
            ps.close()
        except PermissionError:
            print("    (ping dilewati — perlu root, fallback TCP)")

    # 2) TCP connect timing
    rtt_tcp = []
    for _ in range(args.count):
        t0 = time.perf_counter()
        try:
            with socket.create_connection((args.ip, args.port), timeout=args.timeout):
                rtt_tcp.append((time.perf_counter() - t0) * 1000)
        except OSError:
            pass
        time.sleep(args.interval)

    def summarize(name, rtts):
        if not rtts:
            print(f"  {name:8}: SEMUA timeout — target tidak merespon")
            return None
        loss = (args.count - len(rtts)) / args.count * 100
        print(f"  {name:8}: ok={len(rtts)}/{args.count}  loss={loss:5.1f}%  "
              f"min={min(rtts):.1f}ms avg={sum(rtts)/len(rtts):.1f}ms max={max(rtts):.1f}ms")
        return loss

    print("\n=== hasil probe ===")
    loss_t = summarize("TCP", rtt_tcp)
    if args.ping:
        loss_p = summarize("ICMP", rtt_ping)
    else:
        loss_p = False  # False = tidak diukur (bedakan dari None = semua timeout)

    verdict = "NORMAL"
    reasons = []
    for loss, name in ((loss_p, "ICMP"), (loss_t, "TCP")):
        if loss is False:
            continue
        if loss is None:
            reasons.append(f"{name} tidak merespon sama sekali")
            verdict = "BERMASALAH"
        elif loss > 50:
            reasons.append(f"{name} loss {loss:.0f}%")
            verdict = "MENCURIGAKAN"
        elif loss > 10:
            reasons.append(f"{name} loss {loss:.0f}%")
            if verdict == "NORMAL":
                verdict = "TERDEGRADASI"
    if rtt_tcp and sum(rtt_tcp) / len(rtt_tcp) > 500:
        reasons.append("latensi TCP sangat tinggi")
        if verdict == "NORMAL":
            verdict = "TERDEGRADASI"

    print(f"\nverdict: {verdict}")
    if reasons:
        print("gejala : " + "; ".join(reasons))
        if verdict != "NORMAL":
            print("catatan: pola ini KONSISTEN dengan flood/DDoS, tapi bisa juga")
            print("         target down, link rusak, atau rate-limit. Cek dari 2+")
            print("         vantage point untuk memastikan.")
    else:
        print("gejala : tidak ada — target merespon normal")
    return 0


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data)//2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


BANNER = r"""
   ____                 __                            ____  _     _  __ _   
  / ___| __ _ _ __   __| | __ _ _ __ ___  _ __      / ___|| |   (_)/ _| |_ 
 | |  _ / _` | '_ \ / _` |/ _` | '_ ` _ \| '_ \ ____\___ \| |   | | |_| __|
 | |_| | (_| | | | | (_| | (_| | | | | | | |_) |_____|__) | |___| |  _| |_ 
  \____|\__,_|_| |_|\__,_|\__,_|_| |_| |_| .__/     |____/|_____|_|_|  \__|
                                        |_|                                 
        GarudaShield Flood-check v1.0 — by @andrewjoschelbian
"""


def main() -> int:
    print(BANNER)
    ap = argparse.ArgumentParser(description="GarudaShield Flood-check — deteksi flood/DDoS (monitor lokal / probe remote)")
    sub = ap.add_subparsers(dest="mode", required=True)

    mp = sub.add_parser("monitor", help="sniff trafik lokal, butuh root (Linux)")
    mp.add_argument("--iface", default="any", help="interface (default: semua)")
    mp.add_argument("--thresh", type=float, default=2000, help="pps dianggap flood (default 2000)")
    mp.add_argument("--top", type=int, default=15, help="jumlah sumber IP ditampilkan")
    mp.set_defaults(func=monitor)

    pp = sub.add_parser("probe", help="cek kesehatan IP remote (latensi/loss)")
    pp.add_argument("ip")
    pp.add_argument("--port", type=int, default=80)
    pp.add_argument("--count", type=int, default=10)
    pp.add_argument("--interval", type=float, default=0.5)
    pp.add_argument("--timeout", type=float, default=2.0)
    pp.add_argument("--ping", action="store_true", help="sertakan ICMP echo (perlu root)")
    pp.set_defaults(func=probe)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
