#!/usr/bin/env python3
"""TinyVPN Monitor. Usage: python3 monitor.py [interface]"""
import subprocess, time, sys

IFACE = sys.argv[1] if len(sys.argv) > 1 else "utun3"

def get_stats(iface):
    try:
        out = subprocess.check_output(["netstat", "-I", iface, "-b"], text=True)
        lines = out.strip().splitlines()
        if len(lines) < 2: return None
        p = lines[1].split()
        return {"ip": int(p[4]), "ib": int(p[6]), "op": int(p[7]), "ob": int(p[9])}
    except: return None

def fmt(n):
    if n > 1_000_000: return f"{n/1_000_000:.2f}MB"
    if n > 1_000: return f"{n/1_000:.2f}KB"
    return f"{n}B"

prev = None
print(f"TinyVPN Monitor | {IFACE}\n{'─'*50}")
print(f"  {'ΔIN pkts':>10}  {'ΔIN bytes':>10}  {'ΔOUT pkts':>10}  {'ΔOUT bytes':>10}")
print(f"{'─'*50}")
try:
    while True:
        s = get_stats(IFACE)
        if not s: print(f"  [!] {IFACE} not found — is the tunnel up?", end="\r")
        elif prev:
            print(f"  {s['ip']-prev['ip']:>10}  {fmt(s['ib']-prev['ib']):>10}  "
                  f"{s['op']-prev['op']:>10}  {fmt(s['ob']-prev['ob']):>10}", end="\r", flush=True)
        prev = s
        time.sleep(1)
except KeyboardInterrupt: print("\n[monitor] stopped.")
