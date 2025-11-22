#!/usr/bin/env python3
"""
MYSEC Tool v2 — safer extended toolkit

Features included:
- Port scanner (threaded)
- Subdomain scanner
- Directory brute force (advanced threaded)
- XSS reflected scanner
- Header analyzer
- IP geolocation
- Nmap wrapper (including NSE scripts)
- Packet sniffer (Scapy) - capture headers & save pcap
- WiFi scanner (calls system iwlist / nmcli)
- Hash cracker (local dictionary)
- ARP scanner (non-spoofing) for detection
"""

import os
import sys
import socket
import threading
import requests
import time
import hashlib
import subprocess
from queue import Queue
from colorama import Fore, Style
import nmap

# Try importing scapy (packet sniffing)
try:
    from scapy.all import sniff, wrpcap, conf
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

# ---------- Helper / UI ----------
def banner():
    print(Fore.CYAN + """
======================================================
              MYSEC – Security Toolkit (Safer v2)
    Use these tools only on systems you own or may test
======================================================
""" + Style.RESET_ALL)

def pause():
    input("\nPress Enter to return to menu...")

# ---------- Port scanner ----------
def port_scanner():
    target = input("Enter target IP or host: ").strip()
    try:
        ip = socket.gethostbyname(target)
    except:
        print(Fore.RED + "Cannot resolve target." + Style.RESET_ALL)
        pause(); return

    mode = input("Fast scan (1-500) or Full (1-65535)? [fast/full]: ").strip().lower()
    if mode == "fast":
        ports = range(1, 501)
    elif mode == "full":
        ports = range(1, 65536)
    else:
        ports = range(1, 1025)

    open_ports = []
    q = Queue()
    for p in ports:
        q.put(p)

    def worker():
        while not q.empty():
            port = q.get()
            try:
                s = socket.socket()
                s.settimeout(0.4)
                s.connect((ip, port))
                open_ports.append(port)
                try:
                    s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = s.recv(1024).decode(errors="ignore").strip().splitlines()[0]
                except:
                    banner = "No banner"
                print(Fore.GREEN + f"[OPEN] {port} -> {banner}" + Style.RESET_ALL)
                s.close()
            except:
                pass
            q.task_done()

    thread_count = min(200, os.cpu_count() * 10)
    threads = []
    for _ in range(thread_count):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        threads.append(t)

    q.join()
    print(Fore.MAGENTA + "\nScan complete. Open ports:" + Style.RESET_ALL, sorted(open_ports))
    pause()

# ---------- Subdomain scanner (small wordlist) ----------
def subdomain_scan():
    domain = input("Enter domain (example.com): ").strip()
    wordlist = ["www","api","dev","staging","test","admin","mail","portal","webmail","m"]
    print(Fore.YELLOW + f"Scanning subdomains for {domain}..." + Style.RESET_ALL)
    for sub in wordlist:
        host = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(host)
            print(Fore.GREEN + f"[FOUND] {host} -> {ip}" + Style.RESET_ALL)
        except:
            pass
    pause()

# ---------- Advanced Directory Bruteforce ----------
def dir_bruteforce():
    url = input("Enter base URL (http://example.com): ").strip().rstrip("/")
    wl = input("Path to wordlist file (press Enter to use small default): ").strip()
    if not wl:
        wordlist = ["admin","login","dashboard","uploads","backup","config","test","portal","wp-admin",".git"]
    else:
        try:
            with open(wl, 'r', errors='ignore') as f:
                wordlist = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(Fore.RED + f"Could not open wordlist: {e}" + Style.RESET_ALL)
            pause(); return

    threads = []
    q = Queue()
    for w in wordlist:
        q.put(w)

    def worker():
        while not q.empty():
            path = q.get()
            full = f"{url}/{path}"
            try:
                r = requests.get(full, timeout=5, allow_redirects=False)
                if r.status_code in (200,301,302,401,403):
                    print(Fore.GREEN + f"[{r.status_code}] {full}" + Style.RESET_ALL)
            except Exception:
                pass
            q.task_done()

    tcount = min(50, len(wordlist))
    for _ in range(tcount):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        threads.append(t)

    q.join()
    print(Fore.MAGENTA + "Bruteforce finished." + Style.RESET_ALL)
    pause()

# ---------- Reflected XSS Checker ----------
def xss_scanner():
    url = input("Enter URL with parameter placeholder (e.g. http://example.com/page?q=): ").strip()
    payloads = [
        "<script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "';alert(1)//",
        "<img src=x onerror=alert(1)>"
    ]
    print(Fore.YELLOW + "Testing reflected XSS (only detection)..." + Style.RESET_ALL)
    for p in payloads:
        test_url = url + requests.utils.requote_uri(p)
        try:
            r = requests.get(test_url, timeout=5)
            if p in r.text:
                print(Fore.RED + f"[POSSIBLE XSS] Payload reflected: {p}" + Style.RESET_ALL)
            else:
                print(f"[OK] payload not reflected: {p}")
        except Exception as e:
            print(f"Error: {e}")
    print("Note: This is a naive reflected-XSS detector; use manual verification.")
    pause()

# ---------- Header analyzer ----------
def header_analyzer():
    url = input("Enter URL (include http/https): ").strip()
    try:
        r = requests.get(url, timeout=6)
        print(Fore.CYAN + "\nResponse headers:\n" + Style.RESET_ALL)
        for k,v in r.headers.items():
            print(k + ":", v)
    except Exception as e:
        print(Fore.RED + f"Error: {e}" + Style.RESET_ALL)
    pause()

# ---------- IP Geolocation ----------
def ip_geo():
    ip = input("Enter IP (or leave blank for remote host): ").strip()
    if not ip:
        host = input("Enter hostname to resolve (or leave blank to cancel): ").strip()
        if not host:
            pause(); return
        try:
            ip = socket.gethostbyname(host)
        except:
            print("Could not resolve host."); pause(); return
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=6).json()
        for k,v in r.items():
            print(f"{k}: {v}")
    except Exception as e:
        print("Error:", e)
    pause()

# ---------- Nmap wrapper (safe NSE options) ----------
def nmap_wrapper():
    target = input("Enter target IP or host: ").strip()
    nm = nmap.PortScanner()
    print("Quick service/version scan (-sV)")
    try:
        nm.scan(target, arguments='-sV --open')
        for h in nm.all_hosts():
            print("\nHost:", h, "State:", nm[h].state())
            for proto in nm[h].all_protocols():
                for port in nm[h][proto].keys():
                    info = nm[h][proto][port]
                    print(f" {port}/{proto} {info['state']} {info.get('name','')}/{info.get('product','')}")
    except Exception as e:
        print("Nmap error:", e)

    # Ask whether to run a small set of NSE scripts (inform user)
    print("\nNSE script runner: run only if you have permission to scan target.")
    yn = input("Run safe NSE scripts (default: no)? [y/N]: ").strip().lower()
    if yn == 'y':
        # safeish scripts: http-title, ssl-cert, vulners (caution)
        scripts = input("Enter comma-separated NSE scripts (e.g. http-title,ssl-cert) or press Enter for defaults: ").strip()
        if not scripts:
            scripts = "http-title,ssl-cert"
        try:
            nm.scan(target, arguments=f'--script {scripts}')
            print("NSE run complete. Results:")
            # Print script output if any
            for h in nm.all_hosts():
                if 'hostscript' in nm[h]:
                    for item in nm[h]['hostscript']:
                        print(item)
        except Exception as e:
            print("NSE error:", e)
    pause()

# ---------- Packet sniffer (Scapy) ----------
def packet_sniffer():
    if not SCAPY_AVAILABLE:
        print(Fore.RED + "Scapy not available. Install with: pip3 install scapy" + Style.RESET_ALL)
        pause(); return

    iface = input("Interface to sniff on (e.g. eth0, wlan0) or leave blank for default: ").strip()
    if not iface:
        iface = conf.iface
    print(Fore.YELLOW + f"Capturing packets on {iface}. Press Ctrl+C to stop." + Style.RESET_ALL)
    pcap_file = f"capture_{int(time.time())}.pcap"
    packets = []

    def pkt_handler(pkt):
        packets.append(pkt)
        # print a short summary
        print(pkt.summary())

    try:
        sniff(iface=iface, prn=pkt_handler, store=False, timeout=None)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print("Error:", e)

    if packets:
        try:
            wrpcap(pcap_file, packets)
            print(Fore.MAGENTA + f"Saved {len(packets)} packets to {pcap_file}" + Style.RESET_ALL)
        except Exception as e:
            print("Could not save pcap:", e)
    else:
        print("No packets captured.")
    pause()

# ---------- WiFi scanner (calls system tools) ----------
def wifi_scan():
    print(Fore.YELLOW + "Wi-Fi scan using system tools (iwlist/nmcli)" + Style.RESET_ALL)
    # try nmcli first
    try:
        out = subprocess.check_output(["nmcli", "-f", "SSID,SIGNAL,BARS,CHAN,SECURITY", "device", "wifi"], stderr=subprocess.DEVNULL)
        print(out.decode(errors='ignore'))
        pause(); return
    except Exception:
        pass

    # fallback to iwlist (requires sudo)
    iface = input("Wireless interface (e.g. wlan0) or leave blank for wlan0: ").strip() or "wlan0"
    try:
        out = subprocess.check_output(["sudo", "iwlist", iface, "scan"], stderr=subprocess.DEVNULL, timeout=15)
        text = out.decode(errors='ignore')
        # simple parsing for ESSID and signal
        for block in text.split("Cell ")[1:]:
            if "ESSID" in block:
                essid = block.split("ESSID:")[1].split("\n")[0].strip().strip('"')
            else:
                essid = "<hidden>"
            if "Signal level" in block:
                sig = block.split("Signal level=")[1].split(" ")[0]
            else:
                sig = "N/A"
            print(f"{essid} | Signal: {sig}")
    except Exception as e:
        print("Error running iwlist:", e)
    pause()

# ---------- Hash cracker (offline dictionary) ----------
def hash_cracker():
    h = input("Enter hash (MD5/SHA1/SHA256): ").strip()
    wl = input("Path to wordlist (default: rockyou small subset) : ").strip()
    if not wl:
        # small embedded list as default
        candidates = ["password","123456","admin","letmein","welcome","qwerty","changeme"]
    else:
        try:
            with open(wl, 'r', errors='ignore') as f:
                candidates = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print("Could not open wordlist:", e); pause(); return

    def hash_of(s, algo):
        if algo == "md5":
            return hashlib.md5(s.encode()).hexdigest()
        if algo == "sha1":
            return hashlib.sha1(s.encode()).hexdigest()
        if algo == "sha256":
            return hashlib.sha256(s.encode()).hexdigest()
        return None

    algo = None
    length = len(h)
    if length == 32:
        algo = "md5"
    elif length == 40:
        algo = "sha1"
    elif length == 64:
        algo = "sha256"
    else:
        print("Unknown hash type by length; trying all three.")
    found = False
    for pw in candidates:
        if algo:
            if hash_of(pw, algo) == h:
                print(Fore.GREEN + f"Found! {pw}" + Style.RESET_ALL)
                found = True; break
        else:
            if hash_of(pw, "md5") == h or hash_of(pw, "sha1") == h or hash_of(pw, "sha256") == h:
                print(Fore.GREEN + f"Found! {pw} (detected algorithm by match)" + Style.RESET_ALL)
                found = True; break
    if not found:
        print(Fore.RED + "No match found in provided wordlist." + Style.RESET_ALL)
    pause()

# ---------- ARP scanner (non-spoofing) ----------
def arp_scan():
    target = input("Enter network (CIDR, e.g. 192.168.1.0/24): ").strip()
    print("Scanning ARP (this uses arp-scan if available, else uses ping sweep).")
    try:
        out = subprocess.check_output(["which", "arp-scan"]).decode().strip()
        if out:
            print("Running arp-scan (requires sudo).")
            subprocess.run(["sudo", "arp-scan", "-l"])
            pause(); return
    except Exception:
        pass

    # fallback: ping sweep
    base = target.split('/')[0].rsplit('.',1)[0]
    live = []
    for i in range(1,255):
        host = f"{base}.{i}"
        try:
            p = subprocess.run(["ping","-c","1","-W","1",host], stdout=subprocess.DEVNULL)
            if p.returncode == 0:
                live.append(host)
                print(Fore.GREEN + f"Host up: {host}" + Style.RESET_ALL)
        except:
            pass
    print("Live hosts:", live)
    pause()

# ---------- Main menu ----------
def main():
    while True:
        banner()
        print(Fore.GREEN + """
1. Port Scanner
2. Subdomain Scanner
3. Directory Bruteforce (advanced)
4. Reflected XSS Scanner
5. Header Analyzer
6. IP Geolocation
7. Nmap Wrapper (with optional NSE)
8. Packet Sniffer (Scapy)*
9. WiFi Scanner (iwlist/nmcli)*
10. Hash Cracker (offline dictionary)
11. ARP Scanner (non-spoofing)
12. Exit
* Features marked with * may require sudo/root.
""" + Style.RESET_ALL)
        choice = input("Choose option: ").strip()
        if choice == "1":
            port_scanner()
        elif choice == "2":
            subdomain_scan()
        elif choice == "3":
            dir_bruteforce()
        elif choice == "4":
            xss_scanner()
        elif choice == "5":
            header_analyzer()
        elif choice == "6":
            ip_geo()
        elif choice == "7":
            nmap_wrapper()
        elif choice == "8":
            packet_sniffer()
        elif choice == "9":
            wifi_scan()
        elif choice == "10":
            hash_cracker()
        elif choice == "11":
            arp_scan()
        elif choice == "12":
            print("Exiting.")
            sys.exit(0)
        else:
            print("Invalid option.")

if __name__ == "__main__":
    main()
