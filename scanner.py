#!/usr/bin/env python3
import requests
import nmap
import sqlite3
from colorama import Fore, Style

# ---------------------- SAVE TO DB ----------------------
def save_scan_to_db(target, scan_type, result):
    conn = sqlite3.connect("scans.db")
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            scan_type TEXT,
            result TEXT
        )
    """)
    cur.execute("INSERT INTO scans (target, scan_type, result) VALUES (?, ?, ?)",
                (target, scan_type, result))
    conn.commit()
    conn.close()

# ---------------------- HEADER SCAN ----------------------
def header_scan():
    url = input("Enter URL: ")
    r = requests.get(url)

    print(Fore.CYAN + "\nSecurity Headers:" + Style.RESET_ALL)
    headers = ""

    for k, v in r.headers.items():
        print(k, ":", v)
        headers += f"{k}: {v}\n"

    save_scan_to_db(url, "header-scan", headers)
    input("\nPress Enter to return to menu...")

# ---------------------- IP GEOLOCATION ----------------------
def ip_geo():
    ip = input("Enter IP address: ")
    url = f"http://ip-api.com/json/{ip}"
    data = requests.get(url).json()

    result = ""
    print(Fore.GREEN + "\nLocation Information:" + Style.RESET_ALL)

    for k, v in data.items():
        print(k, ":", v)
        result += f"{k}: {v}\n"

    save_scan_to_db(ip, "ip-geolocation", result)
    input("\nPress Enter to return to menu...")

# ---------------------- NMAP SCAN ----------------------
def nmap_scan():
    target = input("Enter target IP: ")
    nm = nmap.PortScanner()

    print(Fore.YELLOW + "Running Nmap Scan..." + Style.RESET_ALL)
    nm.scan(target, arguments='-sV')

    result = ""
    for host in nm.all_hosts():
        print("\nHost:", host)
        result += f"Host: {host}\n"

        print("State:", nm[host].state())
        result += f"State: {nm[host].state()}\n"

        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                state = nm[host][proto][port]["state"]
                print(f"Port {port}: {state}")
                result += f"Port {port}: {state}\n"

    save_scan_to_db(target, "nmap", result)
    input("\nPress Enter to return to menu...")

# ---------------------- MAIN MENU ----------------------
def menu():
    while True:
        print(Fore.MAGENTA + "\n--- SECURITY TOOLKIT ---" + Style.RESET_ALL)
        print("1. Header Scan")
        print("2. IP Geolocation")
        print("3. Nmap Scan")
        print("4. Exit")

        choice = input("\nEnter choice: ")

        if choice == "1":
            header_scan()
        elif choice == "2":
            ip_geo()
        elif choice == "3":
            nmap_scan()
        elif choice == "4":
            exit()
        else:
            print(Fore.RED + "Invalid choice!" + Style.RESET_ALL)

menu() 

