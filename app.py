from flask import Flask, render_template, request, jsonify, send_file
import sqlite3
import requests
import socket
import nmap
from datetime import datetime
from fpdf import FPDF
import time

app = Flask(__name__)

# ------------------ DATABASE SETUP ------------------
def init_db():
    conn = sqlite3.connect("mysec.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            type TEXT,
            result TEXT,
            time TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

def save_record(target, scan_type, result):
    conn = sqlite3.connect("mysec.db")
    c = conn.cursor()
    c.execute("INSERT INTO scans (target, type, result, time) VALUES (?, ?, ?, ?)",
              (target, scan_type, result, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()


# ------------------ HELPER ------------------
def fix_url(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        return "http://" + url
    return url

# FIX → Convert Unicode to safe PDF text
def clean_text(text):
    return text.encode("latin-1", "replace").decode("latin-1")


# ------------------ SCAN FUNCTIONS ------------------
def run_port_scan(target):
    result = ""
    for port in range(1, 101):
        sock = socket.socket()
        sock.settimeout(0.2)
        try:
            sock.connect((target, port))
            result += f"OPEN PORT → {port}\n"
        except:
            pass
        sock.close()
    return result or "No open ports found."


def run_subdomain_scan(domain):
    wordlist = ["www", "mail", "ftp", "admin", "dev"]
    result = ""
    for sub in wordlist:
        url = f"http://{sub}.{domain}"
        try:
            requests.get(url, timeout=1)
            result += f"FOUND → {url}\n"
        except:
            pass
    return result or "No subdomains found."


def run_directory_scan(url):
    url = fix_url(url)
    dirs = ["admin", "login", "dashboard", "uploads", "images", "css", "js"]
    result = ""

    for d in dirs:
        test = url.rstrip("/") + "/" + d
        try:
            r = requests.get(test, timeout=5)
            if r.status_code == 200:
                result += f"FOUND → {test}\n"
        except:
            pass

    return result or "No directories found."


def run_sql_test(url):
    url = fix_url(url)
    payload = "?id=1' OR '1'='1"
    try:
        r = requests.get(url + payload, timeout=5)
        return f"Status: {r.status_code}\n\nResponse:\n{r.text[:1000]}"
    except Exception as e:
        return f"SQL Injection test failed:\n{e}"


def run_header_scan(url):
    url = fix_url(url)
    try:
        r = requests.get(url, timeout=5)
    except Exception as e:
        return f"Header scan failed:\n{e}"

    result = ""
    for k, v in r.headers.items():
        result += f"{k}: {v}\n"
    return result


def run_ip_geo(ip):
    try:
        data = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
        return "\n".join([f"{k}: {v}" for k, v in data.items()])
    except:
        return "Geo lookup failed."


def run_nmap_scan(target):
    nm = nmap.PortScanner()
    try:
        nm.scan(target, arguments='-sV')
    except Exception as e:
        return f"Nmap scan failed:\n{e}"

    result = ""
    for host in nm.all_hosts():
        result += f"Host: {host}\n"
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                state = nm[host][proto][port]['state']
                service = nm[host][proto][port].get('name', 'unknown')
                version = nm[host][proto][port].get('version', '')
                result += f"  {proto.upper()} {port}: {state} ({service} {version})\n"

    return result or "No ports found."


# ------------------ UNIFIED SCAN HANDLER ------------------
@app.route("/run-scan", methods=["POST"])
def run_scan():
    target = request.json["target"]
    scan_type = request.json["scan_type"]

    if scan_type == "port-scan":
        result = run_port_scan(target)
    elif scan_type == "subdomain-scan":
        result = run_subdomain_scan(target)
    elif scan_type == "directory-scan":
        result = run_directory_scan(target)
    elif scan_type == "sql-test":
        result = run_sql_test(target)
    elif scan_type == "header-scan":
        result = run_header_scan(target)
    elif scan_type == "ip-geo":
        result = run_ip_geo(target)
    elif scan_type == "nmap-scan":
        result = run_nmap_scan(target)
    else:
        result = "Unknown scan type."

    save_record(target, scan_type, result)
    return jsonify({"result": result})


# ------------------ EXPORT PDF ------------------
@app.route("/export-pdf")
def export_pdf():
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=14)

    pdf.cell(200, 10, txt="MySec Toolkit - Scan Report", ln=True, align='C')
    pdf.ln(10)
    pdf.set_font("Arial", size=12)

    conn = sqlite3.connect("mysec.db")
    c = conn.cursor()
    c.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 10")
    rows = c.fetchall()
    conn.close()

    for row in rows:
        text = f"""
ID: {row[0]}
Target: {row[1]}
Type: {row[2]}
Time: {row[4]}
Result:
{row[3]}
----------------------------------------
"""
        pdf.multi_cell(0, 10, txt=clean_text(text))

    filename = f"scan_report_{int(time.time())}.pdf"
    filepath = f"/tmp/{filename}"
    pdf.output(filepath)

    return send_file(filepath, as_attachment=True)


# ------------------ HOME PAGE ------------------
@app.route("/")
def index():
    conn = sqlite3.connect("mysec.db")
    c = conn.cursor()
    c.execute("SELECT * FROM scans ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    return render_template("index.html", data=rows)


# ------------------ FLASK START ------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050, debug=True)

