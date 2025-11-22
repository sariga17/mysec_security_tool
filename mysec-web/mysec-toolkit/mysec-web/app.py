from flask import Flask, render_template, request
import socket
import requests
import hashlib

app = Flask(__name__)

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/portscan', methods=['GET', 'POST'])
def portscan():
    result = ""
    if request.method == 'POST':
        target = request.form['target']
        ports = [21, 22, 23, 25, 53, 80, 443, 3306, 8080]

        open_ports = []
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            try:
                sock.connect((target, port))
                open_ports.append(port)
            except:
                pass
            sock.close()

        result = f"Open Ports: {open_ports}"
    return render_template("portscan.html", result=result)

@app.route('/subdomain', methods=['GET', 'POST'])
def subdomain():
    result = ""
    if request.method == 'POST':
        domain = request.form['domain']
        subs = ["www", "mail", "ftp", "test", "dev", "api"]
        found = []

        for sub in subs:
            url = f"http://{sub}.{domain}"
            try:
                requests.get(url, timeout=1)
                found.append(url)
            except:
                pass

        result = found
    return render_template("subdomain.html", result=result)

@app.route('/xss', methods=['GET', 'POST'])
def xss():
    result = ""
    if request.method == "POST":
        payload = request.form['payload']
        result = f"Injected Payload: {payload}"
    return render_template("xss.html", result=result)

@app.route('/headers', methods=['GET', 'POST'])
def headers():
    result = ""
    if request.method == "POST":
        url = request.form['url']
        try:
            r = requests.get(url)
            result = dict(r.headers)
        except:
            result = "Error: Cannot fetch headers!"
    return render_template("headers.html", result=result)

@app.route('/hashcrack', methods=['GET', 'POST'])
def hashcrack():
    result = ""
    if request.method == "POST":
        hash_value = request.form['hash']
        wordlist = ["password", "admin", "123456", "letmein", "welcome"]
        cracked = "Not Found"

        for word in wordlist:
            if hashlib.md5(word.encode()).hexdigest() == hash_value:
                cracked = word
                break

        result = cracked
    return render_template("hashcrack.html", result=result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
