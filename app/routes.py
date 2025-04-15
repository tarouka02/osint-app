from flask import Blueprint, render_template, request
import requests

main = Blueprint('main', __name__)

IPINFO_TOKEN = "ed00c49c853ba0"
ABUSEIPDB_KEY = "c9e3012fcd0f78b34d661a02a1dd6f9afa70a059962d31fa6a129fdd6ed98048335a4cbce25a9799"
VIRUSTOTAL_KEY = "09ade77eb4a2776b84fa4e66a293ee33b3b013c40fff003685fa236456d0ca35"

@main.route('/')
def index():
    return render_template('index.html')

@main.route('/lookup', methods=['POST'])
def lookup():
    ip = request.form.get('ip')
    if not ip:
        return render_template('index.html', error="Please enter an IP address.")

    ### --- IPinfo --- ###
    ipinfo_url = f"https://ipinfo.io/{ip}?token={IPINFO_TOKEN}"
    ipinfo_resp = requests.get(ipinfo_url)
    if ipinfo_resp.status_code != 200:
        return render_template('index.html', error="IPinfo API failed.")
    ipinfo_data = ipinfo_resp.json()

    ### --- AbuseIPDB --- ###
    abuse_headers = {
        'Key': ABUSEIPDB_KEY,
        'Accept': 'application/json'
    }
    abuse_url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    abuse_resp = requests.get(abuse_url, headers=abuse_headers)
    abuse_data = abuse_resp.json().get('data', {}) if abuse_resp.status_code == 200 else {"error": "AbuseIPDB failed"}


        ### --- VirusTotal --- ###
    vt_headers = {
        "x-apikey": VIRUSTOTAL_KEY
    }
    vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    vt_resp = requests.get(vt_url, headers=vt_headers)

    if vt_resp.status_code == 200:
        vt_data = vt_resp.json().get("data", {}).get("attributes", {})
        malicious_votes = vt_data.get("last_analysis_stats", {}).get("malicious", 0)
        harmless_votes = vt_data.get("last_analysis_stats", {}).get("harmless", 0)
        suspicious_votes = vt_data.get("last_analysis_stats", {}).get("suspicious", 0)
    else:
        vt_data = {}
        malicious_votes = harmless_votes = suspicious_votes = "?"
        
    return render_template('result.html', ip=ip, ipinfo=ipinfo_data,
                    abuse=abuse_data, malicious_votes=malicious_votes,
                    harmless_votes=harmless_votes, suspicious_votes=suspicious_votes)

