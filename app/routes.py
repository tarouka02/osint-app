from flask import Blueprint, render_template, request
import requests

main = Blueprint('main', __name__)

IPINFO_TOKEN = "ed00c49c853ba0"
ABUSEIPDB_KEY = "c9e3012fcd0f78b34d661a02a1dd6f9afa70a059962d31fa6a129fdd6ed98048335a4cbce25a9799"

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

    return render_template('result.html', ip=ip, ipinfo=ipinfo_data, abuse=abuse_data)
