from flask import Blueprint, render_template, request
from datetime import datetime, timezone
import requests

main = Blueprint('main', __name__)

IPINFO_TOKEN = "ed00c49c853ba0"
ABUSEIPDB_KEY = "c9e3012fcd0f78b34d661a02a1dd6f9afa70a059962d31fa6a129fdd6ed98048335a4cbce25a9799"
VIRUSTOTAL_KEY = "09ade77eb4a2776b84fa4e66a293ee33b3b013c40fff003685fa236456d0ca35"
SHODAN_KEY = "HgVMSbmIyUYe0y8gRrJ9p3XYTLgmikU1"

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
    loc = ipinfo_data.get("loc", "")
    latitude, longitude = (loc.split(",") if loc else ("", ""))


    ### --- AbuseIPDB --- ###
    abuse_headers = {
        'Key': ABUSEIPDB_KEY,
        'Accept': 'application/json'
    }
    abuse_url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    abuse_resp = requests.get(abuse_url, headers=abuse_headers)
    abuse_data = abuse_resp.json().get('data', {}) if abuse_resp.status_code == 200 else {"error": "AbuseIPDB failed"}
    
    
    # Format last reported timestamp (optional)
    raw_timestamp = abuse_data.get("lastReportedAt")
    if raw_timestamp:
        try:
            last_reported = datetime.fromisoformat(raw_timestamp.replace("Z", "+00:00"))
            delta_days = (datetime.now(timezone.utc) - last_reported).days
            abuse_data["lastSeenDaysAgo"] = f"{delta_days} day(s) ago"
        except:
            abuse_data["lastSeenDaysAgo"] = "Unknown"
    else:
        abuse_data["lastSeenDaysAgo"] = "N/A"


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

    ### --- Shodan --- ###
    shodan_url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_KEY}"
    shodan_resp = requests.get(shodan_url)

    if shodan_resp.status_code == 200:
        shodan_data = shodan_resp.json()
        open_ports = shodan_data.get("ports", [])
        org = shodan_data.get("org", "N/A")
        isp = shodan_data.get("isp", "N/A")
        hostnames = shodan_data.get("hostnames", [])
        country = shodan_data.get("country_name", "Unknown")
    else:
        open_ports = []
        org = isp = country = "N/A"
        hostnames = ["Error: Shodan lookup failed"]
    print("Shodan Response:", shodan_resp.text)

        ### --- Risk Scoring Logic --- ###
    try:
        abuse_score = int(abuse_data.get("abuseConfidenceScore", 0))
        abuse_conf = int(abuse_data.get("abuseConfidenceScore", 0))

        if abuse_conf >= 85:
            abuse_level = "High"
            abuse_color = "danger"
            abuse_summary = "🚫 This IP has a very high abuse confidence score. Likely involved in malicious activity."
        elif abuse_conf >= 40:
            abuse_level = "Medium"
            abuse_color = "warning"
            abuse_summary = "⚠️ This IP has a moderate abuse score. May have been used for suspicious activity."
        else:
            abuse_level = "Low"
            abuse_color = "success"
            abuse_summary = "✅ This IP has a low abuse score and is likely safe."

        # Add to render_template

        vt_malicious = int(malicious_votes)
        num_ports = len(open_ports)
    except:
        abuse_score = vt_malicious = num_ports = 0

    score = abuse_score + (vt_malicious * 3) + (num_ports * 2)

    if score >= 80:
        risk_level = "High"
        color = "red"
    elif score >= 40:
        risk_level = "Medium"
        color = "orange"
    else:
        risk_level = "Low"
        color = "green"


    return render_template(
        'result.html',
        ip=ip,
        ipinfo=ipinfo_data,
        abuse=abuse_data,
        malicious_votes=malicious_votes,
        harmless_votes=harmless_votes,
        suspicious_votes=suspicious_votes,
        open_ports=open_ports,
        org=org,
        isp=isp,
        hostnames=hostnames,
        country=country,
        risk_level=risk_level,
        risk_color=color,
        buse_level=abuse_level,
        abuse_color=abuse_color,
        abuse_summary=abuse_summary,
        latitude=latitude,
        longitude=longitude
    )




