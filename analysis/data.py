import requests
from bs4 import BeautifulSoup
import csv
import time
import random
from tqdm import tqdm

TARGET_VALID_RESULTS = 500

def fetch_ip_list():
    url = "https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/ipsum.txt"
    response = requests.get(url)
    response.raise_for_status()
    ip_list = [
        line.split()[0]
        for line in response.text.splitlines()
        if not line.startswith("#") and line.strip()
    ]
    random.shuffle(ip_list)
    return ip_list

def extract_data(html):
    soup = BeautifulSoup(html, 'html.parser')

    def find_text(label):
        tag = soup.find(string=lambda s: s and label in s)
        return tag.strip() if tag else "N/A"

    risk_tag = soup.select_one('.summary-box h4 span')
    risk_level = risk_tag.text.strip() if risk_tag else "N/A"

    country = find_text("Country:")
    abuse_score = find_text("Abuse Score:").split('%')[0].strip() if "Abuse Score:" in html else "N/A"

    return risk_level, country.replace("Country:", "").strip(), abuse_score

def query_ip(ip, session):
    r1 = session.post("http://127.0.0.1:5000/lookup", data={"ip": ip})
    time.sleep(2.5)
    r2 = session.get("http://127.0.0.1:5000/results")
    if r2.status_code == 200:
        return extract_data(r2.text)
    return ("N/A", "N/A", "N/A")

def main():
    ip_list = fetch_ip_list()
    session = requests.Session()

    collected_rows = []

    with tqdm(total=TARGET_VALID_RESULTS, desc="Collecting Valid IPs", unit="IP") as pbar:
        for ip in ip_list:
            try:
                risk, country, abuse = query_ip(ip, session)
                if country != "N/A":
                    collected_rows.append([ip, risk, country, abuse])
                    pbar.update(1)
                if len(collected_rows) >= TARGET_VALID_RESULTS:
                    break
            except Exception as e:
                print(f"[!] Error with IP {ip}: {e}")

    with open('osint_data.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["IP", "Risk Level", "Country", "Abuse Score"])
        writer.writerows(collected_rows)

    print(f"\n✅ Done! {len(collected_rows)} IP entries saved to osint_data.csv")

if __name__ == "__main__":
    main()
