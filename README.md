# OSINT Intelligence Platform

A modern web application built with Flask for Open Source Intelligence (OSINT) IP lookups. This tool gathers data from multiple public APIs to evaluate and visualize the risk level of any IPv4 address. It combines backend processing with a professionally designed frontend to deliver detailed and interactive intelligence reports.

---

## Features

- Geolocation, ASN, and organization details from **IPinfo**
- Abuse reports, confidence scores, and threat history from **AbuseIPDB**
- Threat analysis statistics from **VirusTotal**
- Open ports, ISP, and hostnames from **Shodan**
- Risk scoring algorithm based on aggregate threat signals
- Animated loading screen and result transition
- Professional landing page with:
  - Typed headline animations (Typed.js)
  - Slide-based API feature explanation (Swiper.js)
  - Scroll animations (AOS.js)
- Gradient titles, responsive layout, and interactive styling using Bootstrap 5 and custom CSS

---

## Tech Stack

**Backend:**
- Python 3
- Flask
- Requests

**Frontend:**
- HTML5, CSS3
- Bootstrap 5
- Swiper.js (slide animations)
- Typed.js (typing header animation)
- AOS.js (scroll-triggered animations)

**External APIs Used:**
- [IPinfo](https://ipinfo.io/)
- [AbuseIPDB](https://abuseipdb.com/)
- [VirusTotal](https://www.virustotal.com/)
- [Shodan](https://www.shodan.io/)

---

## Setup Instructions

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/osint-intel-platform.git
cd osint-intel-platform
```

### 2. Create and activate a virtual environment

# Create virtual environment
```bash
python -m venv venv
```

# Activate (choose the appropriate command for your OS)
# Windows (PowerShell)
```bash
.\venv\Scripts\Activate
```

# macOS/Linux
```bash
source venv/bin/activate
```

### 3. Install dependencies
```bash
pip install flask requests
```

### 4. Run the App
# Ensure you're in the venv and in the project directory
```bash
flask run
```

### 5. Project Structure
```bash
osint-intel-platform/
├── static/
│   └── styles.css, scripts/
├── templates/
│   ├── index.html
│   ├── loading.html
│   └── result.html
├── app.py or routes.py
├── requirements.txt
└── README.md
```



