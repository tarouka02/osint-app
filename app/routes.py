from flask import Blueprint, render_template, request
import requests
import os

main = Blueprint('main', __name__)

IPINFO_TOKEN = "ed00c49c853ba0"  # Replace with your token or use env var

@main.route('/')
def index():
    return render_template('index.html')

@main.route('/lookup', methods=['POST'])
def lookup():
    ip = request.form.get('ip')
    if not ip:
        return render_template('index.html', error="Please enter an IP address.")

    # Call IPinfo API
    url = f"https://ipinfo.io/{ip}?token={IPINFO_TOKEN}"
    response = requests.get(url)
    
    if response.status_code != 200:
        return render_template('index.html', error="Failed to fetch IP info.")

    data = response.json()
    return render_template('result.html', ip=ip, data=data)

