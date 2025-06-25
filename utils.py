import re
import os
import requests
import hashlib
import cv2
from flask import request
from datetime import datetime

def capture_intrusion_screenshot():
    cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        return
    
    ret, frame = cap.read()
    if ret:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        folder = "intrusion_logs"
        os.makedirs(folder, exist_ok=True)
        filename = f"{folder}/intruder_{timestamp}.jpg"
        cv2.imwrite(filename, frame)
        print(f"Intrusion captured: {filename}")

        ip = request.remote_addr
        agent = request.headers.get("User-Agent")
        with open(f"{folder}/log.txt", "a") as f:
            f.write(f"{timestamp} | IP: {ip} | Agent: {agent}\n")
    cap.release()
    cv2.destroyAllWindows()

def get_password_strength(password):
    length = len(password) >= 0
    upper = re.search(r'[A-Z]', password)
    lower = re.search(r'[a-z]', password)
    digit = re.search(r'\d', password)
    special = re.search(r'\W', password)

    score = sum([length, bool(upper), bool(lower), bool(digit), bool(special)])

    if score <= 2:
        return "Weak"
    elif score == 3 or score == 4:
        return "Medium"
    else:
        return "Strong"

def check_pwned(password):
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]

    try:
        response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
        if response.status_code != 200:
            return None
        hashes = (line.split(':') for line in response.text.splitlines())
        for h, count in hashes:
            if h == suffix:
                return int(count)
    except Exception as e:
        print(f"HIBP check failed: {e}")
        return None
    
    return 0