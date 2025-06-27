import re
import os
import requests
import hashlib
import cv2
import pyautogui
from email.message import EmailMessage
import smtplib
from flask import request
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

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

def handle_intrusion(user):
    os.makedirs("intrusion_logs", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    intruder_path = f"intrusion_logs/intruder_{user.id}_{timestamp}.jpg"
    screenshot_path = f"intrusion_logs/screenshot_{user.id}_{timestamp}.png"

    cam = cv2.VideoCapture(0)
    ret, frame = cam.read()
    if ret:
        cv2.imwrite(intruder_path, frame)
    cam.release()

    screenshot = pyautogui.screenshot()
    screenshot.save(screenshot_path)

    send_intrusion_alert(user.email, intruder_path, screenshot_path)

def send_intrusion_alert(from_email, to_email, intruder_path, screen_path):
    from_email = os.getenv('MAIL_USER')
    mail_password = os.getenv('MAIL_PASSWORD')
    msg = EmailMessage()
    msg['Subject'] = 'CryptNest intrusion alert'
    msg['From'] = from_email
    msg['To'] = to_email
    msg.set_content(
        "⚠️ CryptNest detected 3 failed face unlock attempts.\n"
        "Attached are the intruder's photo and a screenshot taken during the intrusion."
    )

    try:
        with open(intruder_path, 'rb') as img:
            img_data = img.read()
            img_name = os.path.basename(intruder_path)
            msg.add_attachment(img_data, maintype='image', subtype='jpeg', filename=img_name)
    except Exception as e:
        print(f"Failed to attach intruder image: {e}")

    try:
        with open(screen_path, 'rb') as ss:
            ss_data = ss.read()
            ss_name = os.path.basename(screen_path)
            msg.add_attachment(ss_data, maintype='image', subtype='png', filename=ss_name)
    except Exception as e:
        print(f"Failed to attach screenshot: {e}")

    try:
        smtp_server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        smtp_server.login('cryptnestpm@gmail.com', mail_password)
        smtp_server.send_message(msg)
        smtp_server.quit()
        print("Intrusion alert mail sent")
    except smtplib.SMTPAuthenticationError as e:
        print("SMTP Authentication failed", e)
    except Exception as e:
        print("Failed to send email", e)