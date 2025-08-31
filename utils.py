import re
import requests
import hashlib
from flask import current_app as app
from flask import flash
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message

mail = Mail()

def send_reset_email(to_email, reset_url):
    msg = Message("Password Reset Request", recipients=[to_email])
    msg.body = f"""To reset your password, click the following link:
    {reset_url}

    If you did not make this request, simply ignore this email
    """
    try:
        mail.send(msg)
    except Exception as e:
        app.logger.error(f"Failed to send reset email to {to_email}: {e}")
        flash("An error occured while sending the password reset email, please try again later", "danger")


def generate_reset_token(user_email, expires_sec=3600):
    s = URLSafeTimedSerializer(app.config["SECRET_KEY"])
    return s.dumps(user_email, salt="password-reset-salt")

def verify_reset_token(token, expires_sec=3600):
    s = URLSafeTimedSerializer(app.config["SECRET_KEY"])
    try:
        email = s.loads(token, salt="password-reset-salt", max_age=expires_sec)
    except Exception:
        return None
    return email

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