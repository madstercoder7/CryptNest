# 🔐 CryptNest – Your Personal Local Password Vault

CryptNest is a secure, privacy-first password manager that runs entirely **locally on your computer**. With **face unlock**, **intruder detection**, and **zero-knowledge** design goals, CryptNest keeps your secrets safe where they belong — with you.

---

## 🚀 Features

- 🔐 **Password Vault** – Securely store and manage credentials.
- 👤 **Face Unlock** – Log in using your face (optional, enabled per user).
- 🧠 **Intruder Detection** – After 3 failed face attempts, disables face unlock, captures webcam image + screenshot, and emails them.
- 🔒 **Username + Password Fallback** – Always available as a backup login.
- 🛡️ **Breach Checker** – Warns if your password was found in known data breaches (powered by HaveIBeenPwned).
- 💪 **Password Strength Meter** – Rates passwords as Weak / Medium / Strong.
- 🎨 **Dark-Themed Dashboard** – Clean, secure, and easy to use.

---

## 🧰 Technologies Used

- Python + Flask
- OpenCV + face_recognition
- PyAutoGUI (for screenshots)
- SQLite (local database)
- HTML/CSS + Bootstrap (frontend)
- Gmail SMTP (for alerts)

---

## 📦 Installation

### ✅ Step-by-Step Setup (Windows)

1. **Clone the Repository**
```bash
git clone https://github.com/madstercoder7/CryptNest.git
cd CryptNest
```

2. **Create Virtual Environment**
```bash
python -m venv venv
venv\Scripts\activate
```

3. **Install Requirements**
```bash
pip install -r requirements.txt
```

4. **Initialize the database**
```bash
flask shell
```
```bash
from app import db
db.create_all()
exit()
```

5. **Configure Environment Variables**
```bash
SECRET_KEY=your_secret_key_here
ADMIN_MAIL=admins_gmail_id
APP_PASSWORD=admins_gmail_app_password
APP_PASSWORD can be created here https://myaccount.google.com/apppasswords, only if the admin here has 2FA enabled
```

6. **Run the App**
```bash
flask run
```
