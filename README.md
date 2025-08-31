# 🔐 CryptNest – Your Personal Password Vault

CryptNest is a secure, privacy-first password manager, with **face unlock** and **zero-knowledge** design goals. CryptNest keeps your secrets safe where they belong — with you.

---

## Live Demo
https://cryptnest-oxje.onrender.com

---

## 🚀 Features

- 🔐 **Password Vault** – Securely store and manage credentials.
- 👤 **Face Unlock** – Log in using your face (optional, enabled per user).
- 🔒 **Username + Password Fallback** – Always available as a backup login.
- 🛡️ **Breach Checker** – Warns if your password was found in known data breaches (powered by HaveIBeenPwned).
- 💪 **Password Strength Meter** – Rates passwords as Weak / Medium / Strong.
- 🎨 **Dark-Themed Dashboard** – Clean, secure, and easy to use.

---

## 🧰 Technologies Used

- Python + Flask (Backend)
- face-api.js (Frontend face recognition)
- Supabase (PostgreSQL)
- HTML/CSS + Bootstrap (Frontend)
- HaveIBeenPwned API (Breach Check)
  
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

3. **Install Dependencies**
```
pip install -r requirements.txt
```

4. **Initialize the database**
```bash
flask db init
flask db migrater -m "Initial migration"
flask db upgrade
```

5. **Configure Environment Variables**
Create a .env file in your project root and add:
```bash
SECRET_KEY=your_secret_key_here
DATABASE_URL=your_database_url_here
ENCRYPTION_KEY=your_encryption_key_here
```

6. **Run the App**
```bash
flask run
```

Please provide feedback
