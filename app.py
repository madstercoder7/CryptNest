import os
import re
import base64
import numpy as np
import json
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, flash, request, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate # type: ignore
from sqlalchemy import or_, text
from sqlalchemy.exc import OperationalError
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from flask_wtf import FlaskForm
from wtforms import PasswordField, SubmitField, StringField, EmailField
from wtforms.validators import DataRequired, EqualTo, Length, Email
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_limiter.errors import RateLimitExceeded
from cryptography.fernet import Fernet
from utils import get_password_strength, check_pwned
from scipy.spatial.distance import euclidean # type: ignore
from utils import send_reset_email, verify_reset_token, generate_reset_token, mail

load_dotenv()

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")  
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USE_SSL"] = False
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = os.getenv("MAIL_USERNAME")
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

db = SQLAlchemy(app)
migrate = Migrate(app, db)
mail.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

@app.before_request
def warm_db():
    if request.endpoint in ('static', None) or request.path == '/favicon.ico':
        return
    
    try:
        db.session.execute(text("SELECT 1"))
    except OperationalError:
        app.logger.warning("Database is waking up or unreachable")

ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY')
if not ENCRYPTION_KEY:
    ENCRYPTION_KEY = Fernet.generate_key().decode()

fernet = Fernet(ENCRYPTION_KEY.encode())

def encrypt_password(password_plain):
    return fernet.encrypt(password_plain.encode()).decode()

def decrypt_password(password_encrypted):
    return fernet.decrypt(password_encrypted.encode()).decode()

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    face_unlock_enabled = db.Column(db.Boolean, default=True)
    face_attempts = db.Column(db.Integer, default=0)
    face_descriptor = db.Column(db.Text, nullable=True)

class Credential(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    site = db.Column(db.String(100), nullable=False)
    site_username = db.Column(db.String(100), nullable=False)
    site_password = db.Column(db.Text, nullable=False)
    strength = db.Column(db.String(10))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

REDIS_URL = os.getenv("REDIS_URL")
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per day"], storage_uri=REDIS_URL)
limiter.init_app(app)

@app.errorhandler(RateLimitExceeded)
def ratelimit_handler(e):
    return jsonify({
        "error": "Too many requests, please slow down",
        "message": str(e.description)
    }), 429

# Load user
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Forms
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = EmailField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class CredentialForm(FlaskForm):
    site = StringField('Site', validators=[DataRequired()])
    site_username = StringField('Username', validators=[DataRequired()])
    site_password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Save')

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField("Current Password", validators=[DataRequired()])
    new_password = PasswordField("New Password", validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField("Confirm New Password", validators=[DataRequired(), EqualTo("new_password")])
    submit = SubmitField("Change Password")

class ForgotPasswordForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    submit = SubmitField("Request Password Reset")

class ResetPasswordForm(FlaskForm):
    password = PasswordField("New Password", validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo("password")])
    submit = SubmitField("Reset Password")

# Routes
@app.route('/')
def home():
    return render_template("landing.html")

@app.route("/register", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        existing_user = User.query.filter(or_(User.username == form.username.data, User.email == form.email.data)).first()
        if existing_user:
            if existing_user.username == form.username.data:
                flash("Username already exists, try another", "danger")
            else:
                flash("Email already registered, try anther", "danger")
            return redirect(url_for("register"))
        
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode("utf-8")
        face_descriptor = request.form.get("face_descriptor")
        user = User(username=form.username.data, email=form.email.data, password=hashed_password, face_descriptor=json.dumps(json.loads(face_descriptor)) if face_descriptor else None)
        db.session.add(user)
        db.session.commit()

        flash("Registration successful please login", "success")
        return redirect(url_for("login"))
    return render_template("register.html", form=form)

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data.strip()).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            user.face_attempts = 0
            db.session.commit()
            flash("Login successful", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Incorrect username or password", "danger")
    return render_template("login.html", form=form)
    
@app.route("/verify_face_descriptor", methods=["POST"])
def verify_face_descriptor():
    data = request.get_json()
    username = data.get("username")
    descriptor = data.get("descriptor")
    if not username or not descriptor:
        return jsonify({"success": False, "message": "Missing username or descriptor"}), 400
    
    user = User.query.filter_by(username=username).first()
    if not user or not user.face_descriptor:
        return jsonify({"success": False, "message": "User not found or no face data"}), 404
    
    stored_descriptor = np.array(json.loads(user.face_descriptor))
    incoming_descriptor = np.array(descriptor)
    distance = np.linalg.norm(stored_descriptor - incoming_descriptor)

    if distance < 0.6:
        login_user(user)
        user.face_attempts = 0
        db.session.commit()
        return jsonify({"success": True, "redirect": url_for("dashboard")})
    else:
        user.face_attempts += 1
        db.session.commit()
        if user.face_attempts >= 3:
            user.face_unlock_enabled = False
            db.session.commit()
            return jsonify({"success": False, "message": "Face unlock disabled after 3 failed attempts"}), 423
        return jsonify({"success": False, "message": f"Face mismatch, attempt {user.face_attempts}/3"}), 401
    
@app.route("/dashboard", methods=["GET", "POST"])
@limiter.limit("20 per minute")
@login_required
def dashboard():
    form = CredentialForm()
    if form.validate_on_submit():
        site_password = form.site_password.data
        password_strength = get_password_strength(site_password)
        encrypted_password = encrypt_password(site_password)

        pwned_count = check_pwned(site_password)
        if pwned_count is None:
            flash("Could not verify password with Have I Been Pwned, try again later", "warning")
        elif pwned_count > 0:
            flash(f"This password was found in {pwned_count} known breaches", "danger")
        else:
            flash("This password was not found in any breaches", "success")

        new_cred = Credential(site=form.site.data, site_username=form.site_username.data, site_password=encrypted_password, strength=password_strength, user_id=current_user.id)
        db.session.add(new_cred)
        db.session.commit()
        flash("Credential saved", "success")
        return redirect(url_for("dashboard"))
    
    credentials = Credential.query.filter_by(user_id=current_user.id).all()
    return render_template("dashboard.html", form=form, credentials=credentials)

@app.route("/reveal_password/<int:cred_id>", methods=["POST"])
@login_required
def reveal_password(cred_id):
    credential = Credential.query.filter_by(id=cred_id, user_id=current_user.id).first_or_404()
    decrypted_password = decrypt_password(credential.site_password)
    return jsonify({"success": True, "password": decrypted_password})

@app.route("/delete/<int:cred_id>", methods=["GET", "POST"])
@login_required
def delete_credential(cred_id):
    cred = Credential.query.filter_by(id=cred_id, user_id=current_user.id).first_or_404()
    db.session.delete(cred)
    db.session.commit()
    flash("Credential deleted", "info")
    return redirect(url_for("dashboard"))

@app.route("/change_password", methods=["GET", "POST"])
@login_required
@limiter.limit("5 per minute")
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if bcrypt.check_password_hash(current_user.password, form.current_password.data):
            hashed_pw = bcrypt.generate_password_hash(form.new_password.data).decode("utf-8")
            current_user.password = hashed_pw
            db.session.commit()
            flash("Your password has been updated", "success")
            return redirect(url_for("profile"))
        else:
            flash("Incorrect current password", "danger")
    return render_template("change_password.html", form=form)

@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = generate_reset_token(user.email)
            reset_url = url_for("reset_password", token=token, _external=True)
            send_reset_email(user.email, reset_url)
            flash(f"A password reset email has been sent to your registered email: {user.email}", "info")
        else:
            flash("Email not found", "danger")
        return redirect(url_for("login"))
    return render_template("forgot_password.html", form=form)

@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    email = verify_reset_token(token)
    if not email:
        flash("The reset link is invalid or has expired", "danger")
        return redirect(url_for("forgot_password"))
    
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=email).first_or_404()
        hashed_pw = bcrypt.generate_password_hash(form.password.data).decode("utf-8")
        user.password = hashed_pw
        db.session.commit()
        flash("Your password has been updated, you can now login", "success")
        return redirect(url_for("login"))
    return render_template("reset_password.html", form=form)

@app.route("/profile")
@limiter.limit("10 per minute")
@login_required
def profile():
    return render_template("profile.html", user=current_user)

@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    session.clear()
    flash("Logged out successfully", "info")
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)