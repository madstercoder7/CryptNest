import os
import re
import base64
import numpy as np
import json
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, flash, request, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate # type: ignore
from sqlalchemy import or_
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from flask_wtf import FlaskForm
from wtforms import PasswordField, SubmitField, StringField, EmailField
from wtforms.validators import DataRequired, EqualTo
from dotenv import load_dotenv
from cryptography.fernet import Fernet
from utils import get_password_strength, check_pwned
from scipy.spatial.distance import euclidean # type: ignore

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY') 
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("SQLALCHEMY_DATABASE_URI")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

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

# Routes
@app.route('/')
def home():
    return render_template("landing.html")

@app.route("/register", methods=["GET", "POST"])
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

@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    session.clear()
    flash("Logged out successfully", "info")
    return redirect(url_for("login"))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)