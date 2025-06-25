import os
from flask import Flask, render_template, redirect, url_for, flash, request, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from flask_wtf import FlaskForm
from wtforms import PasswordField, SubmitField, StringField
from wtforms.validators import DataRequired, EqualTo
from dotenv import load_dotenv
from cryptography.fernet import Fernet
from face_unlock import capture_face_temp, move_temp_face_to_user, verify_face_against_encodings
from utils import get_password_strength, check_pwned, capture_intrusion_screenshot

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY') or 'devkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cryptnest.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
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
    password = db.Column(db.String(128), nullable=False)

class Credential(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    site = db.Column(db.String(100), nullable=False)
    site_username = db.Column(db.String(100), nullable=False)
    site_password = db.Column(db.Text, nullable=False)
    strength = db.Column(db.String(10))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Load user for login manager
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Forms
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
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

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    temp_path = os.path.join("face_data", "temp_face.npy")

    if request.method == 'GET' and not session.get('face_captured'):
        session.pop('face_captured', None)
        if os.path.exists(temp_path):
            os.remove(temp_path)

    if request.method == 'POST' and 'capture_face' in request.form:
        success = capture_face_temp()
        if success and os.path.exists(temp_path):
            session['face_captured'] = True
            flash("✅ Face captured successfully", "success")
        else:
            session.pop('face_captured', None)
            flash("❌ Face capture failed. Try again.", "danger")
        return redirect(url_for('register'))

    if request.method == 'POST' and 'submit' in request.form:
        if form.validate_on_submit():
            existing_user = User.query.filter_by(username=form.username.data).first()
            if existing_user:
                flash("❌ Username already exists. Try another one.", "danger")
                return redirect(url_for('register'))

            hashed_pw = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user = User(username=form.username.data, password=hashed_pw)
            db.session.add(user)
            db.session.commit()

            if session.get('face_captured'):
                try:
                    move_temp_face_to_user(user.id)
                    session.pop('face_captured', None)
                except Exception:
                    flash("⚠️ Registered, but face could not be saved.", "warning")

            flash("✅ Registration successful. Please login.", "success")
            return redirect(url_for('login'))
        else:
            flash("❌ Form validation failed. Please check your input.", "danger")

    return render_template("register.html", form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST':
        if 'face_unlock' in request.form:
            matched_user_id = verify_face_against_encodings()
            if matched_user_id:
                user = db.session.get(User, matched_user_id)
                if user:
                    login_user(user)
                    flash('Logged in using face unlock.', 'success')
                    session.pop('face_attempts', None)
                    return redirect(url_for('dashboard'))
            
            session['face_attempts'] = session.get('face_attempts', 0) + 1
            if session['face_attempts'] >= 3:
                capture_intrusion_screenshot()
                session['face_attempts'] = 0
                flash("Suspicious activity detected. Screenshot saved", "danger")
            else:
                flash("Face not recognized, try manual login", "warning")
            return redirect(url_for('login'))

        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()
            if user and bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                flash('Login successful.', 'success')
                session.pop('face_attempts', None)
                return redirect(url_for('dashboard'))
            else:
                flash('Incorrect username or password.', 'danger')

    return render_template('login.html', form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = CredentialForm()
    credentials = Credential.query.filter_by(user_id=current_user.id).all()

    if form.validate_on_submit():
        site_password = form.site_password.data
        password_strength = get_password_strength(form.site_password.data)
        encrypted_pw = encrypt_password(site_password)

        pwned_count = check_pwned(site_password)
        if pwned_count is None:
            flash("⚠️ Could not verify password with HIBP. Try again later", "warning")
        elif pwned_count > 0:
            flash(f"🚨This password was for in {pwned_count} known breaches! Consider using a safer one", "danger")
        else:
            flash("✅ This password was not found in any breaches", "success")

        new_cred = Credential(
            site=form.site.data,
            site_username=form.site_username.data,
            site_password=encrypted_pw,
            strength=password_strength,
            user_id=current_user.id
        )
        db.session.add(new_cred)
        db.session.commit()
        flash('Credential saved', 'success')
        return redirect(url_for('dashboard'))

    credentials = Credential.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', form=form, credentials=credentials)

@app.route('/reveal_password/<int:cred_id>', methods=['POST'])
@login_required
def reveal_password(cred_id):
    credential = Credential.query.filter_by(id=cred_id, user_id=current_user.id).first_or_404()
    decrypted_password = decrypt_password(credential.site_password)
    return jsonify({"password": decrypted_password})

@app.route('/delete/<int:cred_id>', methods=['GET', 'POST'])
@login_required
def delete_credential(cred_id):
    cred = Credential.query.filter_by(id=cred_id, user_id=current_user.id).first_or_404()
    db.session.delete(cred)
    db.session.commit()
    flash('Credential deleted', 'info')
    return redirect(url_for('dashboard'))

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for('login'))

# Run the app
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
