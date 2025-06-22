import os
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from flask_wtf import FlaskForm
from wtforms import PasswordField, SubmitField, StringField
from wtforms.validators import DataRequired, EqualTo
from dotenv import load_dotenv
from cryptography.fernet import Fernet

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cryptnest.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY')
if not ENCRYPTION_KEY:
    ENCRYPTION_KEY = Fernet.generate_key().decode()
    print("Generated dev key", ENCRYPTION_KEY)

fernet = Fernet(ENCRYPTION_KEY.encode())

def encrypt_password(password_plain):
    return fernet.encrypt(password_plain.encode()).decode()

def decrypt_password(password_encrypted):
    return fernet.decrypt(password_encrypted.encode()).decode()

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    master_password = db.Column(db.String(128), nullable=False)

class Credential(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    site = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    password_enc = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Forms
class RegisterForm(FlaskForm):
    password = PasswordField('Master Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    password = PasswordField('Master Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class CredentialForm(FlaskForm):
    site = StringField('Site', validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Save')

# Routes
@app.route('/')
def home():
    if try_face_unlock():
        return redirect(url_for('dashboard'))
    else:
        return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if User.query.first():
        flash('Master password already set. Please login.', 'info')
        return redirect(url_for('login'))
    if form.validate_on_submit():
        hashed_pw = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(master_password=hashed_pw)
        db.session.add(user)
        db.session.commit()
        flash('Master password set! Please login.', 'success')
        return redirect(url_for('login'))   
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    user = User.query.first()
    if not user:
        return redirect(url_for('register'))
    if form.validate_on_submit():
        if bcrypt.check_password_hash(user.master_password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Incorrect master password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    form = CredentialForm()
    if form.validate_on_submit():
        encrypted_pw = encrypt_password(form.password.data)
        new_cred = Credential(
            site=form.site.data,
            username=form.username.data,
            password_enc=encrypted_pw,
            user_id=current_user.id
        )
        db.session.add(new_cred)
        db.session.commit()
        flash("Credential added!", "success")
        return redirect(url_for('dashboard'))
    
    credentials = Credential.query.filter_by(user_id=current_user.id).all()
    for cred in credentials:
        cred.decrypted_password = decrypt_password(cred.password_enc)
    
    return render_template('dashboard.html', form=form, credentials=credentials)

@app.route('/delete/<int:cred_id>', methods=['POST'])
@login_required
def delete_credential(cred_id):
    cred = Credential.query.get_or_404(cred_id)
    if cred.user_id != current_user.id:
        flash("Unauthorized access", "danger")
        return redirect(url_for('dashboard'))
    
    db.session.delete(cred)
    db.session.commit()
    flash("Credential deleted", "info")
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
