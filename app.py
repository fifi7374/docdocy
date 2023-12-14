from flask import Flask, render_template, url_for, redirect, request, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import InputRequired, Length, Optional
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
from datetime import datetime
import logging
import os
import random
import string
import requests
import uuid

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    # Remove or comment out the email field
    # email = db.Column(db.String(100), nullable=True, unique=True)

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(300))
    path = db.Column(db.String(300))
    access_code = db.Column(db.String(4), unique=True)
    uploader_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    unique_id = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    # Remove or comment out the email field
    # email = StringField(validators=[InputRequired(), Length(max=100)], render_kw={"placeholder": "Email"})
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        access_code = request.form.get('access_code')
        return redirect(url_for('access_document', code=access_code))
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', form=form, error="Invalid username or password.")
    return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    documents = Document.query.filter_by(uploader_id=current_user.id).order_by(Document.uploaded_at.desc()).all()
    return render_template('dashboard.html', documents=documents)

@app.route('/delete_document/<int:doc_id>', methods=['POST'])
@login_required
def delete_document(doc_id):
    doc = Document.query.get(doc_id)
    if doc and doc.uploader_id == current_user.id:
        db.session.delete(doc)
        db.session.commit()
        # Optionally, delete the file from the filesystem
        # os.remove(os.path.join(app.config['UPLOAD_FOLDER'], doc.filename))
    return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            return render_template('register.html', form=form, error="Username already taken.")
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


def generate_access_code():
    return ''.join(random.choices(string.digits, k=4))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        file = request.files['file']
        if file:
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            access_code = generate_access_code()
            existing_doc = Document.query.filter_by(access_code=access_code).first()

            if existing_doc:
                existing_doc.filename = filename
                existing_doc.path = file_path
                existing_doc.uploaded_at = datetime.utcnow()
            else:
                new_doc = Document(
                    filename=filename,
                    path=file_path,
                    access_code=access_code,
                    uploader_id=current_user.id,
                    uploaded_at=datetime.utcnow()
                )
                db.session.add(new_doc)

            db.session.commit()

            # Generate QR code URL
            qr_code_url = generate_qr_code(url_for('access_document', code=access_code, _external=True))

            if qr_code_url:
                # Redirect to upload_success page with access_code and qr_code_url
                return render_template('upload_success.html', access_code=access_code, qr_code_url=qr_code_url)
            else:
                # Handle the scenario when QR code generation fails
                # E.g., show a message to the user, log the error, etc.
                return render_template('upload_success.html', access_code=access_code, qr_code_url=None)

    return render_template('upload.html')





@app.route('/download', methods=['GET', 'POST'])
def download():
    if request.method == 'POST':
        access_code = request.form.get('access_code')
        doc = Document.query.filter_by(access_code=access_code).first()
        if doc:
            return render_template('display_file.html', doc=doc)
    return render_template('home.html', error="Invalid access code")

@app.route('/download_file/<unique_id>')
def download_file(unique_id):
    doc = Document.query.filter_by(unique_id=unique_id).first()
    if doc:
        return send_from_directory(app.config['UPLOAD_FOLDER'], doc.filename, as_attachment=True)
    return 'File not found', 404

@app.route('/access_document/<code>')
def access_document(code):
    doc = Document.query.filter_by(access_code=code).first()
    if doc:
        return render_template('download_document.html', doc=doc)
    return 'Document not found', 404

@app.route('/information')
def information():
    return render_template('information.html')

def generate_qr_code(data):
    try:
        api_url = "https://api.qrserver.com/v1/create-qr-code/"
        params = {'size': '150x150', 'data': data}
        response = requests.get(api_url, params=params)
        if response.status_code == 200:
            return response.url
        else:
            logging.error(f"QR Code API responded with status code: {response.status_code}")
            return None
    except Exception as e:
        logging.error(f"Error occurred while generating QR code: {e}")
        return None

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)