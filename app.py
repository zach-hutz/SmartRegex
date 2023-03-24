from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, get_flashed_messages
from flask_sqlalchemy import SQLAlchemy
from flask_login import current_user, LoginManager, UserMixin, login_required, logout_user, login_user
from werkzeug.security import generate_password_hash, check_password_hash
from apscheduler.schedulers.background import BackgroundScheduler
import atexit
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from email.mime.text import MIMEText
import base64
import os
from datetime import datetime, timedelta
import hashlib
import openai
import requests
import bleach
import uuid
import re
from datetime import timezone
from dotenv import dotenv_values
import os


config = dotenv_values(".env")
app = Flask(__name__)
login_manager = LoginManager()
login_manager.init_app(app)
basedir = os.path.abspath(os.path.dirname(__file__))


app.config['SECRET_KEY'] = config['DB_SECRET']
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
if 'RDS_DB_NAME' in os.environ:
    app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{config["DB_USERNAME"]}:{config["DB_PASSWORD"]}@{config["DB_HOST"]}:{config["DB_PORT"]}/{config["DB_NAME"]}'
else:
    app.config['SQLALCHEMY_DATABASE_URI'] =\
        'sqlite:///' + os.path.join(basedir, 'database.db')
db = SQLAlchemy(app)

openai.api_key = config['CHATGPT_API_KEY']
openai.organization = config['OPENAI_ORG']

class Users(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(128), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    subscription_status = db.Column(db.String(64), default='free')
    transaction_id = db.Column(db.String(64))
    email_confirmed = db.Column(db.String(64), default='False')
    subscription_id = db.Column(db.String(64))


    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

    def __repr__(self):
        return '<User %r>' % self.username
    
    @login_manager.user_loader
    def load_user(user_id):
        return Users.query.get(int(user_id))

class FreeUserQuery(db.Model):
    __tablename__ = 'free_user_queries'

    hashed_ip_address = db.Column(db.String, primary_key=True)
    query_count = db.Column(db.Integer, nullable=False)
    last_query_date = db.Column(db.Date, nullable=False)


def remove_old_free_user_queries():
    week_ago = datetime.now(timezone.utc).date() - timedelta(days=7)
    old_queries = FreeUserQuery.query.filter(FreeUserQuery.last_query_date <= week_ago).all()

    for query in old_queries:
        db.session.delete(query)

    db.session.commit()

def is_valid_email(email):
    email_regex = re.compile(
        r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
    )
    return bool(email_regex.match(email))

def send_email(subject, body, to):
    service_account_file = config['SERVICE_AUTH']

    credentials = service_account.Credentials.from_service_account_file(service_account_file, scopes=['https://www.googleapis.com/auth/gmail.send'])

    delegated_credentials = credentials.with_subject(config['EMAIL'])

    try:
        service = build('gmail', 'v1', credentials=delegated_credentials)

        message = MIMEText(body)
        message['to'] = to
        message['subject'] = subject
        create_message = {'raw': base64.urlsafe_b64encode(message.as_bytes()).decode()}

        send_message = (service.users().messages().send(userId="me", body=create_message).execute())
        print(F'sent message to {to} Message Id: {send_message["id"]}')
    except HttpError as error:
        print(F'An error occurred: {error}')
        send_message = None
    return send_message

def get_hashed_ip_address(ip_address):
    sha256 = hashlib.sha256()
    sha256.update(ip_address.encode())
    return sha256.hexdigest()

def get_week_start_date(date):
    return date - timedelta(days=date.weekday())

def sanitize_input(input):
    return bleach.clean(input)

scheduler = BackgroundScheduler()
scheduler.add_job(func=remove_old_free_user_queries, trigger="interval", days=1)
scheduler.start()
atexit.register(lambda: scheduler.shutdown())

tokens = {}

@app.errorhandler(401)
def unauthorized_error(error):
    return redirect(url_for('index'))

@app.errorhandler(404)
def file_not_found_error(error):
    return render_template('404.html')

@app.route('/')
def index():
    if not current_user.is_authenticated:
        return render_template('index.html')
    if current_user.subscription_status == 'pro':
        return redirect(url_for('pro'))
    messages = get_flashed_messages()
    message = messages[0] if messages else None
    return render_template('index.html', user=f'Hello, {current_user.username}', message=message)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


def get_client_ip():
    if request.headers.get("CF-Connecting-IP"):
        return request.headers.get("CF-Connecting-IP")
    elif request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For")
    else:
        return request.remote_addr


@app.route('/update_profile', methods=['POST', 'GET'])
@login_required
def update_profile():
    if not current_user.is_authenticated:
        return jsonify({'error': "Can't change a profile that doesn't exist."})
    
    dirty_new_password = request.get_json()['new_password']
    new_password = sanitize_input(dirty_new_password)
    hashed_password = generate_password_hash(new_password, method='sha256')
    current_user.password_hash = hashed_password
    db.session.commit()
    send_email('ACCOUNT UPDATE - Password Change', 'The password for your account has just been changed.', current_user.email)
    return jsonify({'success':'Password changed!'})

@app.route('/update_email', methods=['POST'])
def update_email():
    if not current_user.is_authenticated:
        return jsonify({'error': 'Cannot change email while not logged in.'})
    dirty_new_email = request.form['new_email']
    new_email = sanitize_input(dirty_new_email)

    if not is_valid_email(new_email):
        return jsonify({'error': f'{new_email} is not a valid email address!'})
    user = current_user

    # Generate a token and store it with the user's ID
    token = uuid.uuid4().hex
    tokens[token] = user.id

    # Send an email with the token
    subject = "Confirm your new email address"
    body = f"Please confirm your new email address by clicking the following link: {url_for('confirm_email', token=token, new_email=new_email, _external=True)}"
    send_email(subject, body, new_email)

    return jsonify({"success": "An email has been sent to your new address for confirmation."})

@app.route('/confirm_email/<token>')
def confirm_email(token):
    user_id = tokens.get(token)

    if user_id is None:
        flash("Token expired or not found. Please try again.")
        return redirect(url_for('profile'))

    user = Users.query.filter_by(id=user_id).first()

    if user is None:
        flash("User not found.")
        return redirect(url_for('profile'))

    # Update the email address and save the changes
    dirty_email = request.args.get('new_email')
    new_email = sanitize_input(dirty_email)
    if user.email_confirmed == "False":
        if user.email != new_email:
            return redirect(url_for('index'))
        user.email = new_email
        user.email_confirmed = 'True'
        db.session.commit()
        del tokens[token]
        flash("Email has been confirmed!")
        return redirect(url_for('index'))
    else:
        user.email = new_email
        db.session.commit()
        del tokens[token]
        flash("Email has been confirmed and is now changed!")
        return redirect(url_for('profile'))

@app.route('/profile')
@login_required
def profile():
    if not current_user.is_authenticated:
        return redirect(url_for('index'))
    messages = get_flashed_messages()
    message = messages[0] if messages else None
    return render_template('profile.html', user=current_user, message=message)

@app.route('/benefits')
def benefits():
    if current_user.is_authenticated:

        return render_template('benefits.html', user=current_user.username)
    else:
        return render_template('benefits.html', user="Guest")


@app.route('/payment', methods=['GET', 'POST'])
@login_required
def payment():
    return render_template('payment.html')

@app.route('/privacy', methods=['GET', 'POST'])
def privacy():
    return render_template('privacy.html')

@app.route('/payment_successful', methods=['POST'])
@login_required
def payment_successful():
    user_id = current_user.id
    dirty_transaction_id = request.get_json()['transaction_id']
    transaction_id = sanitize_input(dirty_transaction_id)

    subscription_id = request.get_json()['subscription_id']

    if user := Users.query.filter_by(id=user_id).first():
        user.subscription_status = 'pro'
        user.transaction_id = transaction_id
        user.subscription_id = subscription_id
        db.session.commit()
        send_email('ACCOUNT UPGRADE', "The Pro subscription has been succesfully added to your account!", current_user.email)
    else:
        return jsonify({"error": "User not found"}), 404

    return jsonify({'success': "Account upgraded!"})

@app.route('/cancel_subscription', methods=['POST'])
@login_required
def cancel_subscription():
    subscription_id = current_user.subscription_id
    client_id = config['PP_CLIENT_ID']
    client_secret = config['PP_CLIENT_SECRET']

    auth_response = requests.post(
        'https://api.paypal.com/v1/oauth2/token',
        auth=(client_id, client_secret),
        data={'grant_type': 'client_credentials'}
    )

    access_token = auth_response.json()['access_token']

    cancel_response = requests.post(
        f'https://api.paypal.com/v1/billing/subscriptions/{subscription_id}/cancel',
        headers={'Authorization': f'Bearer {access_token}'},
        json={"reason": "User requested cancellation"}
    )

    print(cancel_response.status_code)
    if cancel_response.status_code != 204:
        error_message = "Unknown error"
        if cancel_response.headers.get('Content-Type') == 'application/json':
            error_message = cancel_response.json().get("message", "Unknown error")
        return jsonify({"status": "error", "error": error_message})

    current_user.subscription_status = "free"
    db.session.commit()
    return jsonify({"status": "success"})

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        dirty_username_or_email = request.form.get('username_or_email')
        dirty_password = request.form.get('password')

        username_or_email = sanitize_input(dirty_username_or_email)
        password = sanitize_input(dirty_password)


        user = Users.query.filter(
            (Users.email == username_or_email) | (Users.username == username_or_email)
        ).first()

        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('index'))
        else: 
            error = 'Invalid username/email or password.'

    return render_template('login.html', error=error)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    error = None
    if request.method == 'POST':
        dirty_username = request.form.get('username')
        username = sanitize_input(dirty_username)

        dirty_email = request.form.get('email')
        email = sanitize_input(dirty_email)

        dirty_password = request.form.get('password')
        password = sanitize_input(dirty_password)

        dirty_confirm_password = request.form.get('confirm_password')
        confirm_password = sanitize_input(dirty_confirm_password)

        dirty_subscription = request.form.get('subscription')
        subscription = sanitize_input(dirty_subscription)
        
        if password != confirm_password:
            error = 'Passwords do not match.'
        elif not (is_valid_email(email)):
            error = 'Email not valid.'
        elif existing_user := Users.query.filter(
            (Users.username == username) | (Users.email == email)
        ).first():
            if existing_user.username == username:
                error = 'Username already exists.'
            elif existing_user.email == email:
                error = 'Email already exists.'
        if error is None:
            hashed_password = generate_password_hash(password, method='sha256')
            new_user = Users(username=username, email=email, password_hash=hashed_password, subscription_status='free', email_confirmed='False')
            db.session.add(new_user)
            db.session.commit()

            token = uuid.uuid4().hex
            tokens[token] = new_user.id

            subject = "Confirm your email address"
            body = f"Please confirm your email address by clicking the following link: {url_for('confirm_email', token=token, new_email=email, _external=True)}"
            send_email(subject, body, email)

            if subscription == 'paid':
                return redirect(url_for('payment'))
            return redirect(url_for('login'))
    return render_template('signup.html', error=error)

@app.route('/forgot_password', methods=['POST'])
def forgot_password():
    # TODO
    pass

@app.route('/pro')
@login_required
def pro():
    if current_user.subscription_status == 'pro':
        return render_template('pro.html', user=f'Hello, {current_user.username}')
    else:
        return redirect(url_for('index'))

@app.route('/generate_regex', methods=['POST'])
def generate_regex():
    if (
        current_user.is_authenticated
        and current_user.email_confirmed == "False"
    ):
        token = uuid.uuid4().hex
        tokens[token] = current_user.id
        subject = "Confirm your email address"
        body = f"Please confirm your email address by clicking the following link: {url_for('confirm_email', token=token, new_email=current_user.email, _external=True)}"
        send_email(subject, body, current_user.email)
        return jsonify({'error':'Please click the link in your email to verify.'})
    dirty_input_text = request.form.get("input_text")
    input_text = sanitize_input(dirty_input_text)

    dirty_explanation = request.form.get("explanation")
    explanation = sanitize_input(dirty_explanation)

    dirty_recaptcha_response = request.form.get("recaptcha_response")
    recaptcha_response = sanitize_input(dirty_recaptcha_response)

    recaptcha_data = {"secret": config['GOOGLE_KEY'], "response": recaptcha_response}
    recaptcha_url = "https://www.google.com/recaptcha/api/siteverify"
    verification_response = requests.post(recaptcha_url, data=recaptcha_data)
    verification_result = verification_response.json()

    if not verification_result["success"]:
        return jsonify({"error": "reCAPTCHA verification failed"}), 400

    dirty_input_text = request.form['input_text']
    input_text = sanitize_input(dirty_input_text)

    dirty_explanation = request.form['explanation']
    explanation = sanitize_input(dirty_explanation)

    ip_address = get_client_ip()
    hashed_ip_address = get_hashed_ip_address(ip_address)
    now = datetime.now(timezone.utc).date()
    week_start_date = get_week_start_date(now)

    free_user_query = FreeUserQuery.query.filter_by(hashed_ip_address=hashed_ip_address).first()

    if free_user_query:

        last_query_week_start_date = get_week_start_date(free_user_query.last_query_date)

        if week_start_date > last_query_week_start_date:
            free_user_query.query_count = 1
        else:
            free_user_query.query_count += 1

        free_user_query.last_query_date = now
    else:

        free_user_query = FreeUserQuery(
            hashed_ip_address=hashed_ip_address,
            query_count=1,
            last_query_date=now
        )
        db.session.add(free_user_query)

    db.session.commit()

    if free_user_query.query_count <= 3:
        try:
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a helpful assistant that generates regex patterns. You will strictly follow your Task and give regex that does that exact solution for the Input text."},
                    {"role": "user", "content": f"Input text: {input_text}"},
                    {"role": "user", "content": f"Task: {explanation}"},
                    {"role": "assistant", "content": "Please provide the regex pattern without any additional text. Do not say Regex pattern: "}
                ],         
                max_tokens=50,
                n=1,
                )
        except Exception as e:
            return jsonify({"error": f"Unable to fetch regex from ChatGPT: {str(e)}"}), 500

        regex = response.choices[0].message['content'].strip()
        return jsonify({"regex": regex})
    else:
        last_query_date = free_user_query.last_query_date
        days_passed = (now - last_query_date).days

        if days_passed >= 7:
            remaining_days = 0
            remaining_hours = 0
        else:
            remaining_days = 6 - days_passed
            remaining_hours = 24 - datetime.now(timezone.utc).hour
        message = f"You have used up all of your queries for this week. Upgrade to Pro, or you can try again in {remaining_days} day(s) and {remaining_hours} hour(s)."
        return jsonify({'error': 'Out of queries.', 'message':message})

@app.route('/generate_regex_pro', methods=['POST'])
def generate_regex_pro():
    if (
        not current_user.is_authenticated
        or current_user.subscription_status != 'pro'
    ):
        return jsonify({'error': 'Good try.'})
    if current_user.email_confirmed == "False":
        token = uuid.uuid4().hex
        tokens[token] = current_user.id
        subject = "Confirm your email address"
        body = f"Please confirm your email address by clicking the following link: {url_for('confirm_email', token=token, new_email=current_user.email, _external=True)}"
        send_email(subject, body, current_user.email)
        return jsonify({'error': 'Please click the link in your email to verify your account.'})
    dirty_input_text = request.form.get("input_text")
    input_text = sanitize_input(dirty_input_text)

    dirty_explanation = request.form.get("explanation")
    explanation = sanitize_input(dirty_explanation)

    dirty_model = request.form.get("model")
    model = sanitize_input(dirty_model)

    dirty_input_text = request.form['input_text']
    input_text = sanitize_input(dirty_input_text)

    dirty_explanation = request.form['explanation']
    explanation = sanitize_input(dirty_explanation)

    dirty_model = request.form['model']
    model = sanitize_input(dirty_model)
    if Users.query.filter_by(id=current_user.id).first().subscription_status == 'pro':
        try:
            response = openai.ChatCompletion.create(
                model=model,
                messages=[
                    {"role": "system", "content": "You are a helpful assistant that generates regex patterns. You will strictly follow your Task and give regex that does that exact solution for the Input text."},
                    {"role": "user", "content": f"Input text: {input_text}"},
                    {"role": "user", "content": f"Task: {explanation}"},
                    {"role": "assistant", "content": "Please provide the regex pattern without any additional text. Do not say Regex pattern: "}
                ],         
                max_tokens=50,
                n=1,
                )
        except Exception as e:
            return jsonify({"error": f"Unable to fetch regex from ChatGPT: {str(e)}"}), 500

        regex = response.choices[0].message['content'].strip()
        return jsonify({"regex": regex})
    else:
        return jsonify({'error': 'good try.'})

if __name__ == '__main__':
    with app.app_context():  
        db.create_all()  
    app.run()