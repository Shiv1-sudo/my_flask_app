from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import webbrowser
import threading
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm, CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from wtforms import StringField, PasswordField, ValidationError
from wtforms.validators import InputRequired
import mysql.connector
from mysql.connector import Error
import redis
import logging
from dotenv import load_dotenv
from google.cloud import dialogflow
from google.cloud import dialogflow
from google.oauth2 import service_account
import os

# Load environment variables
load_dotenv()
# Get the path to the service account file from the environment variable
service_account_path = os.getenv('GOOGLE_APPLICATION_CREDENTIALS')

# Logging configuration
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key')

# Database configuration
try:
    db = mysql.connector.connect(
        host=os.getenv('DB_HOST'),
        user=os.getenv('DB_USER'),
        password=os.getenv('DB_PASSWORD'),
        database=os.getenv('DB_NAME')
    )
    if db.is_connected():
        logging.info("Connected to MySQL database")
        db_Info = db.get_server_info()
        logging.info("MySQL Server version on %s", db_Info)
except Error as e:
    logging.error("Error while connecting to MySQL: %s", e)

# Check and connect to Redis
redis_url = os.getenv('REDIS_URL')
if redis_url:
    redis_connection = redis.StrictRedis.from_url(redis_url)
else:
    raise EnvironmentError("REDIS_URL environment variable not set.")

limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=redis_url,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

csrf = CSRFProtect(app)
csrf.init_app(app)  # Initialize CSRF protection

#Load Dialogflow credentials #Google Cloud API
#path not to harcode will call from config file 
#(E:\STUDY MATerial\my_flask_app\dialogflow-service-account.json")
credentials=service_account.Credentials.from_service_account_file(service_account_path)

# Custom password validator
def strong_password(form, field):
    password = field.data
    if len(password) < 8 or len(password) > 16:
        raise ValidationError('Password must be between 8 and 16 characters long.')
    if not any(char.isdigit() for char in password):
        raise ValidationError('Password must contain at least one digit.')
    if not any(char.isalpha() for char in password):
        raise ValidationError('Password must contain at least one letter.')
    if not any (char in '!@#$%^&*()_+-=[]{}|;:,.<>?`~' for char in password):
        raise ValidationError('Password must contain at least one special character.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])

class SignupForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired(), strong_password])
    phone_number = StringField('Phone Number', validators=[InputRequired()])
    house_address = StringField('House Address', validators=[InputRequired()])
    pincode = StringField('Pincode', validators=[InputRequired()])

class AccountForm(FlaskForm):  # Added new form for account updates with password validation
    password = PasswordField('Password', validators=[InputRequired(), strong_password])
    phone_number = StringField('Phone Number', validators=[InputRequired()])
    house_address = StringField('House Address', validators=[InputRequired()])
    pincode = StringField('Pincode', validators=[InputRequired()])

@app.route('/')
def home():
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products")
    products = cursor.fetchall()
    cursor.close()
    return render_template('main.html', products=products)

@app.route('/category/<category_name>')
def category(category_name):
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products WHERE category = %s", (category_name,))
    products = cursor.fetchall()
    cursor.close()
    return render_template('main.html', products=products, category=category_name)

@app.route('/search')
def search():
    query = request.args.get('query')
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products WHERE name LIKE %s", (f"%{query}%",))
    products = cursor.fetchall()
    cursor.close()
    return render_template('main.html', products=products)

@app.route('/chat')
def chat():
    # Render a template for the chat interface
    return render_template('chat.html')

@app.route('/get_response', methods=['POST'])
def get_response():
    user_message = request.json.get('message')
    session_client = dialogflow.SessionsClient(credentials=credentials)
    session = session_client.session_path('your-dialogflow-project-id', 'unique-session-id')

    text_input = dialogflow.TextInput(text=user_message, language_code='en')
    query_input = dialogflow.QueryInput(text=text_input)
    response = session_client.detect_intent(session=session, query_input=query_input)
    
    return jsonify({'response': response.query_result.fulfillment_text})

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    form = LoginForm()
    if request.method == 'POST' and form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        cursor = db.cursor()
        cursor.execute("SELECT password FROM users WHERE email = %s", (email,))
        result = cursor.fetchone()

        if result:
            if check_password_hash(result[0], password):
                session['email'] = email
                flash('Welcome back!')
                return redirect(url_for('home'))
            else:
                flash('Invalid credentials. Please try again.')
        else:
            flash('No account found with this email. Please sign up.')
            return redirect(url_for('signup'))

    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def signup():
    form = SignupForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            email = form.email.data
            password = form.password.data
            phone_number = form.phone_number.data
            house_address = form.house_address.data
            pincode = form.pincode.data

            hashed_password = generate_password_hash(password)
            cursor = db.cursor()
            cursor.execute("""
                INSERT INTO users (email, password, phone_number, house_address, pincode)
                VALUES (%s, %s, %s, %s, %s)
            """, (email, hashed_password, phone_number, house_address, pincode))
            db.commit()
            cursor.close()
            flash('Registration successful! Please sign in.')
            return redirect(url_for('login'))
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f"Error in {getattr(form, field).label.text}: {error}")

    return render_template('signup.html', form=form)

@app.route('/account', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def account():
    form = AccountForm()  # Use the new AccountForm for account updates
    if 'email' not in session:
        return redirect(url_for('login'))

    email = session['email']

    if request.method == 'POST':
        if form.validate_on_submit():
            password = form.password.data
            phone_number = form.phone_number.data
            house_address = form.house_address.data
            pincode = form.pincode.data

            hashed_password = generate_password_hash(password)
            cursor = db.cursor()
            cursor.execute("""
                UPDATE users
                SET password = %s, phone_number = %s, house_address = %s, pincode = %s
                WHERE email = %s
            """, (hashed_password, phone_number, house_address, pincode, email))
            db.commit()
            cursor.close()
            flash('Account details updated successfully!')
            return redirect(url_for('account'))
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f"Error in {getattr(form, field).label.text}: {error}")

    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()
    cursor.close()
    return render_template('account.html', user=user, form=form)

def open_browser():
    if not os.environ.get("FLASK_RUN_FROM_CLI"):
        webbrowser.open_new('http://127.0.0.1:5000/login')

if __name__ == '__main__':
    threading.Timer(2, open_browser).start()
    app.run(debug=True)
