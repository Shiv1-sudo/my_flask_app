import json
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
from google.oauth2 import service_account
from flask_mail import Mail, Message
from wtforms.validators import DataRequired, Email
from flask_mail import Mail
from wtforms import TextAreaField, StringField, SubmitField 
import os

# Load environment variables
load_dotenv()
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
csrf.init_app(app)
credentials = service_account.Credentials.from_service_account_file(service_account_path)

def strong_password(form, field):
    password = field.data
    if len(password) < 8 or len(password) > 16:
        raise ValidationError('Password must be between 8 and 16 characters long.')
    if not any(char.isdigit() for char in password):
        raise ValidationError('Password must contain at least one digit.')
    if not any(char.isalpha() for char in password):
        raise ValidationError('Password must contain at least one letter.')
    if not any(char in '!@#$%^&*()_+-=[]{}|;:,.<>?`~' for char in password):
        raise ValidationError('Password must contain at least one special character.')

class DummyForm(FlaskForm):
    pass

# DummyForm for CSRF protection


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])

class SignupForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired(), strong_password])
    phone_number = StringField('Phone Number', validators=[InputRequired()])
    house_address = StringField('House Address', validators=[InputRequired()])
    pincode = StringField('Pincode', validators=[InputRequired()])

class AccountForm(FlaskForm):
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
    form = DummyForm()  # Pass the dummy form to include the CSRF token
    return render_template('main.html', products=products, form=form)

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
    form = AccountForm()
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

@app.route('/category/<category_name>')
def category(category_name):
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products WHERE category = %s", (category_name,))
    products = cursor.fetchall()
    cursor.close()
    form = DummyForm()
    return render_template('main.html', products=products, category=category_name, form=form)

@app.route('/search')
def search():
    query = request.args.get('query')
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products WHERE name LIKE %s", (f"%{query}%",))
    products = cursor.fetchall()
    cursor.close()
    form = DummyForm()
    return render_template('main.html', products=products, form=form)

@app.route('/chat')
def chat():
    form = DummyForm()
    return render_template('chat.html', form=form)

@app.route('/get_response', methods=['POST'])
def get_response():
    try:
        logging.info("Received a request.")

        # Ensure the database connection is active
        if not db.is_connected():
            logging.warning("Database connection lost, attempting to reconnect.")
            db.reconnect(attempts=3, delay=2)

        user_message = request.json.get('message', '').lower()  # Convert to lowercase for easier comparison
        logging.info("User message: %s", user_message)

        # Define a set of greeting messages
        greetings = ["hi", "hello", "hey", "greetings"]

        if user_message in greetings:
            logging.info("Greeting detected.")
            return jsonify({'response': 'Hi there! How can I help you today?'})

        # For other queries, respond with contact information and regards
        logging.info("Handling general query.")
        response_message = (
            "For any queries, please contact duttashivani06@gmail.com for a quick response. "
            "Best regards."
        )
        return jsonify({'response': response_message})
    except mysql.connector.Error as db_err:
        logging.error("Database error in get_response: %s", db_err, exc_info=True)
        return jsonify({'response': 'A database error occurred while processing your request.'})
    except Exception as e:
        logging.error("General error in get_response: %s", e, exc_info=True)
        return jsonify({'response': 'An error occurred while processing your request.'})

@app.route('/add_to_cart/<product_id>', methods=['POST'])
def add_to_cart(product_id):
    cursor = db.cursor()
    # Check if the product is already in the cart
    cursor.execute("SELECT * FROM cart WHERE user_email = %s AND product_id = %s", (session['email'], product_id))
    cart_item = cursor.fetchone()
    
    if cart_item:
        # Update quantity and price
        cursor.execute("UPDATE cart SET quantity = quantity + 1 WHERE user_email = %s AND product_id = %s", (session['email'], product_id))
    else:
        # Insert new product into cart
        cursor.execute("INSERT INTO cart (user_email, product_id, quantity) VALUES (%s, %s, %s)", (session['email'], product_id, 1))
    
    db.commit()
    cursor.close()
    return redirect(url_for('cart'))

@app.route('/cart')
def cart():
    form = DummyForm()
    cursor = db.cursor(dictionary=True)
    query = """
        SELECT cart.id as cart_item_id, cart.product_id, products.image_url, products.name, products.price, cart.quantity, (products.price * cart.quantity) as total_price
        FROM cart 
        JOIN products ON cart.product_id = products.id 
        WHERE cart.user_email = %s
    """
    cursor.execute(query, (session['email'],))
    cart_items = cursor.fetchall()
    cursor.close()
    return render_template('cart.html', cart_items=cart_items, form=form)


@app.route('/remove_from_cart/<int:cart_item_id>', methods=['POST'])
def remove_from_cart(cart_item_id):
    try:
        cursor = db.cursor()
        logging.info("Attempting to decrease quantity for item with ID %s in cart", cart_item_id)

        # Check current quantity
        cursor.execute("SELECT quantity FROM cart WHERE user_email = %s AND id = %s", (session['email'], cart_item_id))
        cart_item = cursor.fetchone()

        if cart_item:
            current_quantity = cart_item[0]  # Use tuple indexing

            if current_quantity > 1:
                # Decrease the quantity by 1
                cursor.execute("UPDATE cart SET quantity = quantity - 1 WHERE user_email = %s AND id = %s", (session['email'], cart_item_id))
            else:
                # Remove the item if quantity is 1
                cursor.execute("DELETE FROM cart WHERE user_email = %s AND id = %s", (session['email'], cart_item_id))
            
            db.commit()
            cursor.close()

            logging.info("Item with ID %s successfully updated/removed from cart", cart_item_id)
            flash('Item updated/removed from cart successfully!')
        else:
            logging.warning("No item with ID %s found in cart", cart_item_id)
            flash('No such item found in your cart.')

    except mysql.connector.Error as err:
        logging.error("Error: %s", err)
        flash('An error occurred while trying to update/remove the item from your cart.')
    return redirect(url_for('cart'))

@app.route('/proceed_to_payment')
def proceed_to_payment():
    form = DummyForm()
    return render_template('ProceedToPayment.html', form=form)

@app.route('/payment', methods=['GET', 'POST'])
def payment():
    if request.method == 'POST':
        payment_method = request.form.get('payment_method')
        return render_template('payment.html', payment_method=payment_method)
    return render_template('ProceedToPayment.html')

@app.route('/process_payment', methods=['POST'])
def process_payment():
    payment_method = request.form.get('payment_method')
    details = request.form.get('details')

    # Convert the details JSON string back to a dictionary
    details = json.loads(details)

    if payment_method == 'cod':
        address = details.get('address')
        pincode = details.get('pincode')
        country_code = details.get('country_code')
        phone = details.get('phone')
        email = details.get('email')
        # Insert the address, pincode, phone, email, and payment method into the orders table
        try:
            cursor = db.cursor()
            query = """
                INSERT INTO orders (user_email, address, pincode, phone, email, payment_method) 
                VALUES (%s, %s, %s, %s, %s, %s)
            """
            cursor.execute(query, (session['email'], address, pincode, country_code + phone, email, payment_method))
            db.commit()
            cursor.close()
            flash('Order placed successfully!')
        except mysql.connector.Error as err:
            logging.error("Error: %s", err)
            flash('An error occurred while placing the order.')
    else:
        card_number = details.get('card_number')
        expiry_date = details.get('expiry_date')
        cvv = details.get('cvv')
        name_on_card = details.get('name_on_card')
        # Add logic to process payment here, e.g., using a payment gateway API
        flash('Payment details saved successfully!')

    return redirect(url_for('proceed_to_payment'))


@app.route('/raise_complaint', methods=['GET', 'POST'])
def raise_complaint():
    if request.method == 'POST':
        flash('For any concerns, please reach out to our support team.')
        return redirect(url_for('raise_complaint'))
    return render_template('raise_complaint.html')


def open_browser():
    if not os.environ.get("FLASK_RUN_FROM_CLI"):
        webbrowser.open_new('http://127.0.0.1:5000/login')

if __name__ == '__main__':
    threading.Timer(2, open_browser).start()
    app.run(debug=True)
