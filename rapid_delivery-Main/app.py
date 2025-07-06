from flask import Flask, request, jsonify, session, render_template, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_cors import CORS
from flask_session import Session
import os
import random
import psycopg2
from psycopg2 import sql
from datetime import datetime, timedelta, timezone
import jwt
from jwt.exceptions import PyJWTError
from functools import wraps
from twilio.rest import Client

app = Flask(__name__)
CORS(app)

SECRET_KEY='this is jwt'
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

# Twilio credentials
account_sid = ""
auth_token = ""
verify_sid = ''  # Your Twilio Verify Service SID
client = Client(account_sid, auth_token)

DB_HOST = 'localhost'
DB_NAME = 'postgres'
DB_USER = 'postgres'
DB_PASSWORD = '122333'

def get_db_connection():
    connection = psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )
    return connection

def create_customers_table_if_not_exist():
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS customers (
            id SERIAL PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            phone_number TEXT NOT NULL
        );
    """)
    connection.commit()
    cursor.close()
    connection.close()

def create_tables_if_not_exist():
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS items (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            price REAL NOT NULL,
            discount_price REAL NOT NULL,
            type TEXT NOT NUll,
            quantity INTEGER NOT NULL,
            description TEXT NOT NULL,
            restaurant_id INTEGER NOT NULL,
            restaurant_name TEXT NOT NULL,
            image_paths TEXT NOT NULL  
        );
    """)
    connection.commit()
    cursor.close()
    connection.close()

def create_reviews_table():
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
      CREATE TABLE IF NOT EXISTS reviews (
            id SERIAL PRIMARY KEY,
            item_id INTEGER NOT NULL REFERENCES items(id),
            username VARCHAR(255) NOT NULL,
            rating DECIMAL(2,1) NOT NULL CHECK (rating >= 1 AND rating <= 5),
            description TEXT,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
    """)
    connection.commit()
    cursor.close()
    connection.close()

def create_restaurant_table():
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
      CREATE TABLE IF NOT EXISTS restaurants (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            password TEXT NOT NULL,
            address TEXT NOT NULL,
            phone_number TEXT NOT NULL,
            description TEXT NOT NULL,
            payment_method TEXT NOT NULL,
            logo TEXT NOT NULL
        );
    """)
    connection.commit()
    cursor.close()
    connection.close()
    
create_tables_if_not_exist()
create_reviews_table()
create_restaurant_table()
create_customers_table_if_not_exist()

@app.route('/user/signup', methods=['POST'])
def register():
    username = request.json.get('username')
    email = request.json.get('email')
    password = request.json.get('password')
    phone_number = request.json.get('phone_number')
    print(email)
    if not username or not email or not password or not phone_number:
        return jsonify({"error": "Check the entered details properly"}), 400

    hashed_password = generate_password_hash(password)
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("""
            INSERT INTO customers(username, email, password, phone_number) VALUES(%s, %s, %s, %s);
        """, (username, email, hashed_password, phone_number))
        connection.commit()
        cursor.close()
        connection.close()
        return jsonify({"message": "User registered successfully"}), 201
    except psycopg2.IntegrityError:
        return jsonify({"error": "Username or email already exists"}), 409
    except Exception as e:
        return jsonify({"error": f"An unexpected error occurred: {e}"}), 500

@app.route('/user/login', methods=['POST'])
def signin():
    email = request.json.get('email')
    password = request.json.get('password')
    if not email or not password:
        return jsonify({"success": False, "error": "Both email and password are required"}), 400

    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT id, username, password FROM customers WHERE email=%s;
            """, (email,))
            user = cursor.fetchone()
        
        if not user or not check_password_hash(user[2], password):
            return jsonify({"success": False, "error": "Invalid email or password"}), 401

        expiration_time = datetime.now(timezone.utc) + timedelta(days=1)
        token = jwt.encode({
            'username': user[1],
            'id': user[0],
            'exp': expiration_time,
            'iat': datetime.now(timezone.utc)
        }, SECRET_KEY, algorithm='HS256')

        return jsonify({"success": True, "message": "User signed in successfully", "token": token}), 200

    except psycopg2.Error as db_err:
        return jsonify({"success": False, "error": "Database error occurred.", "details": str(db_err)}), 500
    except jwt.PyJWTError as jwt_err:
        return jsonify({"success": False, "error": "Token generation error.", "details": str(jwt_err)}), 500
    except Exception as e:
        return jsonify({"success": False, "error": "An unexpected error occurred."}), 500
    finally:
        connection.close()

@app.route("/restaurant/login", methods=["POST"])
def restaurant_login():
    email = request.json.get("email")
    password = request.json.get("password")

    if not email or not password:
        return jsonify({"error": "Both email and password are required"}), 400

    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute("SELECT name, id, password,logo FROM restaurants WHERE email=%s;", (email,))
            restaurant = cursor.fetchone()

        if not restaurant:
            return jsonify({"error": "User not found"}), 404

        if restaurant[2] != password:  # Ideally, compare hashed passwords
            return jsonify({"error": "Invalid email or password"}), 401

        # Use timezone-aware datetime for UTC
        current_utc = datetime.now(timezone.utc)
        expiration_time = current_utc + timedelta(days=1)

        token = jwt.encode({
            "name": restaurant[0],
            "logo":restaurant[3],
            "id": restaurant[1],
            "exp": expiration_time,
            "iat": current_utc
        }, SECRET_KEY, algorithm="HS256")
        return jsonify({"message": "Restaurant signed in successfully", "token": token}), 200

    except psycopg2.Error as db_err:
        print(f"Database error: {db_err}")
        return jsonify({"error": "Database error occurred.", "details": str(db_err)}), 500
    except jwt.PyJWTError as jwt_err:
        print(f"JWT Error: {jwt_err}")
        return jsonify({"error": "Token generation error.", "details": str(jwt_err)}), 500
    except Exception as e:
        print(f"Unexpected error: {e}")
        return jsonify({"error": "An unexpected error occurred."}), 500
    finally:
        if connection:
            connection.close()
        
@app.route("/restaurant/signup", methods=["POST"])
def restaurant_signup():
    name = request.form.get("name")
    email = request.form.get("email")
    password = request.form.get("password")
    address = request.form.get("address")
    phone_number = request.form.get("phone_number")
    description = request.form.get("description")
    payment_method = request.form.get("payment_method")
    logo_file = request.files.get("logo")

    if not all([name, email, password, address, phone_number, description, payment_method, logo_file]):
        return jsonify({"error": "All fields are required"}), 400

    # Save logo file
    filename = secure_filename(logo_file.filename)
    logo_path = os.path.join("uploads", filename)
    logo_file.save(logo_path)

    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("""
            INSERT INTO restaurants (name, email, password, address, phone_number, description, payment_method, logo)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
        """, (name, email, password, address, phone_number, description, payment_method, logo_path))
        connection.commit()
        cursor.close()
        connection.close()
        return jsonify({"message": "Restaurant registered successfully"}), 201
    except psycopg2.IntegrityError:
        return jsonify({"error": "Email already exists"}), 409
    except Exception as e:
        return jsonify({"error": f"An unexpected error occurred: {e}"}), 500
               
      
def verify_token():
    token = None
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization']
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
    
    if not token:
        return None, jsonify({"message": "Token is missing!"}), 403

    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        print(decoded)
        return decoded, None, None
    except jwt.ExpiredSignatureError:
        return None, jsonify({"message": "Token expired!"}), 401
    except jwt.InvalidTokenError:
        return None, jsonify({"message": "Invalid token!"}), 401

import traceback

from flask import Flask, request, jsonify
import traceback

@app.route("/items", methods=["GET"])
def get_items():
    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        # Get filters from request
        search = request.args.get('search', default="", type=str)
        category = request.args.get('category', default="", type=str)
        min_price = request.args.get('min_price', default=None)
        max_price = request.args.get('max_price', default=None)
        print(min_price)
        # Build SQL query with filters
        query = "SELECT * FROM items WHERE 1=1"
        params = []

        if search:
            query += " AND name ILIKE %s"
            params.append(f"%{search}%")
        if category:
            query += " AND type = %s"
            params.append(category)
        if min_price is not None:
            query += " AND discount_price >= %s"
            params.append(min_price)
        if max_price is not None:
            query += " AND discount_price <= %s"
            params.append(max_price)

        cursor.execute(query, tuple(params))
        rows = cursor.fetchall()
        columns = [desc[0] for desc in cursor.description]
        cursor.close()
        connection.close()

        # Convert rows to list of dicts
        items_list = []
        for row in rows:
            item = dict(zip(columns, row))
            items_list.append({
                "id": item["id"],
                "name": item["name"],
                "description": item.get("description", ""),
                "price": float(item["price"]),
                "discount_price": float(item["discount_price"]) if item["discount_price"] is not None else None,
                "type": item["type"],
                "quantity": item["quantity"],
                "images": item["image_paths"].split(',') if item.get("image_paths") else [],
                "restaurant_id": item["restaurant_id"],
                "restaurant_name": item["restaurant_name"]
            })
        print(items_list)
        return jsonify(items_list)

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/restaurant/items", methods=["GET"])
def get_items_by_restaurant():
    try:
        payload = verify_token()
        print(payload)
        restaurant_id = payload[0].get("id") if payload else None
        if not restaurant_id:
            return jsonify({"error": "restaurant_id not found in token"}), 400

        # DB fetch
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute("SELECT * FROM items WHERE restaurant_id = %s", (restaurant_id,))
        rows = cursor.fetchall()
        columns = [desc[0] for desc in cursor.description]
        cursor.execute("SELECT logo FROM restaurants WHERE id = %s", (restaurant_id,))
        restaurant_logo = cursor.fetchone()
        cursor.close()
        connection.close()

        items_list = []
        for row in rows:
            item = dict(zip(columns, row))
            items_list.append({
                "id": item["id"],
                "name": item["name"],
                "description": item.get("description", ""),
                "price": float(item["price"]),
                "discount_price": float(item["discount_price"]) if item["discount_price"] is not None else None,
                "type": item["type"],
                "quantity": item["quantity"],
                "images": item["image_paths"].split(',') if item.get("image_paths") else [],
                "restaurant_id": item["restaurant_id"],
                "restaurant_name": item["restaurant_name"],
                "logo": restaurant_logo[0] if restaurant_logo else None
            })
        return jsonify(items_list)

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"Server error: {str(e)}"}), 500

    
@app.route("/items", methods=["POST"])
def add_item():
    restaurant, error_response, status_code = verify_token()
    if error_response:
        return error_response, status_code

    try:
        # Use form data instead of JSON
        name = request.form["name"]
        price = float(request.form["price"])
        discount_price=float(request.form["discount_price"])
        type_ = request.form["type"]
        quantity = int(request.form.get("quantity", 1))  # default to 1 if not provided
        description = request.form["description"]
        image_file = request.files["image"]

        # Save uploaded image
        image_filename = secure_filename(image_file.filename)
        image_path = os.path.join("uploads", image_filename)
        image_file.save(image_path)

        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("""
            INSERT INTO items (name, price, discount_price, type, quantity,description,  restaurant_id, restaurant_name, image_paths)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (name, price, discount_price, type_, quantity, description,
              restaurant["id"], restaurant["name"], image_path))
        connection.commit()
        cursor.close()
        connection.close()
        return jsonify({"message": "Item added successfully"}), 201
    except Exception as e:
        print(str(e))
        return jsonify({"error": str(e)}), 500

@app.route('/billing', methods=['GET'])
def billing():
    try:
        token = request.cookies.get('token') or request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return "Unauthorized", 401

        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        username = decoded.get('username')
        user_id = decoded.get('id')

        return render_template('billing.html', username=username, user_id=user_id)

    except Exception as e:
        return f"Error: {str(e)}", 500
    
@app.route('/submit_cart', methods=['POST'])
def submit_cart():
    try:
        data = request.get_json()
        cart = data.get('cart', [])
        token = request.headers.get('Authorization', '').replace('Bearer ', '')

        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_id = decoded.get('id')

        total_amount = sum(item['price'] * item['quantity'] for item in cart)

        # Simulate billing processing
        return jsonify({
            "user_id": user_id,
            "total": total_amount,
            "message": "Billing processed successfully"
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route("/items/<int:item_id>", methods=["GET"])
def get_item_by_id(item_id):
    try:
        print(item_id)
        connection = get_db_connection()
        cursor = connection.cursor()

        # Query for the specific item
        cursor.execute("SELECT * FROM items WHERE id = %s", (item_id,))
        item_row = cursor.fetchone()

        if not item_row:
            return render_template("404.html", error="Item not found")  # Optional error page

        columns = [desc[0] for desc in cursor.description]
        item = dict(zip(columns, item_row))

        # Prepare item data
        item_data = {
            "id": item["id"],
            "name": item["name"],
            "description": item.get("description", ""),
            "price": float(item["price"]),
            "discount_price": float(item["discount_price"]) if item["discount_price"] else None,
            "type": item["type"],
            "quantity": item["quantity"],
            "image_url": item["image_paths"].split(',')[0] if item.get("image_paths") else None,
            "restaurant_id": item["restaurant_id"],
            "restaurant_name": item["restaurant_name"]
        }

        # Rating and reviews
        cursor.execute("SELECT AVG(rating), COUNT(*) FROM reviews WHERE item_id = %s", (item_id,))
        rating_data = cursor.fetchone()
        item_data["rating"] = float(rating_data[0]) if rating_data[0] else None
        item_data["review_count"] = rating_data[1]

        cursor.close()
        connection.close()

        # Pass data to the template
        return render_template("items.html", item=item_data)

    except Exception as e:
        import traceback
        traceback.print_exc()
        return render_template("500.html", error=str(e))  # Optional error page

@app.route("/items/<int:item_id>/reviews", methods=["GET"])
def get_item_reviews(item_id):
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        
        # Query for reviews of the specific item
        cursor.execute("""
            SELECT id, item_id, username, rating, description, created_at 
            FROM reviews 
            WHERE item_id = %s
            ORDER BY created_at DESC
        """, (item_id,))
        
        reviews_rows = cursor.fetchall()
        columns = [desc[0] for desc in cursor.description]
        
        # Format the reviews
        reviews = []
        for row in reviews_rows:
            review = dict(zip(columns, row))
            reviews.append({
                "id": review["id"],
                "itemId": review["item_id"],
                "username": review["username"],
                "rating": float(review["rating"]),
                "description": review["description"],
                "date": review["created_at"].isoformat() if isinstance(review["created_at"], datetime) else review["created_at"]
            })
        
        cursor.close()
        connection.close()
        
        return jsonify(reviews)
        
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/reviews", methods=["POST"])
def add_review():
    try:
        data = request.json
        
        # Validate required fields
        required_fields = ["itemId", "username", "rating", "description"]
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"Missing required field: {field}"}), 400
        
        # Validate rating
        rating = data["rating"]
        if not isinstance(rating, (int, float)) or rating < 1 or rating > 5:
            return jsonify({"error": "Rating must be a number between 1 and 5"}), 400
        
        connection = get_db_connection()
        cursor = connection.cursor()
        
        # Insert the review
        cursor.execute("""
            INSERT INTO reviews (item_id, username, rating, description)
            VALUES (%s, %s, %s, %s)
            RETURNING id, created_at
        """, (data["itemId"], data["username"], data["rating"], data["description"]))
        
        # Get the inserted review's ID and timestamp
        result = cursor.fetchone()
        review_id = result[0]
        created_at = result[1]
        
        connection.commit()
        cursor.close()
        connection.close()
        
        # Return the created review
        review = {
            "id": review_id,
            "itemId": data["itemId"],
            "username": data["username"],
            "rating": data["rating"],
            "description": data["description"],
            "date": created_at.isoformat() if isinstance(created_at, datetime) else created_at
        }
        
        return jsonify(review), 201
        
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/restaurants", methods=["GET"])
def get_all_restaurants():
    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        # Get filters from request
        search = request.args.get('search', default="", type=str)
        
        # Build SQL query with filters
        query = "SELECT id, name, address, description, phone_number, logo, payment_method FROM restaurants WHERE 1=1"
        params = []

        if search:
            query += " AND name ILIKE %s"
            params.append(f"%{search}%")

        cursor.execute(query, tuple(params))
        rows = cursor.fetchall()
        columns = [desc[0] for desc in cursor.description]
        cursor.close()
        connection.close()

        # Convert rows to list of dicts
        restaurants_list = []
        for row in rows:
            restaurant = dict(zip(columns, row))
            restaurants_list.append({
                "id": restaurant["id"],
                "name": restaurant["name"],
                "address": restaurant["address"],
                "description": restaurant["description"],
                "phone_number": restaurant["phone_number"],
                "logo": restaurant["logo"],
                "payment_method": restaurant["payment_method"]
            })

        return jsonify(restaurants_list)

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/restaurants/<int:restaurant_id>/items", methods=["GET"])
def get_restaurant_items(restaurant_id):
    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        # First get restaurant info
        cursor.execute("SELECT name, address, description, phone_number, logo FROM restaurants WHERE id = %s", (restaurant_id,))
        restaurant_data = cursor.fetchone()
        
        if not restaurant_data:
            return jsonify({"error": "Restaurant not found"}), 404
            
        restaurant_info = {
            "id": restaurant_id,
            "name": restaurant_data[0],
            "address": restaurant_data[1],
            "description": restaurant_data[2],
            "phone_number": restaurant_data[3],
            "logo": restaurant_data[4]
        }
        
        # Then get restaurant's items
        cursor.execute("SELECT * FROM items WHERE restaurant_id = %s", (restaurant_id,))
        rows = cursor.fetchall()
        columns = [desc[0] for desc in cursor.description]
        
        items_list = []
        for row in rows:
            item = dict(zip(columns, row))
            items_list.append({
                "id": item["id"],
                "name": item["name"],
                "description": item.get("description", ""),
                "price": float(item["price"]),
                "discount_price": float(item["discount_price"]) if item["discount_price"] is not None else None,
                "type": item["type"],
                "quantity": item["quantity"],
                "images": [img.replace("\\", "/") for img in item["image_paths"].split(',')] if item.get("image_paths") else [],
                "restaurant_id": item["restaurant_id"],
                "restaurant_name": item["restaurant_name"]
            })

        cursor.close()
        connection.close()

        return jsonify({
            "restaurant": restaurant_info,
            "items": items_list
        })

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"Server error: {str(e)}"}), 500
    
#phone number - verification
@app.route('/verify-phone')
def verify_phone():
    return render_template('verify_phone.html')

@app.route('/send-otp', methods=['POST'])
def send_otp():
    data = request.get_json()
    phone_number = data.get('phone')
    print(phone_number)
    if not phone_number:
        return jsonify({'status': 'error', 'message': 'Phone number is required'}), 400

    try:
        verification = client.verify \
            .v2 \
            .services(verify_sid) \
            .verifications \
            .create(to=phone_number, channel='sms')
        
        return jsonify({'status': 'success', 'message': 'OTP sent', 'sid': verification.sid})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    phone_number = data.get('phone')
    otp_code = data.get('otp')

    if not phone_number or not otp_code:
        return jsonify({'status': 'error', 'message': 'Phone and OTP are required'}), 400

    try:
        verification_check = client.verify \
            .v2 \
            .services(verify_sid) \
            .verification_checks \
            .create(to=phone_number, code=otp_code)

        if verification_check.status == 'approved':
            return jsonify({'status': 'success', 'message': 'Phone number verified'})
        else:
            return jsonify({'status': 'failed', 'message': 'Invalid OTP'}), 401
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


#payment page
@app.route('/payment', methods=['GET'])
def payment():
    try:
        token = request.cookies.get('token') or request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return "Unauthorized", 401

        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        username = decoded.get('username')
        user_id = decoded.get('id')

        return render_template('payment.html', username=username, user_id=user_id)

    except Exception as e:
        return f"Error: {str(e)}", 500

@app.route('/faq', methods=['GET', 'POST'])
def faq():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        message = request.form.get('message')
        print(f"Support request from {name} ({email}): {message}")
        return render_template('faq.html', success=True)

    return render_template('faq.html', success=False)

    
@app.route('/restaurant')
def rests():
        return render_template('restaurant.html')
        
@app.route('/upload')
def upload():
    return render_template('upload.html')
@app.route('/usr_login')
def login():
    return render_template('login.html')  
@app.route('/index')
def index1():
    return render_template('index.html')  

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(os.path.join(app.root_path, 'uploads'), filename)

@app.route("/rest_dashboard")
def rest_dashboard():
    return render_template("restaurant_dashboard.html")
@app.route("/rest_login")
def rest_login():
    return render_template("rest_login.html")    
@app.route('/home')
def index():
    return render_template('home1.html')
@app.route("/usr_signup")
def user_signup():
    return render_template("signup.html")
@app.route("/usr_login")
def user_login():
    return render_template("login.html")
@app.route("/")
def landing_page():
    return render_template("landing.html")

@app.route("/bill")
def bill():
    return render_template("billing.html")

if __name__ == '__main__':
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    app.run(debug=True)