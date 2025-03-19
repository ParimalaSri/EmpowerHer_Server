from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
import os
from flask_cors import cross_origin
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token, JWTManager
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import timedelta

import jwt
import datetime
from dotenv import load_dotenv  # Load environment variables

import pytz  # Import pytz for timezone conversion

# Define IST timezone
ist = pytz.timezone("Asia/Kolkata")

# Get the current time in UTC and convert it to IST
utc_now = datetime.datetime.utcnow()  # ✅ Fix: Access utcnow from the datetime class
ist_now = utc_now.astimezone(ist)



# Load environment variables from .env
load_dotenv()

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "http://localhost:8080"}}, supports_credentials=True)

bcrypt = Bcrypt(app)

# Use environment variables for MongoDB and JWT Secret
MONGO_URI = os.getenv("MONGO_URI")
app.config["MONGO_URI"] = MONGO_URI
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
mongo = PyMongo(app)
db = mongo.db  # Accessing the database

# Alternative connection using MongoClient
client = MongoClient(MONGO_URI)
database = client.get_database("WomanEmployment")  # Replace with your database name
users_collection = database.get_collection("users")  # Users collection
sellers_collection = database.get_collection("sellers")
wishlists_collection = db["wishlist"]
products_collection = db["products"] 
orders_collection = db["orders"] 



@app.route('/api/auth/customer-login', methods=['POST'])
def login():
    data = request.json
    email = data.get("email")
    password = data.get("password")

    user = users_collection.find_one({"email": email})
    name = user["name"]
    if user and check_password_hash(user["password"], password):
        # ✅ Correct way to create a JWT token
        token = jwt.encode(
            {"user": name, "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
            app.config["JWT_SECRET_KEY"],
            algorithm="HS256",
        )

        return jsonify({"message": "Login successful", "token": token}), 200
    else:
        return jsonify({"error": "Invalid credentials"}), 401
    




@app.route("/user", methods=["GET"])
def dashboard():
    auth_header = request.headers.get("Authorization")
    print(f"Received Authorization Header: {auth_header}")  # ✅ Debugging

    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Invalid token format"}), 401

    token = auth_header.split(" ")[1]
    print(f"Extracted Token: {token}")  # ✅ Debugging

    try:
        decoded_token = jwt.decode(token, app.config["JWT_SECRET_KEY"], algorithms=["HS256"])
        print(f"Decoded Token: {decoded_token}")  # ✅ Debugging
        user = decoded_token["user"]

        return jsonify({"message": {user}})

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401







@app.route('/signup', methods=['POST'])
def signup():
    print("Received signup request")
    print(request.json)
    data = request.json
    name = data.get("name")
    email = data.get("email")
    password = data.get("password")
    phone = data.get("phone")
    print("name:", name, "email:", email, "password:", password, "phone:", phone)

    if users_collection.find_one({"email": email}):
        return jsonify({"error": "Email already exists"}), 400

    hashed_password = generate_password_hash(password)
    users_collection.insert_one({"name": name, "email": email, "password": hashed_password, "phone": phone})

    return jsonify({"message": "User registered successfully"}), 201







#--------------------Seller Register Route ---------------------
# Seller Registration Route
@app.route('/api/sellers/register', methods=['POST'])
def register_seller():
    try:
        data = request.json
        full_name = data.get('fullName')
        email = data.get('email')
        phone = data.get('phone')
        business_name = data.get('businessName')
        business_type = data.get('businessType')
        location = data.get('location')
        password = data.get('password')

        # Check if the seller already exists
        existing_seller = mongo.db.sellers.find_one({"email": email})
        if existing_seller:
            return jsonify({"message": "Seller already registered"}), 400

        # Hash the password before saving
        hashed_password = generate_password_hash(password)

        # Save seller details in MongoDB
        seller_data = {
            "fullName": full_name,
            "email": email,
            "phone": phone,
            "businessName": business_name,
            "businessType": business_type,
            "location": location,
            "password": hashed_password
        }
        mongo.db.sellers.insert_one(seller_data)

        return jsonify({"message": "Seller registered successfully"}), 201

    except Exception as e:
        return jsonify({"message": "Internal Server Error", "error": str(e)}), 500
    





    

    
# ---------------- SELLER LOGIN ----------------

@app.route('/api/auth/seller-login', methods=['POST'])
def seller_login():
    try:
        data = request.json
        email = data.get("email")
        password = data.get("password")

        # Check if seller exists
        seller = sellers_collection.find_one({"email": email})
        if not seller:
            return jsonify({"error": "Invalid credentials"}), 401

        # Verify password
        if not check_password_hash(seller["password"], password):
            return jsonify({"error": "Invalid credentials"}), 401
        
        # ✅ Generate JWT token similar to customer-login
        token = jwt.encode(
            {"user": seller["fullName"], "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
            app.config["JWT_SECRET_KEY"],
            algorithm="HS256",
        )

        return jsonify({"message": "Login successful", "token": token}), 200
    
    except Exception as e:
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500
    





@app.route("/api/wishlist/add", methods=["POST"])
def add_to_wishlist():
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Unauthorized"}), 401

    token = auth_header.split(" ")[1]

    try:
        decoded_token = jwt.decode(token, app.config["JWT_SECRET_KEY"], algorithms=["HS256"])
        user_name = decoded_token["user"]

        data = request.json
        product_id = data.get("productId")

        if not product_id:
            return jsonify({"error": "Product ID is required"}), 400

        wishlist = wishlists_collection.find_one({"user": user_name})

        if wishlist:
            wishlists_collection.update_one(
                {"user": user_name},
                {"$addToSet": {"products": product_id}}  # Prevent duplicates
            )
        else:
            wishlists_collection.insert_one({"user": user_name, "products": [product_id]})

        return jsonify({"message": "Product added to wishlist"}), 200

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

# API to get user's wishlist
@app.route("/api/wishlist", methods=["GET"])
def get_wishlist():
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return jsonify({"error": "Authorization token is missing"}), 401

    try:
        token = auth_header.split(" ")[1]  # Extract the token (format: "Bearer <token>")
        decoded_token = jwt.decode(token, app.config["JWT_SECRET_KEY"], algorithms=["HS256"])
        username = decoded_token["user"]

        if not username:
            return jsonify({"error": "Invalid token"}), 401

        user_wishlist = mongo.db.wishlists.find_one({"user": username}, {"_id": 0})  # Exclude _id
        wishlist_count = len(user_wishlist["wishlist"])
        print(wishlist_count)
        if user_wishlist:
            return jsonify(user_wishlist), 200
        else:
            return jsonify({"error": "Wishlist not found"}), 404

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401





@app.route("/api/addresses", methods=["GET"])
def get_addresses():
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return jsonify({"error": "Authorization token is missing"}), 401

    try:
        token = auth_header.split(" ")[1]  # Extract token from "Bearer <token>"
        decoded_token = jwt.decode(token, app.config["JWT_SECRET_KEY"], algorithms=["HS256"])
        username = decoded_token.get("user")  # Extract username from token
        print("Decoded Username:", username)

        if not username:
            return jsonify({"error": "Invalid token"}), 401

        # Fetch addresses from the 'address' collection
        user_data = mongo.db.address.find_one({"username": username}, {"_id": 0, "addresses": 1})  # Fetch only addresses
        print("Fetched User Data:", user_data)

        if user_data and "addresses" in user_data:
            return jsonify({"username": username, "addresses": user_data["addresses"]}), 200
        else:
            return jsonify({"error": "No addresses found"}), 404

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401


@app.route("/api/add-address", methods=["POST"])
def add_address():
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return jsonify({"error": "Authorization token is missing"}), 401

    try:
        token = auth_header.split(" ")[1]
        decoded_token = jwt.decode(token, app.config["JWT_SECRET_KEY"], algorithms=["HS256"])
        username = decoded_token.get("user")
        
        if not username:
            return jsonify({"error": "Invalid token"}), 401

        # Extract address data from request
        address_data = request.json
        id = address_data.get("id")
        print(address_data)
        required_fields = ["name", "street", "city", "state", "zipcode", "country"]

        if not all(field in address_data for field in required_fields):
            return jsonify({"error": "Missing required address fields"}), 400

        # # Add timestamp
        # address_data["timestamp"] = datetime.utcnow()

        # Update user's address list
        result = mongo.db.address.update_one(
            {"username": username},
            {"$push": {"addresses": address_data}},
            upsert=True  # Creates entry if user does not exist
        )

        if result.modified_count > 0 or result.upserted_id:
            return jsonify({"message": "Address added successfully"}), 201
        else:
            return jsonify({"error": "Failed to add address"}), 500

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401
    




@app.route("/api/carts", methods=["GET"])
def get_cart():
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return jsonify({"error": "Authorization token is missing"}), 401

    try:
        token = auth_header.split(" ")[1]  # Extract the token (format: "Bearer <token>")
        decoded_token = jwt.decode(token, app.config["JWT_SECRET_KEY"], algorithms=["HS256"])
        username = decoded_token["user"]

        if not username:
            return jsonify({"error": "Invalid token"}), 401

        user_cart = mongo.db.carts.find_one({"user": username}, {"_id": 0})  # Exclude _id
        print(user_cart)
        if user_cart:
            return jsonify(user_cart), 200
        else:
            return jsonify({"error": "Wishlist not found"}), 404

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401



@app.route("/api/wishlist-add", methods=["POST"])
def add_to_wishlist_add():
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return jsonify({"error": "Authorization token is missing"}), 401

    try:
        token = auth_header.split(" ")[1]  # Extract token (format: "Bearer <token>")
        decoded_token = jwt.decode(token, app.config["JWT_SECRET_KEY"], algorithms=["HS256"])
        username = decoded_token.get("user")

        if not username:
            return jsonify({"error": "Invalid token"}), 401

        data = request.json
        name = data.get("name")
        price = data.get("price")
        seller = data.get("seller")
        image = data.get("image")


        if not all([name, price, seller]):
            return jsonify({"error": "Missing product details"}), 400

        print(f"Received Product from {username}: ", {"name": name, "price": price, "seller": seller, "image": image})
        existing_wishlist = mongo.db.wishlists.find_one({"user": username})

        if existing_wishlist:
            # If user exists, add the new product to the existing list (if not already present)
            mongo.db.wishlists.update_one(
                {"user": username, "products.name": {"$ne": name}},  # Ensure product is not duplicated
                {"$push": {"wishlist": {"name": name, "price": price, "seller": seller, "image": image}}},
            )
        else:
            # If user doesn't exist, create a new wishlist entry
            mongo.db.wishlists.insert_one({
                "user": username,
                "wishlist": [{"name": name, "price": price, "seller": seller}]
            })
        return jsonify({"message": "Product added to wishlist successfully!", "product": data}), 200

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401
    


@app.route("/api/cart-add", methods=["POST"])
def add_to_cart_add():
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return jsonify({"error": "Authorization token is missing"}), 401

    try:
        token = auth_header.split(" ")[1]  # Extract token (format: "Bearer <token>")
        decoded_token = jwt.decode(token, app.config["JWT_SECRET_KEY"], algorithms=["HS256"])
        username = decoded_token.get("user")

        if not username:
            return jsonify({"error": "Invalid token"}), 401

        data = request.json
        product_id = data.get("id")
        name = data.get("name")
        price = data.get("price")
        seller = data.get("seller")
        quantity = data.get("quantity", 1)
        discount = data.get("discount", 0)

        if not all([product_id, name, price, seller]):
            return jsonify({"error": "Missing product dtails"}), 400

        print(f"Received Product from {username}: ", {
            "id": product_id, "name": name, "price": price, "seller": seller,
             "discount": discount, "quantity": quantity
        })

        existing_cart = mongo.db.carts.find_one({"user": username})

        if existing_cart:
            # Check if the product already exists in the cart
            existing_product = next((item for item in existing_cart["cart"] if item["id"] == product_id), None)

            if existing_product:
                # If product exists, increase the quantity
                mongo.db.carts.update_one(
                    {"user": username, "cart.id": product_id},
                    {"$inc": {"cart.$.quantity": 1}}
                )
            else:
                # If product does not exist, add a new entry
                mongo.db.carts.update_one(
                    {"user": username},
                    {"$push": {"cart": {
                        "id": product_id,
                        "name": name,
                        "price": price,
                        "seller": seller,
                        "quantity": quantity,
                        "discount": discount
                    }}}
                )
        else:
            # If user doesn't have a cart, create a new entry
            mongo.db.carts.insert_one({
                "user": username,
                "cart": [{
                    "id": product_id,
                    "name": name,
                    "price": price,
                    "seller": seller,
                    "quantity": quantity,
                    "discount": discount
                }]
            })

        return jsonify({"message": "Product added to cart successfully!", "product": data}), 200

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401



@app.route("/api/customer/orders", methods=["GET"])
def get_customer_orders():
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return jsonify({"error": "Authorization token is missing"}), 401

    try:
        token = auth_header.split(" ")[1]  # Extract token (format: "Bearer <token>")
        decoded_token = jwt.decode(token, app.config["JWT_SECRET_KEY"], algorithms=["HS256"])
        username = decoded_token.get("user")

        if not username:
            return jsonify({"error": "Unauthorized"}), 401

        orders = list(db.orders.find({"userName": username}, {"_id": 0}))  # Fetch orders
        print("Fetched Orders:", orders)
        return jsonify(orders)

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401




@app.route("/api/user/profile", methods=["GET"])
def get_profile():
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return jsonify({"error": "Authorization token is missing"}), 401

    try:
        token = auth_header.split(" ")[1]  # Extract token (format: "Bearer <token>")
        decoded_token = jwt.decode(token, app.config["JWT_SECRET_KEY"], algorithms=["HS256"])
        username = decoded_token.get("user")

        user = users_collection.find_one({"name": username}, {"password": 0})
        if not user:
            print("User not found")
            return jsonify({"message": "User not found"}), 404
        
        print("User found:", user)

        return jsonify({
            "firstName": user["name"],
            # "lastName": user["lastName"],
            "email": user["email"]
            # "phone": user["phone"]
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 401
    






@app.route("/api/get-products", methods=["GET"])
def get_products():
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return jsonify({"error": "Authorization token is missing"}), 401
    token = auth_header.split(" ")[1]  # Extract token (format: "Bearer <token>")
    decoded_token = jwt.decode(token, app.config["JWT_SECRET_KEY"], algorithms=["HS256"])
    seller_name = decoded_token.get("user") # Get seller name from query parameters
    print("Received seller name:", seller_name)
    if not seller_name:
        return jsonify({"error": "Seller name is required"}), 400

    # Fetch products with the given seller name
    products = list(products_collection.find({"seller": seller_name}, {"_id": 0}))

    if not products:
        return jsonify({"message": "No products found for this seller"}), 404

    return jsonify(products), 200



@app.route("/api/products", methods=["GET"])
def get_products_1():
    # Fetch all products from the collection
    products = list(products_collection.find({}, {"_id": 0}))

    if not products:
        return jsonify({"message": "No products found"}), 404

    return jsonify(products), 200



    
@app.route('/api/add-product', methods=['POST'])
def add_product():
    data = request.json
    print("Received data:", data)
    if not data.get("name") or not data.get("price") or not data.get("stock"):
        return jsonify({"error": "Missing required fields"}), 400

    products_collection.insert_one(data)
    return jsonify(data), 201


@app.route("/api/seller-orders", methods=["GET"])
def get_seller_orders():
    auth_header = request.headers.get("Authorization")

    if not auth_header or "Bearer " not in auth_header:
        return jsonify({"error": "Authorization token is missing or invalid"}), 401

    try:
        token = auth_header.split(" ")[1]  # Extract token
        decoded_token = jwt.decode(token, app.config["JWT_SECRET_KEY"], algorithms=["HS256"])
        seller_name = decoded_token.get("user")  # Extract seller name from token

        if not seller_name:
            return jsonify({"error": "Seller name is required"}), 400

        print("Received seller name:", seller_name)

        # Fetch documents where any order has the given seller_name
        matching_documents = list(orders_collection.find(
            {"orders.seller_name": seller_name},  # Find documents containing this seller
            {"_id": 0, "userName": 1, "orders": 1}  # Exclude _id, return userName and orders
        ))

        if not matching_documents:
            return jsonify({"message": "No orders found for this seller"}), 404

        # Extract only orders that match the seller_name
        filtered_orders = []
        for doc in matching_documents:
            for order in doc["orders"]:
                if order["seller_name"] == seller_name:
                    filtered_orders.append({
                        "Order ID": order["id"],
                        "Customer": doc["userName"],
                        "Product": order.get("items", "N/A"),  # Assuming 'items' refers to product count
                        "Amount": order["total"],
                        "Status": order["status"]
                    })

        print("Filtered Orders:", filtered_orders)
        return jsonify(filtered_orders), 200

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401
    

@app.route("/api/checkout", methods=["POST"])
def checkout():
    try:
        # Extract Authorization Header
        auth_header = request.headers.get("Authorization")
        print("Received Authorization Header:", auth_header)

        if not auth_header or "Bearer " not in auth_header:
            return jsonify({"error": "Authorization token is missing or invalid"}), 401

        try:
            # Extract token and decode it
            token = auth_header.split(" ")[1]
            decoded_token = jwt.decode(token, app.config["JWT_SECRET_KEY"], algorithms=["HS256"])
            user_name = decoded_token.get("user")  # Extract username from token
            print("Decoded Username:", user_name)

            if not user_name:
                return jsonify({"error": "Invalid token, user not found"}), 401

            # Fetch user's cart items
            user_cart = list(db.carts.find({"user": user_name}))
            print("User Cart:", user_cart)

            if not user_cart:
                return jsonify({"message": "Cart is empty!"}), 400

            # Extract cart array from user_cart
            cart_items = user_cart[0]["cart"]

            # Calculate total price after applying discounts
            total_price = sum((item["price"] - (item["price"] * item["discount"] / 100)) * item["quantity"] for item in cart_items)

            # Create a new order object
            new_order = {
                "id": int(ist_now.timestamp()),  # Unique Order ID in IST
                "date": ist_now.strftime("%Y-%m-%d %H:%M:%S"),  # Date and Time in IST
                "items": len(cart_items),  # Number of items
                "total": total_price,  # Total price after discount
                "status": "Pending", 
                "seller_name": cart_items[0]["seller"] if cart_items else "Unknown Seller",  # Default status
                
                
            }

            # Check if the user already has an entry in the `orders` collection
            existing_user_order = db.orders.find_one({"userName": user_name})

            if existing_user_order:
                # If user exists, append new order to the existing `orders` array
                db.orders.update_one(
                    {"userName": user_name},
                    {"$push": {"orders": new_order}}
                )
            else:
                # If user does not exist, create a new order entry
                db.orders.insert_one({
                    "userName": user_name,
                    "orders": [new_order]  # Store as an array
                })

            # Clear the cart after checkout
            db.carts.delete_many({"user": user_name})

            return jsonify({"message": "Order placed successfully!", "order": new_order}), 200

        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

    except Exception as e:
        print("Error:", str(e))
        return jsonify({"error": str(e)}), 500
    
# --------------- Run the Server ---------------
if __name__ == '__main__':
    app.run(debug=True)
