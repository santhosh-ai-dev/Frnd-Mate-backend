from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import os
import jwt
import random
import string
from datetime import datetime, timedelta, timezone
from twilio.rest import Client
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app)

# Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Twilio Configuration
TWILIO_ACCOUNT_SID = os.getenv('TWILIO_ACCOUNT_SID')
TWILIO_AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN')
TWILIO_PHONE_NUMBER = os.getenv('TWILIO_PHONE_NUMBER')  # Updated to include + prefix

# Initialize Twilio client
twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    mobile = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=True)  # Make password optional
    gender = db.Column(db.String(20), nullable=True)
    date_of_birth = db.Column(db.Date, nullable=True)
    language = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))  # Updated to use timezone.utc

    def __repr__(self):
        return f'<User {self.username}>'

class OTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    mobile = db.Column(db.String(20), nullable=False)
    otp_code = db.Column(db.String(4), nullable=False)  # 4 digits
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))  # Updated to use timezone.utc
    expires_at = db.Column(db.DateTime, nullable=False)
    verified = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<OTP {self.mobile}: {self.otp_code}>'

class BlacklistedToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(500), unique=True, nullable=False)
    blacklisted_on = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    def __repr__(self):
        return f'<BlacklistedToken {self.token[:10]}...>'

# Create all database tables
with app.app_context():
    db.create_all()

# Function to format phone numbers in E.164 format
def format_phone_number(phone):
    # Strip any non-digit characters
    digits_only = ''.join(filter(str.isdigit, phone))
    
    # Check if it already has country code
    if phone.startswith('+'):
        return phone
    
    # Assuming Indian numbers (adjust the country code as needed)
    if len(digits_only) == 10:
        return f"+91{digits_only}"
    elif len(digits_only) == 12 and digits_only.startswith('91'):
        return f"+{digits_only}"
    else:
        return f"+{digits_only}"  # Best effort formatting

# Helper function to generate tokens
def generate_token(user_id):
    expiration = datetime.now(timezone.utc) + timedelta(hours=24)
    payload = {
        'exp': expiration,
        'iat': datetime.now(timezone.utc),
        'sub': str(user_id)  # Convert user_id to string
    }
    return jwt.encode(
        payload,
        app.config.get('SECRET_KEY'),
        algorithm='HS256'
    )

# Token verification function
def verify_token(token):
    try:
        # Check if token is blacklisted
        blacklisted = BlacklistedToken.query.filter_by(token=token).first()
        if blacklisted:
            print("Token is blacklisted")
            return None
            
        print(f"Decoding token with secret: {app.config.get('SECRET_KEY')[:5]}...")
        payload = jwt.decode(
            token,
            app.config.get('SECRET_KEY'),
            algorithms=['HS256']
        )
        # Convert string back to integer for database lookup
        user_id = int(payload['sub'])
        print(f"Token decoded successfully: {user_id}")
        return user_id
    except jwt.ExpiredSignatureError:
        print("Token expired")
        return None
    except jwt.InvalidTokenError as e:
        print(f"Invalid token: {str(e)}")
        return None
    except Exception as e:
        print(f"Unexpected error verifying token: {str(e)}")
        return None

# Generate OTP function - now creates 4-digit OTP
def generate_otp():
    return ''.join(random.choices(string.digits, k=4))

# Function to send OTP via SMS using Twilio
def send_sms_otp(mobile_number, otp_code):
    try:
        formatted_number = format_phone_number(mobile_number)
        message = twilio_client.messages.create(
            body=f"Your verification code for FrndMate is: {otp_code}. It will expire in 10 minutes.",
            from_=TWILIO_PHONE_NUMBER,
            to=formatted_number
        )
        return True, message.sid
    except Exception as e:
        # For development: Print OTP to console when SMS fails
        print(f"⚠️ SMS sending failed. OTP for {mobile_number} is: {otp_code}")
        return False, str(e)

@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.get_json()
    
    # Validate required fields
    required_fields = ['username', 'email', 'mobile']
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing required field: {field}"}), 400
    
    username = data.get('username')
    email = data.get('email')
    mobile = data.get('mobile')
    password = data.get('password')  # Optional now
    gender = data.get('gender')
    
    # Parse date of birth if provided
    date_of_birth = None
    if data.get('date_of_birth'):
        try:
            date_of_birth = datetime.strptime(data.get('date_of_birth'), '%Y-%m-%d').date()
        except ValueError:
            return jsonify({"error": "Invalid date format. Use YYYY-MM-DD"}), 400
    
    language = data.get('language')
    
    # Check mobile already exists
    existing_mobile = User.query.filter_by(mobile=mobile).first()
    
    if existing_mobile:
        return jsonify({"error": "Mobile number already registered"}), 409
    
    # Create new user with hashed password if provided
    hashed_password = None
    if password:
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    
    new_user = User(
        username=username, 
        email=email, 
        mobile=mobile,
        password=hashed_password,
        gender=gender,
        date_of_birth=date_of_birth,
        language=language
    )
    
    try:
        db.session.add(new_user)
        db.session.commit()
        
        # Generate token
        token = generate_token(new_user.id)
        
        return jsonify({
            "message": "Account created successfully",
            "token": token,
            "user": {
                "id": new_user.id,
                "username": new_user.username,
                "email": new_user.email,
                "mobile": new_user.mobile,
                "gender": new_user.gender,
                "date_of_birth": new_user.date_of_birth.strftime('%Y-%m-%d') if new_user.date_of_birth else None,
                "language": new_user.language
            }
        }), 201
    
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Database error", "details": str(e)}), 500

@app.route('/api/request-otp', methods=['POST'])
def request_otp():
    data = request.get_json()
    
    if not data or 'mobile' not in data:
        return jsonify({"error": "Mobile number is required"}), 400
    
    mobile = data.get('mobile')
    
    # Check if user exists
    user = User.query.filter_by(mobile=mobile).first()
    if not user:
        return jsonify({"error": "No account found with this mobile number"}), 404
    
    # Generate OTP - now 4 digits
    otp_code = generate_otp()
    
    # Store timezone-aware datetime for expires_at
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
    
    # Delete any existing OTPs for this mobile
    OTP.query.filter_by(mobile=mobile).delete()
    
    # Create new OTP
    new_otp = OTP(
        mobile=mobile,
        otp_code=otp_code,
        expires_at=expires_at
    )
    
    try:
        db.session.add(new_otp)
        db.session.commit()
        
        # Send OTP via SMS
        success, message = send_sms_otp(mobile, otp_code)
        
        if success:
            print(f"SMS sending success: {message}")
            return jsonify({
                "message": "OTP sent successfully to your mobile number",
                "otp": otp_code,  # For development only - remove in production
                "expires_in": "10 minutes"
            }), 200
        else:
            # Log the error but don't expose details to client
            print(f"SMS sending failed: {message}")
            return jsonify({
                "message": "OTP generated but SMS sending failed. Please try again.",
                "expires_in": "10 minutes"
            }), 500
    
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Error generating OTP", "details": str(e)}), 500

@app.route('/api/verify-otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    print(data)
    
    if not data or 'mobile' not in data or 'otp' not in data:
        return jsonify({"error": "Mobile number and OTP are required"}), 400
    
    mobile = data.get('mobile')
    otp_code = data.get('otp')
    
    # Find OTP record
    otp_record = OTP.query.filter_by(
        mobile=mobile,
        otp_code=otp_code,
        verified=False
    ).first()
    
    if not otp_record:
        return jsonify({"error": "Invalid OTP"}), 400
    
    # Fix the timezone comparison issue by making both datetimes timezone-aware
    # Convert the naive datetime from database to timezone-aware
    expiry_aware = otp_record.expires_at.replace(tzinfo=timezone.utc) if otp_record.expires_at.tzinfo is None else otp_record.expires_at
    
    if expiry_aware < datetime.now(timezone.utc):
        return jsonify({"error": "OTP has expired"}), 400
    
    # Mark OTP as verified
    otp_record.verified = True
    
    # Find user
    user = User.query.filter_by(mobile=mobile).first()
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # Generate token
    token = generate_token(user.id)
    
    try:
        db.session.commit()
        
        return jsonify({
            "message": "OTP verified successfully",
            "token": token,
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "mobile": user.mobile,
                "gender": user.gender,
                "date_of_birth": user.date_of_birth.strftime('%Y-%m-%d') if user.date_of_birth else None,
                "language": user.language
            }
        }), 200
    
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Database error", "details": str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    
    if not data or 'mobile' not in data:
        return jsonify({"error": "Mobile number is required"}), 400
    
    mobile = data.get('mobile')
    
    # Check if user exists
    user = User.query.filter_by(mobile=mobile).first()
    if not user:
        return jsonify({"error": "No account found with this mobile number"}), 404
    
    # Generate OTP for login
    otp_code = generate_otp()
    
    # Store timezone-aware datetime for expires_at
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
    
    # Delete any existing OTPs for this mobile
    OTP.query.filter_by(mobile=mobile).delete()
    
    # Create new OTP
    new_otp = OTP(
        mobile=mobile,
        otp_code=otp_code,
        expires_at=expires_at
    )
    
    try:
        db.session.add(new_otp)
        db.session.commit()
        
        # Send OTP via SMS
        success, message = send_sms_otp(mobile, otp_code)
        
        if success:
            print(f"SMS sending success: {message}")
            return jsonify({
                "message": "OTP sent successfully to your mobile number",
                "expires_in": "10 minutes"
            }), 200
        else:
            # Log the error but don't expose details to client
            print(f"SMS sending failed: {message}")
            return jsonify({
                "message": "OTP generated but SMS sending failed. Please try again.",
                "expires_in": "10 minutes"
            }), 500
    
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Error generating OTP", "details": str(e)}), 500

@app.route('/api/verify-token', methods=['POST'])
def verify_auth_token():
    try:
        data = request.get_json()
        
        if not data:
            print("No JSON data received")
            return jsonify({"error": "No data provided"}), 400
            
        token = data.get('token')
        
        if not token:
            print("No token in request")
            return jsonify({"error": "Token is required"}), 400
        
        print(f"Verifying token: {token[:10]}...")  # Print first 10 chars for debugging
        
        user_id = verify_token(token)
        
        if not user_id:
            print("Token verification failed")
            return jsonify({"error": "Invalid or expired token"}), 401
        
        user = User.query.get(user_id)
        
        if not user:
            print(f"User ID {user_id} not found")
            return jsonify({"error": "User not found"}), 404
        
        print(f"User authenticated: {user.username}")
        return jsonify({
            "authenticated": True,
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "mobile": user.mobile,
                "gender": user.gender,
                "date_of_birth": user.date_of_birth.strftime('%Y-%m-%d') if user.date_of_birth else None,
                "language": user.language
            }
        }), 200
        
    except Exception as e:
        print(f"Exception in verify_token: {str(e)}")
        return jsonify({"error": "Server error", "details": str(e)}), 500

@app.route('/api/update-profile', methods=['PUT'])
def update_profile():
    data = request.get_json()
    token = data.get('token')
    
    if not token:
        return jsonify({"error": "Authentication required"}), 401
    
    user_id = verify_token(token)
    
    if not user_id:
        return jsonify({"error": "Invalid or expired token"}), 401
    
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # Update fields if provided
    if 'username' in data:
        # Check if new username is unique
        if user.username != data['username']:
            existing = User.query.filter_by(username=data['username']).first()
            if existing:
                return jsonify({"error": "Username already exists"}), 409
        user.username = data['username']
    
    if 'email' in data:
        # Check if new email is unique
        if user.email != data['email']:
            existing = User.query.filter_by(email=data['email']).first()
            if existing:
                return jsonify({"error": "Email already exists"}), 409
        user.email = data['email']
    
    if 'gender' in data:
        user.gender = data['gender']
    
    if 'date_of_birth' in data:
        try:
            user.date_of_birth = datetime.strptime(data['date_of_birth'], '%Y-%m-%d').date()
        except ValueError:
            return jsonify({"error": "Invalid date format. Use YYYY-MM-DD"}), 400
    
    if 'language' in data:
        user.language = data['language']
    
    if 'password' in data:
        user.password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    
    try:
        db.session.commit()
        
        return jsonify({
            "message": "Profile updated successfully",
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "mobile": user.mobile,
                "gender": user.gender,
                "date_of_birth": user.date_of_birth.strftime('%Y-%m-%d') if user.date_of_birth else None,
                "language": user.language
            }
        }), 200
    
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Database error", "details": str(e)}), 500

# New endpoint to resend OTP if needed
@app.route('/api/resend-otp', methods=['POST'])
def resend_otp():
    data = request.get_json()
    
    if not data or 'mobile' not in data:
        return jsonify({"error": "Mobile number is required"}), 400
    
    mobile = data.get('mobile')
    
    # Check if user exists
    user = User.query.filter_by(mobile=mobile).first()
    if not user:
        return jsonify({"error": "No account found with this mobile number"}), 404
    
    # Generate new OTP
    otp_code = generate_otp()
    
    # Store timezone-aware datetime for expires_at
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
    
    # Delete any existing OTPs for this mobile
    OTP.query.filter_by(mobile=mobile).delete()
    
    # Create new OTP
    new_otp = OTP(
        mobile=mobile,
        otp_code=otp_code,
        expires_at=expires_at
    )
    
    try:
        db.session.add(new_otp)
        db.session.commit()
        
        # Send OTP via SMS
        success, message = send_sms_otp(mobile, otp_code)
        
        if success:
            return jsonify({
                "message": "New OTP sent successfully to your mobile number",
                "expires_in": "10 minutes"
            }), 200
        else:
            # Log the error but don't expose details to client
            print(f"SMS sending failed: {message}")
            return jsonify({
                "message": "OTP generated but SMS sending failed. Please try again.",
                "otp": otp_code,  # For development only - remove in production
                "expires_in": "10 minutes"
            }), 500
    
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Error generating OTP", "details": str(e)}), 500

# New logout endpoint
@app.route('/api/logout', methods=['POST'])
def logout():
    data = request.get_json()
    
    if not data or 'token' not in data:
        return jsonify({"error": "Token is required"}), 400
    
    token = data.get('token')
    
    # Check if token is already blacklisted
    existing_token = BlacklistedToken.query.filter_by(token=token).first()
    if existing_token:
        return jsonify({"message": "Token is already invalidated"}), 200
    
    # Add token to blacklist
    blacklisted_token = BlacklistedToken(token=token)
    
    try:
        db.session.add(blacklisted_token)
        db.session.commit()
        return jsonify({"message": "Successfully logged out"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Database error", "details": str(e)}), 500

# Optional: Cleanup function for expired tokens (this would need to be scheduled)
def clean_expired_tokens():
    with app.app_context():
        # Get current time
        now = datetime.now(timezone.utc)
        
        try:
            # Find all tokens in the blacklist
            tokens = BlacklistedToken.query.all()
            deleted_count = 0
            
            for token_record in tokens:
                try:
                    # Try to decode the token
                    payload = jwt.decode(
                        token_record.token,
                        app.config.get('SECRET_KEY'),
                        algorithms=['HS256'],
                        options={"verify_signature": False}  # Just check expiration
                    )
                    
                    # If token is expired, remove it from blacklist
                    if datetime.fromtimestamp(payload['exp'], tz=timezone.utc) < now:
                        db.session.delete(token_record)
                        deleted_count += 1
                        
                except jwt.ExpiredSignatureError:
                    # Token is expired, we can remove it from blacklist
                    db.session.delete(token_record)
                    deleted_count += 1
                except Exception as e:
                    print(f"Error processing token {token_record.id}: {str(e)}")
            
            # Commit changes
            db.session.commit()
            print(f"Expired tokens cleanup completed at {now}. Removed {deleted_count} tokens.")
            
        except Exception as e:
            db.session.rollback()
            print(f"Error cleaning expired tokens: {str(e)}")

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')