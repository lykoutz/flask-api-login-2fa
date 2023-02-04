import os
import pyotp
import jwt
from datetime import datetime, timedelta
from functools import wraps
from marshmallow import Schema, fields, ValidationError
from flask import Flask, jsonify, request, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://frla_user:frla_pwd@postgres.registration_login_api:5432/frla_db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.urandom(12).hex()

LOGIN_TOKEN_EXPIRATION_MINUTES=1
LOGIN_TOKEN_OTP_EXPIRATION_SECONDS=30

db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = "users"
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(255))
    first_name = db.Column(db.String(50), nullable=True)
    last_name = db.Column(db.String(50), nullable=True)
    token = db.Column(db.String(), nullable=True, default=None)
    otp_enabled = db.Column(db.Boolean, default=False)
    otp_verified = db.Column(db.Boolean, default=False)
    otp_base32 = db.Column(db.String(), nullable=True, default=None)
    
    def verify_password(self, password):
        return check_password_hash(self.password, password)
    
    @staticmethod
    def encode_auth_token(user_id, expiration_timedelta: timedelta):
        try:
            payload = {
                'exp': datetime.utcnow() + expiration_timedelta,
                'iat': datetime.utcnow(),
                'sub': user_id
            }
            return jwt.encode(payload, app.config.get('SECRET_KEY'), algorithm='HS256')
        except Exception as e:
            return e
        
    @staticmethod
    def decode_auth_token(auth_token):
        try:
            payload = jwt.decode(auth_token, app.config.get('SECRET_KEY'), algorithms=['HS256'])
            return True, payload['sub']
        except jwt.ExpiredSignatureError as e:
            return False, 'Token expired. Please log in again.'
        except jwt.InvalidTokenError as e:
            return False, 'Invalid token. Please log in again.'
    
    def __repr__(self):
        return f'<{self.email}>'

def has_valid_token(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        is_valid, result = User.decode_auth_token(session.get('token'))
        if not is_valid:
            response = jsonify({'error': result})
            response.status_code = 401
            return response
        return f(*args, **kwargs)
    return wrap

def login_required(f):
    @wraps(f)
    @has_valid_token
    def wrap(*args, **kwargs):
        user = User.query.filter_by(token=session.get('token')).first()
        if user.otp_enabled and not user.otp_verified:
            response = jsonify({'message': 'Please validate OTP'})
            response.status_code = 401
            return response
        return f(*args, **kwargs)
    return wrap
    
class RegisteredSchema(Schema):
    email = fields.String(required=True)
    password = fields.String(required=True)
    first_name = fields.String()
    last_name = fields.String()
    otp_enabled = fields.Boolean()
    
class LoginSchema(Schema):
    email = fields.String(required=True)
    password = fields.String(required=True)
    
class Login2FASchema(Schema):
    otp = fields.String(required=True)

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    try:
        RegisteredSchema().load(data)
    except ValidationError as err:
        response = jsonify({'error': err.messages})
        response.status_code = 400
        return response
    
    email = data.get('email')
    password = data.get('password')
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    otp_enabled = bool(data.get('otp_enabled'))
    
    if User.query.filter_by(email=email).first():
        response = jsonify({'error': 'Account already exists'})
        response.status_code = 409
        return response
    
    new_user = User(
        email=email,
        password=generate_password_hash(password),
        first_name=first_name,
        last_name=last_name,
        otp_enabled=otp_enabled
    )
    db.session.add(new_user)
    db.session.commit()
    
    response = jsonify({'message': f'{new_user} registered successfully'})
    response.status_code = 201
    return response
    
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    try:
        LoginSchema().load(data)
    except ValidationError as err:
        response = jsonify({'error': err.messages})
        response.status_code = 400
        return response
    
    email = data.get('email')
    password = data.get('password')
    
    user = User.query.filter_by(email=email).first()
    
    if not user or not user.verify_password(password):
        response = jsonify({'error': 'Invalid credentials'})
        response.status_code = 401
        return response
    
    if user.otp_enabled:
        user.otp_base32 = pyotp.random_base32()
        user.otp_verified = False
        user.token = User.encode_auth_token(
            user_id = user.id,
            expiration_timedelta = timedelta(seconds=LOGIN_TOKEN_OTP_EXPIRATION_SECONDS)
        )
        response = jsonify({'otp': user.otp_base32})
    else:
        user.token = User.encode_auth_token(
            user_id=user.id, 
            expiration_timedelta = timedelta(minutes=LOGIN_TOKEN_EXPIRATION_MINUTES)
        )
        response = jsonify({'message': f'{user} logged in successfully'})
        
    db.session.commit()
    
    session['token'] = user.token
    
    return response
    
@app.route('/login-2fa-validation', methods=['POST'])
@has_valid_token
def login_2fa_validation():
    data = request.get_json()
    try:
        Login2FASchema().load(data)
    except ValidationError as err:
        response = jsonify({'error': err.messages})
        response.status_code = 400
        return response

    user = User.query.filter_by(token=session['token']).first()
    if user and not user.otp_enabled:
        response = jsonify({'error': 'User 2FA is disabled.'})
        response.status_code = 409
        return response
    if user.otp_base32 != request.get_json().get('otp'):
        response = jsonify({'error': 'OTP invalid'})
        response.status_code = 400
        return response

    user.otp_verified = True
    user.token = User.encode_auth_token(
        user.id, timedelta(minutes=LOGIN_TOKEN_EXPIRATION_MINUTES))
    db.session.commit()
    session['token'] = user.token
    return jsonify({'otp_valid': True})

@app.route('/logout')
@login_required
def logout():
    session.clear()
    return jsonify({'message': 'Logged out successfully'})

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
