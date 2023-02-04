import unittest
import time
import pyotp
from flask import current_app
from datetime import timedelta
from app import app, db, User, generate_password_hash


class TestApp(unittest.TestCase):
   
    def setUp(self):
        app.config["TESTING"] = True
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite"
        self.app = app
        self.appctx = self.app.app_context()
        self.appctx.push()
        db.create_all()
        self.populate_db()
        self.client = self.app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.appctx.pop()
        self.app = None
        self.appctx = None
        self.client = None
        
    def populate_db(self):
        self.user_no_2fa = User(
            email='mariorossi@example.com', 
            password=generate_password_hash('test1234'),
            first_name="mario",
            last_name="rossi"
        )
        self.user_with_2fa = User(
            email='mariobianchi@example.com', 
            password=generate_password_hash('test1234'),
            first_name="mario",
            last_name="bianchi",
            otp_enabled=True
        )
        db.session.add(self.user_no_2fa)
        db.session.add(self.user_with_2fa)
        db.session.commit()

    def login_user_with_2fa_disabled(self):
        self.client.post('/login', json={
            'email': self.user_no_2fa.email,
            'password': 'test1234'
        })
        
    def login_user_with_2fa_enabled(self):
        self.client.post('/login', json={
            'email': self.user_with_2fa.email,
            'password': 'test1234'
        })

    def test_app(self):
        assert self.app is not None
        assert current_app == self.app

    def test_api_register(self):
        """
        GIVEN a Flask application configured for testing
        WHEN the '/signup' api is posted with valid data
        THEN check the response is valid and the new user is stored properly
        """
        # register user who does not enable 2FA
        response = self.client.post('/signup', json={
            'email': 'marioneri@example.com',
            'password': 'test1234',
            'first_name': 'mario',
            'last_name': 'neri'
        })
        assert response.status_code == 201
        user = User.query.filter_by(email='marioneri@example.com').first()
        assert user is not None
        assert user.verify_password('test1234')
        assert user.first_name == 'mario'
        assert user.last_name == 'neri'
        assert user.otp_enabled == False
        
        # register user who enables 2FA
        response = self.client.post('/signup', json={
            'email': 'mariorosa@example.com',
            'password': 'test1234',
            'first_name': 'mario',
            'last_name': 'neri',
            'otp_enabled': True
        })
        assert response.status_code == 201
        user = User.query.filter_by(email='mariorosa@example.com').first()
        assert user is not None
        assert user.verify_password('test1234')
        assert user.first_name == 'mario'
        assert user.last_name == 'neri'
        assert user.otp_enabled == True
        
    def test_api_register_user_invalid_in_request_data(self):
        """
        GIVEN a Flask application configured for testing
        WHEN the '/signup' api is posted to (POST)
        THEN check the response status is 400 when request data are wrong
        """
        
        # email null
        response = self.client.post('/signup', json={
            'email': None,
            'password': 'test1234',
            'first_name': 'mario',
            'last_name': 'neri'
        })
        assert response.status_code == 400
        
        # missing email in request data
        response = self.client.post('/signup', json={
            'password': 'test1234',
            'first_name': 'mario',
            'last_name': 'neri'
        })
        assert response.status_code == 400
        
        # email is not a string
        response = self.client.post('/signup', json={
            'email': 2,
            'password': 'test1234',
            'first_name': 'mario',
            'last_name': 'neri'
        })
        assert response.status_code == 400
        
        # password is null
        response = self.client.post('/signup', json={
            'email': 'marioneri@example.com',
            'password': None,
            'first_name': 'mario',
            'last_name': 'neri'
        })
        assert response.status_code == 400
        
        # missing password in request data
        response = self.client.post('/signup', json={
            'email': 'marioneri@example.com',
            'first_name': 'mario',
            'last_name': 'neri'
        })
        assert response.status_code == 400
        
        # first_name is not a string
        response = self.client.post('/signup', json={
            'email': 'marioneri@example.com',
            'password': 'test1234',
            'first_name': 1,
            'last_name': 'neri'
        })
        assert response.status_code == 400
        
        # last_name is not a string
        response = self.client.post('/signup', json={
            'email': 'marioneri@example.com',
            'password': 'test1234',
            'first_name': 'mario',
            'last_name': 1
        })
        assert response.status_code == 400
        
        # otp_enabled is not a valid boolean
        response = self.client.post('/signup', json={
            'email': 'marioneri@example.com',
            'password': 'test1234',
            'first_name': 'mario',
            'last_name': 'neri',
            'otp_enabled': 'test'
        })
        assert response.status_code == 400

    def test_api_register_user_already_registered(self):
        """
        GIVEN a Flask application configured for testing
        WHEN the '/signup' api is posted to (POST)
        THEN check the response status is 409 when trying to register a user with email already registered
        """
        response = self.client.post('/signup', json={
            'email': self.user_no_2fa.email,
            'password': 'test1234',
            'first_name': self.user_no_2fa.first_name,
            'last_name': self.user_no_2fa.last_name
        })
        assert response.status_code == 409

    def test_login(self):
        """
        GIVEN a Flask application configured for testing
        WHEN the '/login' api is posted to (POST)
        THEN check the response status is 200 and a valid token is assigned to user logged in
        """        
        response = self.client.post('/login', json={
            'email': self.user_no_2fa.email,
            'password': 'test1234'
        })
        is_token_valid, result = User.decode_auth_token(self.user_no_2fa.token)
        assert response.status_code == 200
        assert is_token_valid
        assert self.user_no_2fa.id == result
        
        response = self.client.post('/login', json={
            'email': self.user_with_2fa.email,
            'password': 'test1234'
        })
        is_token_valid, result = User.decode_auth_token(self.user_no_2fa.token)
        assert response.status_code == 200
        assert is_token_valid
        assert self.user_no_2fa.id == result
        assert self.user_with_2fa.otp_verified == False
        assert response.get_json()['otp'] == self.user_with_2fa.otp_base32
            
    def test_login_invalid_credentials(self):
        """
        GIVEN a Flask application configured for testing
        WHEN the '/login' api is posted with invalid credentials
        THEN check the response status is 401
        """
        response = self.client.post('/login', json={
            'email': self.user_no_2fa.email,
            'password': 'test',
        })
        assert response.status_code == 401
        
    def test_login_invalid_request_data(self):
        """
        GIVEN a Flask application configured for testing
        WHEN the '/login' api is posted with missing data
        THEN check the response status is 401
        """
        # missing email value
        response = self.client.post('/login', json={
            'password': 'test1234'
        })
        assert response.status_code == 400
        
        # missing password value
        response = self.client.post('/login', json={
            'email': 'mariorossi@example.com'
        })
        assert response.status_code == 400

    def test_login_2fa(self):
        """
        GIVEN a Flask application configured for testing
        WHEN the '/login-2fa-validation' api is posted with valid OTP
        THEN check the response status is 200, the user otp_verified value is True, and
            the user token value is changed from the login api
        """        
        self.login_user_with_2fa_enabled()
        temp_token = self.user_with_2fa.token
        
        response = self.client.post('/login-2fa-validation', json={
            'otp': self.user_with_2fa.otp_base32
        })
        assert response.status_code == 200
        assert self.user_with_2fa.otp_verified == True
        assert temp_token != self.user_with_2fa.token

    def test_login_2fa_without_sending_login_credentials(self):
        """
        GIVEN a Flask application configured for testing
        WHEN the '/login-2fa-validation' api is posted with valid OTP
        THEN check the response status is 401 if  
        """
        response = self.client.post('/login-2fa-validation', json={
            'otp': pyotp.random_base32()
        })
        assert response.status_code == 401
        
    def test_login_2fa_invalid_otp(self):
        """
        GIVEN a Flask application configured for testing
        WHEN the '/login-2fa-validation' api is posted with random valid OTP
        THEN check the response status is 400
        """
        self.login_user_with_2fa_enabled()
        response = self.client.post('/login-2fa-validation', json={
            'otp': pyotp.random_base32()
        })
        assert response.status_code == 400
        
    def test_login_2fa_invalid_request_data(self):
        """
        GIVEN a Flask application configured for testing
        WHEN the '/login-2fa-validation' api is posted with invalid request data
        THEN check the response status is 400
        """
        # request data with null payload
        self.login_user_with_2fa_enabled()
        response = self.client.post('/login-2fa-validation', json={})
        assert response.status_code == 400
        
        # request data with wrong payload
        response = self.client.post('/login-2fa-validation', json={
            'test': 'test'
        })
        assert response.status_code == 400

    def test_login_2fa_otp_not_enabled(self):
        """
        GIVEN a Flask application configured for testing
        WHEN the '/login-2fa-validation' api is posted with random valid OTP 
            but the user logged in did not enabled 2FA
        THEN check the response status is 400
        """
        self.login_user_with_2fa_disabled()
        response = self.client.post('/login-2fa-validation', json={
            'otp': pyotp.random_base32()
        })
        assert response.status_code == 409

    def test_login_2fa_expired_otp(self):
        """
        GIVEN a Flask application configured for testing
        WHEN the '/login-2fa-validation' api is posted with valid OTP but after 
            the login token is expired
        THEN check the response status is 401
        """
        self.login_user_with_2fa_enabled()
        with self.client.session_transaction() as session:
            new_temp_token = User.encode_auth_token(self.user_with_2fa.id, timedelta(seconds=1))
            session['token'] = new_temp_token
        self.user_with_2fa.token = new_temp_token
        time.sleep(1)
        response = self.client.post('/login-2fa-validation', json={
            'otp': self.user_with_2fa.otp_base32
        })
        assert response.status_code == 401
        
    def test_logout(self):
        """
        GIVEN a Flask application configured for testing
        WHEN the '/logout' api is called to (GET)
        THEN check the response status is 200
        """
        self.login_user_with_2fa_disabled()
        with self.client.session_transaction() as session:
            assert session.get('token') is not None
        
        response = self.client.get('/logout')
        with self.client.session_transaction() as session:
            assert session.get('token') is None
            assert response.status_code == 200
        
    def test_login_required_api(self):
        """
        GIVEN a Flask application configured for testing
        WHEN the '/logout' api is called to (GET)
        THEN check the response status is 401
        """
        self.login_user_with_2fa_enabled()
        assert self.user_with_2fa.otp_verified == False
        
        response = self.client.get('/logout')
        assert response.status_code == 401
