from flask import Blueprint, render_template, request, jsonify
from app import db, bcrypt
from models import User

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # login logic 
        data = request.form
        user = User.query.filter_by(email=data['email']).first()
        
        if user and bcrypt.check_password_hash(user.password, data['password']):
            # If login is successful, redirect to the dashboard or home
            return jsonify(message="Login successful!"), 200
        else:
            # If login fails, return an error
            return jsonify(message="Login failed!"), 401

    return render_template('auth/login.html')

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.form
        hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        user = User(username=data['username'], email=data['email'], password=hashed_password)
        db.session.add(user)
        db.session.commit()
        return jsonify(message="User registered successfully!"), 201
    
    return render_template('auth/register.html')

