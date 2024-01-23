from flask import Flask, render_template, request, redirect, url_for, jsonify, session
import secrets
import string
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from passlib.hash import bcrypt
from termcolor import cprint
import time
import hashlib

valid = []

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = '5f5b2ec60d42939b0e5b78e2d3ecb0b49b22977ff7f516b83459397bcbde2af1'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    passwords = db.relationship('PasswordEntry', backref='user', lazy=True)




@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class PasswordEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('password_strength_route'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if the username is already taken
        if User.query.filter_by(username=username).first():
            return render_template('register.html', error='Username already taken.')

        # Hash the password before storing it in the database
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Create a new user with the hashed password
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        # Log in the newly registered user
        login_user(new_user)

        return redirect(url_for('index'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('password_strength_route'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):  # Fix here: 'password_hash' to 'password'
            login_user(user)
            return redirect(url_for('password_strength_route'))
        else:
            return render_template('login.html', error='Invalid username or password.')

    return render_template('login.html')


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


def generate_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(characters) for _ in range(length))
    return password

def generate_strong_passwords(): #for suggesting strong passwords in password_strength route.
    strong_passwords = [generate_password(12) for _ in range(3)]
    return strong_passwords

@app.route('/generate_password', methods=['GET', 'POST'])
@login_required
def generate_password_route():
    if request.method == 'POST':
        try:
            password_length = int(request.form.get('password_length', 12))
            generated_password = generate_password(password_length)
            return render_template('generate_password.html', generated_password=generated_password)
        except ValueError:
            return render_template('generate_password.html',
                                   error="Invalid input. Please enter a valid number for password length.")
    return render_template('generate_password.html')


def check_password_strength(password):
    # Check if the password has at least 12 characters
    if len(password) < 10:
        return 'Very Weak'

    # Check if the password contains both uppercase and lowercase characters
    elif not any(c.isupper() for c in password):
        return 'Weak'

    elif not any(c.islower() for c in password):
        return 'Weak'

    # Check if the password contains at least two digits
    elif sum(c.isdigit() for c in password) > 2:
        return 'Moderate'

    # Check if the password contains at least one special character
    elif not any(c in string.punctuation for c in password):
        return 'Moderate'

    # Check if no more than three characters are in a row
    consecutive_chars = sum(1 for i, j, k in zip(password, password[1:], password[2:]) if ord(j) - ord(i) == ord(k) - ord(j) == 1)
    if consecutive_chars > 3:
        return 'Moderate'

    # Check if the password contains a mix of letters, digits, and special characters
    elif not (any(c.isalpha() for c in password) and any(c.isdigit() for c in password) and any(c in string.punctuation for c in password)):
        return 'Strong'

    # If the password passes the above checks, consider it strong
    return 'Strong'



def get_strength_message(strength):
    if strength == 'Very Weak':
        return 'Your password is categorized as very weak. It is highly recommended to improve its security by increasing its length to at least 12 characters.'
    elif strength == 'Weak':
        return 'Your password is categorized as weak. This classification is due to the relatively short length and absence of diverse character types. To enhance its strength, consider increasing the length to at least 12 characters and incorporating a mix of uppercase and lowercase letters, along with digits.'
    elif strength == 'Moderate':
        return 'Your password is assessed as moderate in strength. The recommendations for improvement include increasing its length, using a combination of uppercase and lowercase letters, incorporating digits, symbols, and avoiding consecutive characters. Additionally, consider including a mix of letters, digits, and special characters for added security.'
    elif strength == 'Strong':
        return 'Congratulations! Your password is classified as strong. It meets the recommended criteria for a secure password, including a sufficient length and a diverse combination of character types.'
    else:
        return 'The provided password strength is invalid. Please check your input.'




@app.route('/password_strength', methods=['GET', 'POST'])
@login_required
def password_strength_route():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))

    if request.method == 'POST':
        password = request.form.get('password')

        if not password:
            return jsonify({'strength': 'Invalid'})

        strength = check_password_strength(password)

        # Add a message based on the password strength
        message = get_strength_message(strength)

        # Generate strong password suggestions if the entered password is weak or very weak
        strong_passwords = []
        if strength in ['Weak', 'Very Weak']:
            strong_passwords = generate_strong_passwords()

        # Store strong passwords in session for later use
        session['strong_passwords'] = strong_passwords

        return render_template('password_strength.html', strength=strength, message=message, strong_passwords=strong_passwords)

    return render_template('password_strength.html')


@app.route('/dashboard/<int:user_id>', methods=['GET', 'POST'])
@login_required
def dashboard(user_id):
    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        service = request.form['service']
        password = request.form['password']
        new_entry = PasswordEntry(service=service, password=password, user=user)
        db.session.add(new_entry)
        db.session.commit()

    entries = PasswordEntry.query.filter_by(user=user).all()
    return render_template('dashboard.html', user=user, entries=entries)


@app.route('/remove_password/<int:user_id>/<int:entry_id>')
@login_required
def remove_password(user_id, entry_id):
    user = User.query.get_or_404(user_id)
    entry = PasswordEntry.query.get_or_404(entry_id)

    if entry.user != user:
        return redirect(url_for('dashboard', user_id=user.id))

    db.session.delete(entry)
    db.session.commit()
    return redirect(url_for('dashboard', user_id=user.id))

def identify_hash(hash_input):
    # Function to identify the hash type
    hash_algorithms = {
        32: 'md5',
        40: 'sha1',
        56: 'sha224',
        64: 'sha256',
        96: 'sha384',
        128: 'sha512',
        28: 'ripemd160',
        128: 'whirlpool',
        60: 'sha3_224',
        96: 'sha3_384',
        128: 'sha3_512',
        60: 'blake2b',
        128: 'blake2s',
        60: 'shake_128',
        100: 'shake_256',
        # Add more hash algorithms as needed
    }

    # Check for bcrypt
    if hash_input.startswith('$2a$') or hash_input.startswith('$2b$'):
        return 'bcrypt'

    hash_length = len(hash_input)

    if hash_length in hash_algorithms:
        return hash_algorithms[hash_length]
    else:
        return None

def crack_hash(hash_input, hash_type):
    # Function to attempt to crack the hash using a dictionary attack
    password_file = '/root/PM/rockyou.txt'

    with open(password_file, 'r', encoding='latin-1', errors='ignore') as file:
        for password in file:
            password = password.strip()

            if hash_type == 'bcrypt':
                hashed_password = bcrypt.hashpw(password.encode(), hash_input.encode())
            else:
                hashed_password = hashlib.new(hash_type, password.encode()).hexdigest()

            if hashed_password == hash_input:
                return f"Password found: {password}"

    return "Password not found"



@app.route('/process', methods=['GET', 'POST'])
@login_required
def process():
    if request.method == 'POST':
        user_hash = request.form['user_hash']
        hash_type = identify_hash(user_hash)

        if hash_type:
            result = crack_hash(user_hash, hash_type)
            return render_template('result.html', result=result, hash_type=hash_type, error=None)
        else:
            return render_template('result.html', result=None, hash_type=None, error="Invalid hash input.")

    # If the request method is GET, render the form without processing
    return render_template('result.html', result=None, hash_type=None, error=None)



if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
