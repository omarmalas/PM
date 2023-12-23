from flask import Flask, render_template, request, redirect, url_for, jsonify
import secrets
import string
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

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
    # Check if the password has at least 10 characters
    if len(password) < 10:
        return 'Weak'

    # Check if the password contains both uppercase and lowercase characters
    if not any(c.isupper() for c in password) or not any(c.islower() for c in password):
        return 'Weak'

    # Check if the password contains at least one digit
    if not any(c.isdigit() for c in password):
        return 'Moderate'

    # Check if the password contains at least one symbol
    if not any(c in string.punctuation for c in password):
        return 'Moderate'

    # Check if no more than two characters are in a row
    consecutive_chars = sum(1 for i, j in zip(password, password[1:]) if ord(j) - ord(i) == 1)
    if consecutive_chars < 2:
        return 'Moderate'

    # If the password passes the above checks, consider it strong
    return 'Strong'


def get_strength_message(strength):
    if strength == 'Weak':
        return 'Password is too short. Please use at least 10 characters.'
    elif strength == 'Moderate':
        return 'Password could be stronger. Consider using a mix of uppercase, lowercase, digits, symbols, and avoiding consecutive characters.'
    elif strength == 'Strong':
        return 'Strong password! Good job!'
    else:
        return 'Invalid password strength.'


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

        return jsonify({'strength': strength, 'message': message})

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


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
