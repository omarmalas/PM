from flask import Flask, render_template, request, redirect, url_for
import secrets
# used for generating cryptographically strong random numbers suitable for managing data such as passwords,
# account authentication, security tokens, and related secrets.
import string
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_bcrypt import check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)


with app.app_context():
    db.create_all()


# https://github.com/yanalabuseini/hexxus/tree/main


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            username = request.form['username']
            plain_password = request.form['password']

            # Hash the password before storing it
            hashed_password = bcrypt.generate_password_hash(plain_password).decode('utf-8')

            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()

            return redirect(url_for('index'))
        except KeyError:
            return render_template('register.html', error='Invalid form data.')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            username = request.form['username']
            plain_password = request.form['password']

            user = User.query.filter_by(username=username).first()

            if user and check_password_hash(user.password, plain_password):
                # Password matches
                return redirect(url_for('index'))
            else:
                return render_template('login.html', error='Invalid username or password.')
        except KeyError:
            return render_template('login.html', error='Invalid form data.')

    return render_template('login.html')


def generate_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(characters) for _ in range(length))
    return password


@app.route('/generate_password', methods=['POST'])
def generate_password_route():
    try:
        password_length = int(request.form.get('password_length', 12))
        generated_password = generate_password(password_length)
        return render_template('index.html', generated_password=generated_password)
    except ValueError:
        return render_template('index.html', error="Invalid input. Please enter a valid number for password length.")


@app.route('/check_strength', methods=['POST'])
def check_strength():
    password = request.form.get('password')
    # Implement password strength checking logic here
    strength = "strong"  # replace with actual strength
    return render_template('password_strength.html', strength=strength)


if __name__ == '__main__':
    app.run(debug=True)
