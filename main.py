from flask import Flask, render_template, request
import secrets #used for generating cryptographically strong random numbers suitable for managing data such as passwords, account authentication, security tokens, and related secrets.
import string

app = Flask(__name__)
#https://github.com/yanalabuseini/hexxus/tree/main



@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login.html')
def login():
    print("welco")

@app.route('/generate_password', methods=['POST'])
def generate_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(characters) for _ in range(length))

    if __name__ == "__main__":
        try:
            password_length = int(request.form.get('password_length', 12))
            generated_password = generate_password(password_length)
            return render_template('index.html', generated_password=generated_password)
        except ValueError:
            return render_template('index.html',
                                   error="Invalid input. Please enter a valid number for password length.")

@app.route('/check_strength', methods=['POST'])
def check_strength():
    password = request.form.get('password')
    # Implement password strength checking logic here
    strength = "strong"  # replace with actual strength
    return render_template('password_strength.html', strength=strength)


if __name__ == '__main__':
    app.run(debug=True)

