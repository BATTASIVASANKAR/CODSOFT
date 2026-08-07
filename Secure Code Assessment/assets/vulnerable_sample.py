import os
import sqlite3
import hashlib
# pyrefly: ignore [missing-import]
from flask import Flask, request, render_template_string

app = Flask(__name__)

# HARDCODED SENSITIVE CREDENTIALS
AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE_SECRET_KEY_HERE"
DB_PASSWORD = "SuperSecretPassword123!"
JWT_SECRET = "my_super_secret_jwt_token_key"

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    # WEAK AUTHENTICATION & HASHING (MD5)
    hashed_pass = hashlib.md5(password.encode()).hexdigest()
    
    # SQL INJECTION VULNERABILITY
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{hashed_pass}'"
    cursor.execute(query) # Dangerous raw SQL query concatenation
    user = cursor.fetchone()
    
    return "Logged in successfully" if user else "Invalid credentials"

@app.route('/ping', methods=['GET'])
def ping():
    host = request.args.get('host')
    
    # COMMAND INJECTION VULNERABILITY
    command = f"ping -c 1 {host}"
    os.system(command) # Unchecked command execution
    return f"Pinged {host}"

@app.route('/greet')
def greet():
    name = request.args.get('name', 'Guest')
    
    # CROSS-SITE SCRIPTING (XSS)
    template = f"<h1>Welcome, {name}!</h1>"
    return render_template_string(template) # Unsanitized user input in template

@app.route('/read_file')
def read_file():
    filename = request.args.get('file')
    
    # INSECURE FILE HANDLING / PATH TRAVERSAL
    file_path = f"/var/www/uploads/{filename}"
    with open(file_path, 'r') as f: # User input directly used in open()
        content = f.read()
    return content

if __name__ == '__main__':
    app.run(debug=True) # DEBUG MODE ENABLED IN PRODUCTION
