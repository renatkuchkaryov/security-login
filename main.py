import io
import ssl
import secrets
import hashlib
import time
import smtplib
import threading
from email.message import EmailMessage
import base64
import pyotp
import qrcode
from cryptography.fernet import Fernet
from werkzeug.middleware.proxy_fix import ProxyFix
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
import os
import sqlite3
from functools import wraps

from dotenv import load_dotenv
load_dotenv()  # .env yuklenir

from flask import Flask, render_template, request, redirect, url_for, session, abort
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]  # açarsız giriş yox
app.config["SESSION_COOKIE_HTTPONLY"] = True   # js cookie oxuya bilmir
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# Secure-cookie 
HTTPS_ENABLED = os.environ.get("HTTPS_ENABLED", "0") == "1"
app.config["SESSION_COOKIE_SECURE"] = HTTPS_ENABLED
app.config["PERMANENT_SESSION_LIFETIME"] = 1800  # sesiyanın vaxtı 30dəq

DATABASE = os.environ.get("DATABASE_PATH", "database.db")
ph = PasswordHasher()  # Argon2id, salting üçün
fernet = Fernet(os.environ["FERNET_KEY"].encode())


def encrypt(text):
    return fernet.encrypt(text.encode()).decode()


def decrypt(token):
    return fernet.decrypt(token.encode()).decode()
# loglanma
logging.basicConfig(
    filename="security.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)
security_log = logging.getLogger("security")

ALERT_FROM = os.environ.get("ALERT_EMAIL_FROM")
ALERT_PASSWORD = os.environ.get("ALERT_EMAIL_PASSWORD")
ALERT_TO = os.environ.get("ALERT_EMAIL_TO")
_last_alert = {}


def _send_email(to, subject, body):
    try:
        msg = EmailMessage()
        msg["Subject"] = f"[LoginProject] {subject}"
        msg["From"] = ALERT_FROM
        msg["To"] = to
        msg.set_content(body)
        with smtplib.SMTP("smtp.gmail.com", 587, timeout=10) as server:
            server.starttls(context=ssl.create_default_context())
            server.login(ALERT_FROM, ALERT_PASSWORD)
            server.send_message(msg)
    except Exception:
        security_log.error("ALERT EMAIL FAILED")


def send_alert(subject, body, cooldown=600):
    if not (ALERT_FROM and ALERT_PASSWORD and ALERT_TO):
        return
    now = time.time()
    if now - _last_alert.get(subject, 0) < cooldown:
        return
    _last_alert[subject] = now
    threading.Thread(target=_send_email, args=(ALERT_TO, subject, body), daemon=True).start()
# brute force qarşı
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per hour"],
    storage_uri="memory://",
)

# CSRF 
csrf = CSRFProtect(app)

def get_conn():
    return sqlite3.connect(DATABASE)


def init_db():
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            email_encrypted TEXT,
            totp_secret_encrypted TEXT,
            totp_enabled INTEGER NOT NULL DEFAULT 0
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS known_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            device_hash TEXT NOT NULL,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_ip TEXT,
            UNIQUE(user_id, device_hash)
        )
    ''')
    cursor.execute('SELECT COUNT(*) FROM users')
    if cursor.fetchone()[0] == 0:
        admin_password = os.environ["ADMIN_PASSWORD"]
        cursor.execute(
            'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
            ('admin', ph.hash(admin_password), 'admin')
        )
    conn.commit()
    conn.close()


# Access control

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

def check_device(user_id, username, response):
    device_id = request.cookies.get("device_id")
    if not device_id:
        device_id = secrets.token_urlsafe(32)
        response.set_cookie(
            "device_id", device_id, max_age=60 * 60 * 24 * 365,
            httponly=True, secure=HTTPS_ENABLED, samesite="Lax"
        )
    device_hash = hashlib.sha256(device_id.encode()).hexdigest()
    ip = get_remote_address()

    conn = get_conn()
    has_any = conn.execute(
        'SELECT 1 FROM known_devices WHERE user_id = ? LIMIT 1', (user_id,)
    ).fetchone()
    known = conn.execute(
        'SELECT 1 FROM known_devices WHERE user_id = ? AND device_hash = ?',
        (user_id, device_hash)
    ).fetchone()

    if known:
        conn.execute(
            'UPDATE known_devices SET last_seen = CURRENT_TIMESTAMP, last_ip = ? '
            'WHERE user_id = ? AND device_hash = ?', (ip, user_id, device_hash)
        )
    else:
        conn.execute(
            'INSERT INTO known_devices (user_id, device_hash, last_ip) VALUES (?, ?, ?)',
            (user_id, device_hash, ip)
        )
    row = conn.execute(
        'SELECT email_encrypted FROM users WHERE id = ?', (user_id,)
    ).fetchone()
    conn.commit()
    conn.close()

    if not known and has_any and row and row[0] and ALERT_FROM:
        user_agent = " ".join(request.headers.get("User-Agent", "unknown").split())[:150]
        body = (
            f"Hello, {username}.\n\n"
            f"Your account was just signed in to from a new device.\n\n"
            f"Time (UTC): {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())}\n"
            f"IP address: {ip}\n"
            f"Browser: {user_agent}\n\n"
            f"If this was you, no action is needed.\n"
            f"If this was NOT you, contact the administrator immediately "
            f"and do not use this account until the issue is resolved.\n\n"
            f"This message contains no links on purpose: never trust emails "
            f"asking you to click a link to 'secure' your account."
        )
        threading.Thread(
            target=_send_email, args=(decrypt(row[0]), "New sign-in to your account", body),
            daemon=True
        ).start()
        security_log.warning("NEW DEVICE | user=%s | ip=%s", username, ip)

def finish_login(user_id, username, role):
    session.clear()
    session.permanent = True
    session["user_id"] = user_id
    session["username"] = username
    session["role"] = role
    security_log.info("LOGIN OK | user=%s | ip=%s", username, get_remote_address())

    target = "show_users" if role == "admin" else "profile"
    response = redirect(url_for(target))
    check_device(user_id, username, response)
    return response
def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        if session.get("role") != "admin":
            abort(403)  
        return f(*args, **kwargs)
    return wrapper


# Marşrutlar

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("10 per hour", methods=["POST"])
def register():
    message = ""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        if not (3 <= len(username) <= 30):
            message = "Username must be 3-30 characters."
        elif "@" not in email or len(email) > 100:
            message = "Please enter a valid email."
        elif len(password) < 8:
            message = "Password must be at least 8 characters."
        else:
            try:
                conn = get_conn()
                conn.execute(
                    'INSERT INTO users (username, password_hash, email_encrypted) VALUES (?, ?, ?)',
                    (username, ph.hash(password), encrypt(email))
                )
                conn.commit()
                conn.close()
                security_log.info("REGISTER | user=%s | ip=%s", username, get_remote_address())
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                message = "This username is already taken!"
            except Exception:
                message = "Something went wrong. Please try again."

    return render_template('register.html', message=message)

@app.route('/', methods=['GET', 'POST'])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    message = ""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        ip = get_remote_address()

        conn = get_conn()
        user = conn.execute(
            'SELECT id, username, password_hash, role, totp_enabled FROM users WHERE username = ?',
            (username,)
        ).fetchone()
        conn.close()

        try:
            if user is None:
                raise VerifyMismatchError()
            ph.verify(user[2], password)
        except VerifyMismatchError:
            security_log.warning("LOGIN FAILED | user=%s | ip=%s", username, ip)
            message = "Invalid username or password."
        else:
            if user[4]:  
                session.clear()
                session["pending_user_id"] = user[0]
                return redirect(url_for("verify_2fa"))
            return finish_login(user[0], user[1], user[3])

    return render_template('login.html', message=message)


@app.route('/profile')
@login_required
def profile():
    return (f"Welcome, {session['username']}! "
            f"<a href='{url_for('setup_2fa')}'>Enable 2FA</a> | "
            f"<a href='{url_for('logout')}'>Logout</a>")


@app.route('/admin/users')
@admin_required
def show_users():
    conn = get_conn()
    rows = conn.execute('SELECT id, username, role, email_encrypted FROM users').fetchall()
    conn.close()
    all_users = [(r[0], r[1], r[2], decrypt(r[3]) if r[3] else "-") for r in rows]
    return render_template('admin.html', users=all_users)


@app.route('/delete/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    if user_id == session["user_id"]:
        abort(400)  # özünü silmək olmaz

    conn = get_conn()
    send_alert("User deleted", f"Target id: {user_id}\nBy: {session['username']}")
    security_log.warning(
    "USER DELETED | target_id=%s | by=%s | ip=%s",
    user_id, session["username"], get_remote_address())
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.execute('DELETE FROM known_devices WHERE user_id = ?', (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('show_users'))


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/2fa', methods=['GET', 'POST'])
@limiter.limit("5 per minute", methods=["POST"])
def verify_2fa():
    user_id = session.get("pending_user_id")
    if not user_id:
        return redirect(url_for("login"))

    message = ""
    if request.method == 'POST':
        code = request.form.get('code', '').strip()

        conn = get_conn()
        user = conn.execute(
            'SELECT id, username, role, totp_secret_encrypted FROM users WHERE id = ?',
            (user_id,)
        ).fetchone()
        conn.close()

        secret = decrypt(user[3])
        if pyotp.TOTP(secret).verify(code, valid_window=1):
            return finish_login(user[0], user[1], user[2])

        security_log.warning("2FA FAILED | user=%s | ip=%s", user[1], get_remote_address())
        message = "Invalid code."

    return render_template('verify_2fa.html', message=message)


@app.route('/setup-2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    message = ""
    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        secret = session.get("new_totp_secret")

        if secret and pyotp.TOTP(secret).verify(code, valid_window=1):
            conn = get_conn()
            conn.execute(
                'UPDATE users SET totp_secret_encrypted = ?, totp_enabled = 1 WHERE id = ?',
                (encrypt(secret), session["user_id"])
            )
            conn.commit()
            conn.close()
            session.pop("new_totp_secret", None)
            security_log.info("2FA ENABLED | user=%s | ip=%s", session["username"], get_remote_address())
            return "2FA enabled! <a href='/profile'>Back</a>"
        message = "Invalid code, try again."

    if "new_totp_secret" not in session:
        session["new_totp_secret"] = pyotp.random_base32()
    secret = session["new_totp_secret"]

    uri = pyotp.TOTP(secret).provisioning_uri(
        name=session["username"], issuer_name="LoginProject"
    )
    buffer = io.BytesIO()
    qrcode.make(uri).save(buffer, format="PNG")
    qr_b64 = base64.b64encode(buffer.getvalue()).decode()

    return render_template('setup_2fa.html', qr=qr_b64, secret=secret, message=message)

@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline'; frame-ancestors 'none'"
    )
    response.headers["Cache-Control"] = "no-store"
    if HTTPS_ENABLED:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

@app.errorhandler(429)
def too_many_requests(e):
    ip = get_remote_address()
    security_log.warning("RATE LIMIT HIT | ip=%s | path=%s", get_remote_address(), request.path)
    send_alert("Rate limit triggered", f"IP: {ip}\nPath: {request.path}")
    return "Too many attempts. Please wait a minute and try again.", 429
init_db()  

if __name__ == '__main__':
    app.run(debug=False)
# import sqlite3
# from flask import Flask, render_template, request, redirect, url_for

# app = Flask(__name__)

# def init_db():
#     conn = sqlite3.connect('database.db')
#     cursor = conn.cursor()
#     cursor.execute('''
#         CREATE TABLE IF NOT EXISTS users (
#             id INTEGER PRIMARY KEY AUTOINCREMENT,
#             username TEXT UNIQUE NOT NULL,
#             password TEXT NOT NULL
#         )
#     ''')
#     cursor.execute('SELECT COUNT(*) FROM users')
#     if cursor.fetchone()[0] == 0:
#         cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', ('admin', '12345'))
#         conn.commit()
#     conn.close()


# @app.route('/register', methods=['GET', 'POST'])
# def register():
#     message = ""
#     if request.method == 'POST':
#         username = request.form.get('username')
#         password = request.form.get('password')

#         try:
#             conn = sqlite3.connect('database.db')
#             cursor = conn.cursor()
#             cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
#             conn.commit()
#             conn.close()
#             return redirect(url_for('login'))
#         except sqlite3.IntegrityError:
#             message = "This username is already taken!"
#         except Exception as e:
#             message = f"An error occurred: {e}"

#     return render_template('register.html', message=message)

# @app.route('/', methods=['GET', 'POST'])
# def login():
#     message = ""
#     if request.method == 'POST':
#         username = request.form.get('username')
#         password = request.form.get('password')

#         try:
#             conn = sqlite3.connect('database.db')
#             cursor = conn.cursor()
#             cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
#             conn.commit()
#             conn.close()
#             return redirect(url_for('login'))
#         except sqlite3.IntegrityError:
#             message = "This username is already taken!"
#         except Exception as e:
#             message = f"An error occurred: {e}"
#         conn = sqlite3.connect('database.db')
#         cursor = conn.cursor()
#         cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))
#         user = cursor.fetchone()
#         conn.close()

#         if user:
#             if username == 'admin':
#                 return redirect(url_for('show_users'))
            
#         #     message = f"Welcome, {username}! You are logged in."
#         # else:
#         #     message = "Invalid username or password."

#     return render_template('login.html', message=message)

# @app.route('/admin/users')
# def show_users():
#     conn = sqlite3.connect('database.db')
#     cursor = conn.cursor()
#     cursor.execute('SELECT id, username, password FROM users')
#     all_users = cursor.fetchall()
#     conn.close()
#     return render_template('admin.html', users=all_users)

# @app.route('/delete/<int:user_id>')
# def delete_user(user_id):
#     conn = sqlite3.connect('database.db')
#     cursor = conn.cursor()
#     cursor.execute('SELECT username FROM users WHERE id = ?', (user_id,))
#     user = cursor.fetchone()
#     username = user[0] if user else "Unknown"
#     cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
#     conn.commit()
#     conn.close()
#     print(f"[SUCCESS] User '{username}' was permanently removed from database.db\n")
#     return redirect(url_for('show_users'))


# if __name__ == '__main__':
#     init_db() 
#     app.run(debug=True)


