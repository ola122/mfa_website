from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
import pyotp
import qrcode
import io
from base64 import b64encode

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['MAIL_SERVER'] = 'smtp.example.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@example.com'
app.config['MAIL_PASSWORD'] = 'your_email_password'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)
mail = Mail(app)

# Initialize Flask-Limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    mfa_secret = db.Column(db.String(16))
    login_attempts = db.Column(db.Integer, default=0)
    is_locked = db.Column(db.Boolean, default=False)

@app.before_request
def require_login():
    protected_routes = ['dashboard', 'mfa', 'change_password']
    if 'username' not in session and request.endpoint in protected_routes:
        return redirect(url_for('login'))

@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        mfa_secret = pyotp.random_base32()
        new_user = User(username=username, password=password, mfa_secret=mfa_secret)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! You can now log in.')
        return redirect(url_for('index'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Apply rate limiting to the login route
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.is_locked:
            flash('Account locked due to too many failed login attempts.')
            return render_template('login.html')
        if user and bcrypt.check_password_hash(user.password, password):
            user.login_attempts = 0
            user.is_locked = False
            db.session.commit()
            session['username'] = username
            session['authenticated'] = False  # Initially not authenticated until MFA
            return redirect(url_for('mfa'))
        else:
            if user:
                user.login_attempts += 1
                if user.login_attempts >= 5:
                    user.is_locked = True
                db.session.commit()
            flash('Invalid username or password')
    return render_template('login.html')

@app.route('/mfa', methods=['GET', 'POST'])
def mfa():
    if 'username' not in session:
        return redirect(url_for('login'))
    user = User.query.filter_by(username=session['username']).first()
    if request.method == 'POST':
        otp = request.form['otp']
        totp = pyotp.TOTP(user.mfa_secret)
        if totp.verify(otp):
            session['authenticated'] = True
            user.login_attempts = 0  # Reset login attempts on successful login
            db.session.commit()
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid MFA code')
    img = qrcode.make(pyotp.totp.TOTP(user.mfa_secret).provisioning_uri(name=user.username, issuer_name="MFA App"))
    buf = io.BytesIO()
    img.save(buf)
    img_str = b64encode(buf.getvalue()).decode('ascii')
    return render_template('mfa.html', img_data=img_str)

@app.route('/dashboard')
def dashboard():
    if 'authenticated' not in session or not session['authenticated']:
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'username' not in session:
        flash('You need to be logged in to change your password.')
        return redirect(url_for('login'))
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        user = User.query.filter_by(username=session['username']).first()
        if user and bcrypt.check_password_hash(user.password, current_password):
            user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            db.session.commit()
            flash('Your password has been updated!')
            return redirect(url_for('dashboard'))
        else:
            flash('Current password is incorrect.')
    return render_template('change_password.html')

@app.route('/logout')
def logout():
    session.clear()  # Clear all session data
    return redirect(url_for('index'))

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(username=email).first()
        if user:
            token = s.dumps(email, salt='email-confirm')
            msg = Message('Password Reset Request', sender='noreply@example.com', recipients=[email])
            link = url_for('reset_token', token=token, _external=True)
            msg.body = f'Your link to reset password is {link}'
            mail.send(msg)
            flash('Password reset email has been sent.')
            return redirect(url_for('login'))
    return render_template('reset_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
    except:
        flash('The reset link is invalid or has expired.', 'danger')
        return redirect(url_for('reset_password'))
    if request.method == 'POST':
        user = User.query.filter_by(username=email).first()
        if user:
            password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
            user.password = password
            db.session.commit()
            flash('Your password has been updated!')
            return redirect(url_for('login'))
    return render_template('reset_token.html')

@app.errorhandler(429)
def ratelimit_handler(e):
    return render_template('ratelimit.html'), 429

if __name__ == '__main__':
    app.run(debug=True)
