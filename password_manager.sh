#!/bin/bash

# Password Manager Installation Script for Debian 12
# This script installs a complete password manager web application

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   print_error "This script should not be run as root"
   exit 1
fi

# Update system
print_status "Updating system packages..."
sudo apt update && sudo apt upgrade -y

# Install required packages
print_status "Installing required packages..."
sudo apt install -y nginx postgresql postgresql-contrib python3 python3-pip python3-venv git curl

# Create application directory
APP_DIR="/var/www/password-manager"
print_status "Creating application directory: $APP_DIR"
sudo mkdir -p $APP_DIR
sudo chown $USER:$USER $APP_DIR

# Create Python virtual environment
print_status "Setting up Python virtual environment..."
cd $APP_DIR
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
print_status "Installing Python dependencies..."
pip install flask flask-sqlalchemy flask-login flask-wtf flask-bcrypt python-dotenv psycopg2-binary

# Create Flask application
print_status "Creating Flask application..."

# Create app.py
cat > app.py << 'EOF'
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from flask_bcrypt import Bcrypt
import os
from datetime import datetime
import base64
from cryptography.fernet import Fernet

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-change-this')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'postgresql://pmuser:pmpassword@localhost/password_manager')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Generate encryption key
def generate_key():
    return Fernet.generate_key()

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    encryption_key = db.Column(db.LargeBinary)
    passwords = db.relationship('Password', backref='user', lazy=True, cascade='all, delete-orphan')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100))
    password_encrypted = db.Column(db.LargeBinary, nullable=False)
    url = db.Column(db.String(200))
    notes = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', 
                                   validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign In')

class PasswordForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    username = StringField('Username')
    password = PasswordField('Password', validators=[DataRequired()])
    url = StringField('URL')
    notes = TextAreaField('Notes')
    submit = SubmitField('Save')

# Helper functions
def encrypt_password(password, key):
    f = Fernet(key)
    return f.encrypt(password.encode())

def decrypt_password(encrypted_password, key):
    f = Fernet(key)
    return f.decrypt(encrypted_password).decode()

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # Check if user already exists
        if User.query.filter_by(email=form.email.data).first():
            flash('Email already registered', 'error')
            return render_template('register.html', form=form)
        
        if User.query.filter_by(username=form.username.data).first():
            flash('Username already taken', 'error')
            return render_template('register.html', form=form)
        
        # Create new user
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        encryption_key = generate_key()
        
        user = User(
            username=form.username.data,
            email=form.email.data,
            password_hash=hashed_password,
            encryption_key=encryption_key
        )
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        
        if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password', 'error')
    
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    passwords = Password.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', passwords=passwords)

@app.route('/add_password', methods=['GET', 'POST'])
@login_required
def add_password():
    form = PasswordForm()
    if form.validate_on_submit():
        encrypted_password = encrypt_password(form.password.data, current_user.encryption_key)
        
        password = Password(
            title=form.title.data,
            username=form.username.data,
            password_encrypted=encrypted_password,
            url=form.url.data,
            notes=form.notes.data,
            user_id=current_user.id
        )
        
        db.session.add(password)
        db.session.commit()
        
        flash('Password added successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('password_form.html', form=form, title='Add Password')

@app.route('/edit_password/<int:password_id>', methods=['GET', 'POST'])
@login_required
def edit_password(password_id):
    password = Password.query.get_or_404(password_id)
    
    if password.user_id != current_user.id:
        flash('Unauthorized access', 'error')
        return redirect(url_for('dashboard'))
    
    form = PasswordForm()
    
    if form.validate_on_submit():
        password.title = form.title.data
        password.username = form.username.data
        password.password_encrypted = encrypt_password(form.password.data, current_user.encryption_key)
        password.url = form.url.data
        password.notes = form.notes.data
        password.updated_at = datetime.utcnow()
        
        db.session.commit()
        flash('Password updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    # Pre-fill form with existing data
    form.title.data = password.title
    form.username.data = password.username
    form.password.data = decrypt_password(password.password_encrypted, current_user.encryption_key)
    form.url.data = password.url
    form.notes.data = password.notes
    
    return render_template('password_form.html', form=form, title='Edit Password')

@app.route('/delete_password/<int:password_id>', methods=['POST'])
@login_required
def delete_password(password_id):
    password = Password.query.get_or_404(password_id)
    
    if password.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'Unauthorized access'}), 403
    
    db.session.delete(password)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Password deleted successfully'})

@app.route('/get_password/<int:password_id>')
@login_required
def get_password(password_id):
    password = Password.query.get_or_404(password_id)
    
    if password.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'Unauthorized access'}), 403
    
    decrypted_password = decrypt_password(password.password_encrypted, current_user.encryption_key)
    
    return jsonify({
        'success': True,
        'password': decrypted_password
    })

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
EOF

# Create password form template
cat > templates/password_form.html << 'EOF'
{% extends "base.html" %}

{% block title %}{{ title }} - Password Manager{% endblock %}

{% block content %}
<div style="max-width: 600px; margin: 2rem auto;">
    <div class="card">
        <h2 style="text-align: center; margin-bottom: 2rem; color: #333;">{{ title }}</h2>
        
        <form method="POST">
            {{ form.hidden_tag() }}
            
            <div class="form-group">
                {{ form.title.label(class="form-label") }}
                {{ form.title(class="form-control", placeholder="e.g., Gmail, Facebook, Bank Account") }}
                {% if form.title.errors %}
                    <div style="color: #dc3545; font-size: 0.875rem; margin-top: 0.25rem;">
                        {% for error in form.title.errors %}
                            <span>{{ error }}</span>
                        {% endfor %}
                    </div>
                {% endif %}
            </div>
            
            <div class="form-group">
                {{ form.username.label(class="form-label") }}
                {{ form.username(class="form-control", placeholder="Username or email") }}
                {% if form.username.errors %}
                    <div style="color: #dc3545; font-size: 0.875rem; margin-top: 0.25rem;">
                        {% for error in form.username.errors %}
                            <span>{{ error }}</span>
                        {% endfor %}
                    </div>
                {% endif %}
            </div>
            
            <div class="form-group">
                {{ form.password.label(class="form-label") }}
                <div style="position: relative;">
                    {{ form.password(class="form-control", id="password-input") }}
                    <button type="button" onclick="togglePasswordVisibility()" style="position: absolute; right: 10px; top: 50%; transform: translateY(-50%); background: none; border: none; cursor: pointer; font-size: 1.2rem;">👁️</button>
                </div>
                <button type="button" onclick="generatePassword()" class="btn btn-secondary" style="margin-top: 0.5rem; font-size: 0.9rem; padding: 8px 16px;">Generate Strong Password</button>
                {% if form.password.errors %}
                    <div style="color: #dc3545; font-size: 0.875rem; margin-top: 0.25rem;">
                        {% for error in form.password.errors %}
                            <span>{{ error }}</span>
                        {% endfor %}
                    </div>
                {% endif %}
            </div>
            
            <div class="form-group">
                {{ form.url.label(class="form-label") }}
                {{ form.url(class="form-control", placeholder="https://example.com") }}
                {% if form.url.errors %}
                    <div style="color: #dc3545; font-size: 0.875rem; margin-top: 0.25rem;">
                        {% for error in form.url.errors %}
                            <span>{{ error }}</span>
                        {% endfor %}
                    </div>
                {% endif %}
            </div>
            
            <div class="form-group">
                {{ form.notes.label(class="form-label") }}
                {{ form.notes(class="form-control", rows="3", placeholder="Additional notes...") }}
                {% if form.notes.errors %}
                    <div style="color: #dc3545; font-size: 0.875rem; margin-top: 0.25rem;">
                        {% for error in form.notes.errors %}
                            <span>{{ error }}</span>
                        {% endfor %}
                    </div>
                {% endif %}
            </div>
            
            <div style="display: flex; gap: 1rem; justify-content: center; margin-top: 2rem;">
                {{ form.submit(class="btn") }}
                <a href="{{ url_for('dashboard') }}" class="btn btn-secondary">Cancel</a>
            </div>
        </form>
    </div>
</div>

<script>
function togglePasswordVisibility() {
    const passwordInput = document.getElementById('password-input');
    const button = event.target;
    
    if (passwordInput.type === 'password') {
        passwordInput.type = 'text';
        button.textContent = '🙈';
    } else {
        passwordInput.type = 'password';
        button.textContent = '👁️';
    }
}

function generatePassword() {
    const length = 16;
    const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
    let password = '';
    
    // Ensure at least one character from each category
    const lower = 'abcdefghijklmnopqrstuvwxyz';
    const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const numbers = '0123456789';
    const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';
    
    password += lower[Math.floor(Math.random() * lower.length)];
    password += upper[Math.floor(Math.random() * upper.length)];
    password += numbers[Math.floor(Math.random() * numbers.length)];
    password += symbols[Math.floor(Math.random() * symbols.length)];
    
    // Fill the rest randomly
    for (let i = password.length; i < length; i++) {
        password += charset[Math.floor(Math.random() * charset.length)];
    }
    
    // Shuffle the password
    password = password.split('').sort(() => Math.random() - 0.5).join('');
    
    document.getElementById('password-input').value = password;
    document.getElementById('password-input').type = 'text';
    
    // Show a brief animation
    const input = document.getElementById('password-input');
    input.style.background = '#d4edda';
    input.style.borderColor = '#28a745';
    
    setTimeout(() => {
        input.style.background = 'rgba(255, 255, 255, 0.9)';
        input.style.borderColor = '#e1e1e1';
    }, 1000);
}
</script>
{% endblock %}
EOF

# Install additional Python dependencies
pip install cryptography

# Create environment file
cat > .env << 'EOF'
SECRET_KEY=your-very-secure-secret-key-change-this-in-production
DATABASE_URL=postgresql://pmuser:pmpassword@localhost/password_manager
FLASK_ENV=production
EOF

# Create systemd service file
print_status "Creating systemd service..."
sudo tee /etc/systemd/system/password-manager.service > /dev/null << EOF
[Unit]
Description=Password Manager Flask App
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$APP_DIR
Environment=PATH=$APP_DIR/venv/bin
ExecStart=$APP_DIR/venv/bin/python app.py
Restart=always
RestartSec=10
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=password-manager

[Install]
WantedBy=multi-user.target
EOF

# Setup PostgreSQL
print_status "Setting up PostgreSQL database..."
sudo -u postgres psql << 'EOF'
CREATE USER pmuser WITH PASSWORD 'pmpassword';
CREATE DATABASE password_manager OWNER pmuser;
GRANT ALL PRIVILEGES ON DATABASE password_manager TO pmuser;
\q
EOF

# Create Nginx configuration
print_status "Configuring Nginx..."
sudo tee /etc/nginx/sites-available/password-manager << 'EOF'
server {
    listen 80;
    server_name localhost;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_buffering off;
    }
}
EOF

# Enable Nginx site
sudo ln -sf /etc/nginx/sites-available/password-manager /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default

# Test Nginx configuration
sudo nginx -t

# Create production-ready app runner
cat > run_production.py << 'EOF'
from app import app
import os
from werkzeug.serving import run_simple

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    run_simple('0.0.0.0', port, app, use_reloader=False, use_debugger=False)
EOF

# Update systemd service to use production runner
sudo sed -i 's/ExecStart=.*/ExecStart='$(echo $APP_DIR | sed 's/\//\\\//g')'\/venv\/bin\/python run_production.py/' /etc/systemd/system/password-manager.service

# Set proper permissions
sudo chown -R $USER:$USER $APP_DIR
chmod +x $APP_DIR/run_production.py

# Initialize database
print_status "Initializing database..."
cd $APP_DIR
source venv/bin/activate
python << 'EOF'
from app import app, db
with app.app_context():
    db.create_all()
    print("Database initialized successfully!")
EOF

# Start and enable services
print_status "Starting services..."
sudo systemctl daemon-reload
sudo systemctl enable password-manager
sudo systemctl start password-manager
sudo systemctl enable nginx
sudo systemctl restart nginx

# Create SSL certificate (optional)
print_status "Installing Certbot for SSL..."
sudo apt install -y certbot python3-certbot-nginx

# Create backup script
cat > backup_script.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="/var/backups/password-manager"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory if it doesn't exist
mkdir -p $BACKUP_DIR

# Backup database
sudo -u postgres pg_dump password_manager > $BACKUP_DIR/db_backup_$DATE.sql

# Backup application files
tar -czf $BACKUP_DIR/app_backup_$DATE.tar.gz -C /var/www password-manager

# Keep only last 7 days of backups
find $BACKUP_DIR -name "*.sql" -mtime +7 -delete
find $BACKUP_DIR -name "*.tar.gz" -mtime +7 -delete

echo "Backup completed: $DATE"
EOF

chmod +x backup_script.sh
sudo mv backup_script.sh /usr/local/bin/password-manager-backup

# Add backup to crontab
(crontab -l 2>/dev/null; echo "0 2 * * * /usr/local/bin/password-manager-backup") | crontab -

# Setup firewall
print_status "Configuring firewall..."
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw --force enable

# Final status check
print_status "Checking service status..."
sudo systemctl status password-manager --no-pager
sudo systemctl status nginx --no-pager

# Get server IP
SERVER_IP=$(hostname -I | awk '{print $1}')

print_status "Installation completed!"
echo ""
echo "=========================="
echo "🎉 PASSWORD MANAGER SETUP COMPLETE!"
echo "=========================="
echo ""
echo "📍 Access your password manager at:"
echo "   http://$SERVER_IP"
echo "   http://localhost (if accessing locally)"
echo ""
echo "🔧 Service management:"
echo "   sudo systemctl start password-manager"
echo "   sudo systemctl stop password-manager"
echo "   sudo systemctl restart password-manager"
echo "   sudo systemctl status password-manager"
echo ""
echo "🔄 To update the application:"
echo "   cd $APP_DIR"
echo "   sudo systemctl stop password-manager"
echo "   # Make your changes"
echo "   sudo systemctl start password-manager"
echo ""
echo "💾 Backup command:"
echo "   /usr/local/bin/password-manager-backup"
echo ""
echo "🔒 To setup SSL certificate:"
echo "   sudo certbot --nginx -d your-domain.com"
echo ""
echo "📝 Application logs:"
echo "   sudo journalctl -u password-manager -f"
echo ""
echo "⚙️  Database access:"
echo "   sudo -u postgres psql password_manager"
echo ""
echo "🎨 Features included:"
echo "   ✅ User registration and authentication"
echo "   ✅ Password encryption and storage"
echo "   ✅ Beautiful minimalist UI with animations"
echo "   ✅ Responsive design"
echo "   ✅ Password generator"
echo "   ✅ Secure password viewing"
echo "   ✅ CRUD operations for passwords"
echo "   ✅ Automatic backups"
echo "   ✅ Systemd service"
echo "   ✅ Nginx reverse proxy"
echo "   ✅ Firewall configuration"
echo ""
echo "🛡️  Security features:"
echo "   - Passwords encrypted with user-specific keys"
echo "   - Bcrypt password hashing"
echo "   - Session management"
echo "   - CSRF protection"
echo "   - SQL injection protection"
echo ""
echo "📱 The application is fully responsive and works on:"
echo "   - Desktop browsers"
echo "   - Mobile devices"
echo "   - Tablets"
echo ""
print_warning "IMPORTANT SECURITY NOTES:"
echo "1. Change the SECRET_KEY in $APP_DIR/.env"
echo "2. Change the database password"
echo "3. Setup SSL certificate for production use"
echo "4. Regular backups are scheduled daily at 2 AM"
echo "5. Keep your system updated"
echo ""
echo "🎯 Default database credentials:"
echo "   Database: password_manager"
echo "   User: pmuser"
echo "   Password: pmpassword"
echo "   (Please change these in production!)"
echo ""
echo "Have fun with your new secure password manager! 🔐"

# Create base template
cat > templates/base.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}Password Manager{% endblock %}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            flex: 1;
        }

        /* Header */
        .header {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border-bottom: 1px solid rgba(255, 255, 255, 0.2);
            padding: 1rem 0;
            animation: slideDown 0.6s ease-out;
        }

        .nav {
            display: flex;
            justify-content: space-between;
            align-items: center;
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 20px;
        }

        .logo {
            font-size: 1.5rem;
            font-weight: bold;
            color: white;
            text-decoration: none;
            display: flex;
            align-items: center;
        }

        .logo::before {
            content: "🔒";
            margin-right: 8px;
            font-size: 1.2rem;
        }

        .nav-links {
            display: flex;
            gap: 20px;
        }

        .nav-links a {
            color: white;
            text-decoration: none;
            padding: 8px 16px;
            border-radius: 8px;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }

        .nav-links a::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.2), transparent);
            transition: left 0.5s ease;
        }

        .nav-links a:hover::before {
            left: 100%;
        }

        .nav-links a:hover {
            background: rgba(255, 255, 255, 0.2);
            transform: translateY(-2px);
        }

        /* Card styles */
        .card {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            padding: 2rem;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.2);
            animation: fadeInUp 0.8s ease-out;
            transition: transform 0.3s ease;
        }

        .card:hover {
            transform: translateY(-5px);
        }

        /* Form styles */
        .form-group {
            margin-bottom: 1.5rem;
            position: relative;
        }

        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            color: #333;
            font-weight: 500;
            transition: color 0.3s ease;
        }

        .form-group input,
        .form-group textarea {
            width: 100%;
            padding: 12px 16px;
            border: 2px solid #e1e1e1;
            border-radius: 12px;
            font-size: 1rem;
            transition: all 0.3s ease;
            background: rgba(255, 255, 255, 0.9);
        }

        .form-group input:focus,
        .form-group textarea:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
            transform: scale(1.02);
        }

        .form-group input:focus + label,
        .form-group textarea:focus + label {
            color: #667eea;
        }

        /* Button styles */
        .btn {
            display: inline-block;
            padding: 12px 24px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            text-decoration: none;
            border-radius: 12px;
            border: none;
            font-size: 1rem;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
            min-width: 120px;
            text-align: center;
        }

        .btn::before {
            content: '';
            position: absolute;
            top: 50%;
            left: 50%;
            width: 0;
            height: 0;
            background: rgba(255, 255, 255, 0.3);
            border-radius: 50%;
            transition: all 0.3s ease;
            transform: translate(-50%, -50%);
        }

        .btn:hover::before {
            width: 300px;
            height: 300px;
        }

        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
        }

        .btn:active {
            transform: translateY(0);
        }

        .btn-danger {
            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a52 100%);
        }

        .btn-secondary {
            background: linear-gradient(135deg, #6c757d 0%, #495057 100%);
        }

        /* Flash messages */
        .flash-messages {
            margin-bottom: 1rem;
        }

        .flash-message {
            padding: 1rem;
            border-radius: 12px;
            margin-bottom: 0.5rem;
            animation: slideInRight 0.5s ease-out;
        }

        .flash-message.success {
            background: rgba(40, 167, 69, 0.1);
            border: 1px solid rgba(40, 167, 69, 0.3);
            color: #155724;
        }

        .flash-message.error {
            background: rgba(220, 53, 69, 0.1);
            border: 1px solid rgba(220, 53, 69, 0.3);
            color: #721c24;
        }

        /* Animations */
        @keyframes fadeInUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        @keyframes slideDown {
            from {
                opacity: 0;
                transform: translateY(-20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        @keyframes slideInRight {
            from {
                opacity: 0;
                transform: translateX(30px);
            }
            to {
                opacity: 1;
                transform: translateX(0);
            }
        }

        @keyframes pulse {
            0% {
                transform: scale(1);
            }
            50% {
                transform: scale(1.05);
            }
            100% {
                transform: scale(1);
            }
        }

        /* Responsive design */
        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }
            
            .nav {
                flex-direction: column;
                gap: 15px;
            }
            
            .nav-links {
                flex-direction: column;
                gap: 10px;
            }
            
            .card {
                padding: 1.5rem;
            }
        }
    </style>
</head>
<body>
    <header class="header">
        <nav class="nav">
            <a href="{{ url_for('index') }}" class="logo">SecurePass</a>
            <div class="nav-links">
                {% if current_user.is_authenticated %}
                    <a href="{{ url_for('dashboard') }}">Dashboard</a>
                    <a href="{{ url_for('add_password') }}">Add Password</a>
                    <a href="{{ url_for('logout') }}">Logout</a>
                {% else %}
                    <a href="{{ url_for('login') }}">Login</a>
                    <a href="{{ url_for('register') }}">Register</a>
                {% endif %}
            </div>
        </nav>
    </header>

    <div class="container">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                <div class="flash-messages">
                    {% for category, message in messages %}
                        <div class="flash-message {{ category }}">{{ message }}</div>
                    {% endfor %}
                </div>
            {% endif %}
        {% endwith %}

        {% block content %}{% endblock %}
    </div>

    <script>
        // Add some interactive animations
        document.addEventListener('DOMContentLoaded', function() {
            // Animate cards on scroll
            const cards = document.querySelectorAll('.card');
            
            const observer = new IntersectionObserver((entries) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        entry.target.style.animation = 'fadeInUp 0.8s ease-out';
                    }
                });
            });
            
            cards.forEach(card => {
                observer.observe(card);
            });
            
            // Add ripple effect to buttons
            const buttons = document.querySelectorAll('.btn');
            buttons.forEach(button => {
                button.addEventListener('click', function(e) {
                    const ripple = document.createElement('span');
                    const rect = button.getBoundingClientRect();
                    const size = Math.max(rect.width, rect.height);
                    const x = e.clientX - rect.left - size / 2;
                    const y = e.clientY - rect.top - size / 2;
                    
                    ripple.style.cssText = `
                        position: absolute;
                        width: ${size}px;
                        height: ${size}px;
                        left: ${x}px;
                        top: ${y}px;
                        background: rgba(255, 255, 255, 0.5);
                        border-radius: 50%;
                        transform: scale(0);
                        animation: ripple 0.6s ease-out;
                        pointer-events: none;
                    `;
                    
                    button.appendChild(ripple);
                    
                    setTimeout(() => {
                        ripple.remove();
                    }, 600);
                });
            });
        });
        
        // CSS for ripple animation
        const style = document.createElement('style');
        style.textContent = `
            @keyframes ripple {
                to {
                    transform: scale(4);
                    opacity: 0;
                }
            }
        `;
        document.head.appendChild(style);
    </script>
</body>
</html>
EOF

# Create index template
cat > templates/index.html << 'EOF'
{% extends "base.html" %}

{% block content %}
<div style="text-align: center; padding: 4rem 0;">
    <div class="card" style="max-width: 600px; margin: 0 auto;">
        <div style="margin-bottom: 2rem;">
            <div style="font-size: 4rem; margin-bottom: 1rem; animation: pulse 2s infinite;">🔐</div>
            <h1 style="font-size: 2.5rem; margin-bottom: 1rem; color: #333;">Welcome to SecurePass</h1>
            <p style="font-size: 1.2rem; color: #666; margin-bottom: 2rem;">Your secure password manager for all your accounts</p>
        </div>
        
        <div style="display: flex; gap: 1rem; justify-content: center; flex-wrap: wrap;">
            <a href="{{ url_for('login') }}" class="btn">Get Started</a>
            <a href="{{ url_for('register') }}" class="btn btn-secondary">Create Account</a>
        </div>
        
        <div style="margin-top: 3rem; text-align: left;">
            <h3 style="color: #333; margin-bottom: 1rem;">Features:</h3>
            <ul style="color: #666; line-height: 1.8;">
                <li>🔒 Military-grade encryption</li>
                <li>🌐 Access from anywhere</li>
                <li>📱 Responsive design</li>
                <li>⚡ Fast and secure</li>
                <li>🎨 Beautiful interface</li>
            </ul>
        </div>
    </div>
</div>
{% endblock %}
EOF

# Create login template
cat > templates/login.html << 'EOF'
{% extends "base.html" %}

{% block title %}Login - Password Manager{% endblock %}

{% block content %}
<div style="max-width: 400px; margin: 2rem auto;">
    <div class="card">
        <h2 style="text-align: center; margin-bottom: 2rem; color: #333;">Sign In</h2>
        
        <form method="POST">
            {{ form.hidden_tag() }}
            
            <div class="form-group">
                {{ form.email.label(class="form-label") }}
                {{ form.email(class="form-control") }}
                {% if form.email.errors %}
                    <div style="color: #dc3545; font-size: 0.875rem; margin-top: 0.25rem;">
                        {% for error in form.email.errors %}
                            <span>{{ error }}</span>
                        {% endfor %}
                    </div>
                {% endif %}
            </div>
            
            <div class="form-group">
                {{ form.password.label(class="form-label") }}
                {{ form.password(class="form-control") }}
                {% if form.password.errors %}
                    <div style="color: #dc3545; font-size: 0.875rem; margin-top: 0.25rem;">
                        {% for error in form.password.errors %}
                            <span>{{ error }}</span>
                        {% endfor %}
                    </div>
                {% endif %}
            </div>
            
            <div style="text-align: center; margin-top: 2rem;">
                {{ form.submit(class="btn") }}
            </div>
        </form>
        
        <div style="text-align: center; margin-top: 1.5rem;">
            <p style="color: #666;">Don't have an account? <a href="{{ url_for('register') }}" style="color: #667eea; text-decoration: none;">Sign up</a></p>
        </div>
    </div>
</div>
{% endblock %}
EOF

# Create register template
cat > templates/register.html << 'EOF'
{% extends "base.html" %}

{% block title %}Register - Password Manager{% endblock %}

{% block content %}
<div style="max-width: 400px; margin: 2rem auto;">
    <div class="card">
        <h2 style="text-align: center; margin-bottom: 2rem; color: #333;">Create Account</h2>
        
        <form method="POST">
            {{ form.hidden_tag() }}
            
            <div class="form-group">
                {{ form.username.label(class="form-label") }}
                {{ form.username(class="form-control") }}
                {% if form.username.errors %}
                    <div style="color: #dc3545; font-size: 0.875rem; margin-top: 0.25rem;">
                        {% for error in form.username.errors %}
                            <span>{{ error }}</span>
                        {% endfor %}
                    </div>
                {% endif %}
            </div>
            
            <div class="form-group">
                {{ form.email.label(class="form-label") }}
                {{ form.email(class="form-control") }}
                {% if form.email.errors %}
                    <div style="color: #dc3545; font-size: 0.875rem; margin-top: 0.25rem;">
                        {% for error in form.email.errors %}
                            <span>{{ error }}</span>
                        {% endfor %}
                    </div>
                {% endif %}
            </div>
            
            <div class="form-group">
                {{ form.password.label(class="form-label") }}
                {{ form.password(class="form-control") }}
                {% if form.password.errors %}
                    <div style="color: #dc3545; font-size: 0.875rem; margin-top: 0.25rem;">
                        {% for error in form.password.errors %}
                            <span>{{ error }}</span>
                        {% endfor %}
                    </div>
                {% endif %}
            </div>
            
            <div class="form-group">
                {{ form.confirm_password.label(class="form-label") }}
                {{ form.confirm_password(class="form-control") }}
                {% if form.confirm_password.errors %}
                    <div style="color: #dc3545; font-size: 0.875rem; margin-top: 0.25rem;">
                        {% for error in form.confirm_password.errors %}
                            <span>{{ error }}</span>
                        {% endfor %}
                    </div>
                {% endif %}
            </div>
            
            <div style="text-align: center; margin-top: 2rem;">
                {{ form.submit(class="btn") }}
            </div>
        </form>
        
        <div style="text-align: center; margin-top: 1.5rem;">
            <p style="color: #666;">Already have an account? <a href="{{ url_for('login') }}" style="color: #667eea; text-decoration: none;">Sign in</a></p>
        </div>
    </div>
</div>
{% endblock %}
EOF

# Create dashboard template
cat > templates/dashboard.html << 'EOF'
{% extends "base.html" %}

{% block title %}Dashboard - Password Manager{% endblock %}

{% block content %}
<div style="margin-bottom: 2rem;">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem;">
        <h1 style="color: white; font-size: 2rem;">Welcome back, {{ current_user.username }}!</h1>
        <a href="{{ url_for('add_password') }}" class="btn">Add New Password</a>
    </div>
</div>

<div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(350px, 1fr)); gap: 1.5rem;">
    {% for password in passwords %}
    <div class="card password-card" style="position: relative; transition: all 0.3s ease;">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 1rem;">
            <h3 style="color: #333; margin: 0; font-size: 1.2rem;">{{ password.title }}</h3>
            <div style="display: flex; gap: 0.5rem;">
                <button onclick="togglePassword({{ password.id }})" class="btn-small" style="background: #28a745; font-size: 0.8rem; padding: 5px 10px;">👁️</button>
                <a href="{{ url_for('edit_password', password_id=password.id) }}" class="btn-small" style="background: #ffc107; color: #000; font-size: 0.8rem; padding: 5px 10px;">✏️</a>
                <button onclick="deletePassword({{ password.id }})" class="btn-small btn-danger" style="font-size: 0.8rem; padding: 5px 10px;">🗑️</button>
            </div>
        </div>
        
        {% if password.username %}
        <div style="margin-bottom: 0.5rem;">
            <strong style="color: #666; font-size: 0.9rem;">Username:</strong>
            <span style="color: #333;">{{ password.username }}</span>
        </div>
        {% endif %}
        
        <div style="margin-bottom: 0.5rem;">
            <strong style="color: #666; font-size: 0.9rem;">Password:</strong>
            <span id="password-{{ password.id }}" style="color: #333; font-family: monospace;">••••••••</span>
        </div>
        
        {% if password.url %}
        <div style="margin-bottom: 0.5rem;">
            <strong style="color: #666; font-size: 0.9rem;">URL:</strong>
            <a href="{{ password.url }}" target="_blank" style="color: #667eea; text-decoration: none;">{{ password.url }}</a>
        </div>
        {% endif %}
        
        {% if password.notes %}
        <div style="margin-bottom: 0.5rem;">
            <strong style="color: #666; font-size: 0.9rem;">Notes:</strong>
            <p style="color: #333; margin: 0; font-size: 0.9rem;">{{ password.notes }}</p>
        </div>
        {% endif %}
        
        <div style="font-size: 0.8rem; color: #999; margin-top: 1rem;">
            Created: {{ password.created_at.strftime('%Y-%m-%d %H:%M') }}
            {% if password.updated_at != password.created_at %}
            <br>Updated: {{ password.updated_at.strftime('%Y-%m-%d %H:%M') }}
            {% endif %}
        </div>
    </div>
    {% endfor %}
</div>

{% if not passwords %}
<div class="card" style="text-align: center; padding: 3rem;">
    <div style="font-size: 3rem; margin-bottom: 1rem; opacity: 0.5;">🔐</div>
    <h3 style="color: #666; margin-bottom: 1rem;">No passwords saved yet</h3>
    <p style="color: #999; margin-bottom: 2rem;">Start by adding your first password to keep it secure.</p>
    <a href="{{ url_for('add_password') }}" class="btn">Add Your First Password</a>
</div>
{% endif %}

<style>
.btn-small {
    display: inline-block;
    padding: 5px 10px;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    text-decoration: none;
    border-radius: 8px;
    border: none;
    font-size: 0.8rem;
    cursor: pointer;
    transition: all 0.3s ease;
    min-width: auto;
}

.btn-small:hover {
    transform: translateY(-1px);
    box-shadow: 0 3px 10px rgba(0, 0, 0, 0.2);
}

.password-card:hover {
    transform: translateY(-3px);
    box-shadow: 0 10px 25px rgba(0, 0, 0, 0.15);
}
</style>

<script>
function togglePassword(passwordId) {
    const passwordElement = document.getElementById(`password-${passwordId}`);
    
    if (passwordElement.textContent === '••••••••') {
        fetch(`/get_password/${passwordId}`)
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    passwordElement.textContent = data.password;
                    passwordElement.style.background = '#f8f9fa';
                    passwordElement.style.padding = '2px 4px';
                    passwordElement.style.borderRadius = '4px';
                } else {
                    alert('Error: ' + data.message);
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Error fetching password');
            });
    } else {
        passwordElement.textContent = '••••••••';
        passwordElement.style.background = 'transparent';
        passwordElement.style.padding = '0';
    }
}

function deletePassword(passwordId) {
    if (confirm('Are you sure you want to delete this password?')) {
        fetch(`/delete_password/${passwordId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                location.reload();
            } else {
                alert('Error: ' + data.message);
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert('Error deleting password');
        });
    }
}
</script>
{% endblock %}
EOF
