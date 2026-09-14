# app.py - MANUAL ENTRY VERSION (No NAV integration)
from flask import Flask, request, jsonify
from flask_cors import CORS
import base64
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
import io
import zipfile
import logging
import re
import json
from io import BytesIO
from PIL import Image as PILImage
from reportlab.lib.utils import ImageReader
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
import urllib.request
import secrets
from functools import wraps
import uuid
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr
import bcrypt

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', secrets.token_hex(32))

# ===== CORS =====
CORS(app, 
     supports_credentials=True,
     origins=[
         "http://localhost:64462", "http://127.0.0.1:64462",
         "http://localhost:5500", "http://127.0.0.1:5500",
         "http://localhost:5501", "http://127.0.0.1:5501",
         "https://jafari-customer-report.vercel.app",
         "https://jafari-report.netlify.app",
         "null", "*"
     ],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
     allow_headers=["Content-Type", "Authorization", "Accept", "X-Requested-With", "Origin", "Cache-Control"],
     expose_headers=["Access-Control-Allow-Origin", "Access-Control-Allow-Credentials"],
     max_age=3600)

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger(__name__)

# ============================================================
# CONFIGURATION
# ============================================================
def ensure_html_path(url: str) -> str:
    url = url.rstrip('/')
    if url.endswith('.html'):
        return url
    return f"{url}/index.html"

_raw_frontend_url = os.getenv('FRONTEND_URL', 'http://localhost:5501/index.html')
FRONTEND_URL = ensure_html_path(_raw_frontend_url)
logger.info(f"🔗 FRONTEND_URL: {FRONTEND_URL}")

SMTP_HOST = os.getenv('SMTP_HOST', 'smtp.office365.com').strip()
SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
SMTP_USER = os.getenv('SMTP_USER', '').strip()
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD', '').strip().strip('"').strip("'")
SMTP_FROM = os.getenv('SMTP_FROM', SMTP_USER).strip()
SMTP_FROM_NAME = os.getenv('SMTP_FROM_NAME', 'Jafari Credit').strip()
SMTP_USE_TLS = True

_dev_mode_raw = os.getenv('DEV_MODE_EMAIL', 'true').lower()
DEV_MODE_EMAIL = _dev_mode_raw in ('true', '1', 'yes', 'on')

# ============================================================
# LOAN PRODUCT REFERENCE
# ============================================================
LOAN_PRODUCT_MAP = {
    'BUYL': 'BUY OFF LOAN',
    'BUYL-IZ': 'BUY OFF LOAN-IZ',
    'BUYREF': 'BUY OFF REFINANCE LOAN',
    'REFL': 'REFINANCE LOAN',
    'STL': 'STRAIGHT LOAN',
    'STL-LOHO': 'LOHO STRAIGHT',
    'TOPL': 'TOP UP LOAN',
}

def get_loan_product_label(code: str) -> str:
    if not code:
        return 'N/A'
    if code in LOAN_PRODUCT_MAP.values():
        return code
    return LOAN_PRODUCT_MAP.get(code.upper(), code)

# ============================================================
# TOKENS
# ============================================================
TOKENS = {}
TOKEN_EXPIRY_HOURS = 24
INVITATION_TOKENS = {}
INVITATION_EXPIRY_HOURS = 72

def generate_token(user_data):
    token = secrets.token_hex(32)
    TOKENS[token] = {
        'user_data': user_data,
        'created_at': datetime.now().isoformat(),
        'expires_at': (datetime.now() + timedelta(hours=TOKEN_EXPIRY_HOURS)).isoformat()
    }
    return token

def validate_token(token):
    if not token:
        return None
    token_data = TOKENS.get(token)
    if not token_data:
        return None
    expires_at = datetime.fromisoformat(token_data['expires_at'])
    if datetime.now() > expires_at:
        del TOKENS[token]
        return None
    return token_data['user_data']

def invalidate_token(token):
    if token in TOKENS:
        del TOKENS[token]
        return True
    return False

def generate_invitation_token(email):
    token = secrets.token_urlsafe(48)
    INVITATION_TOKENS[token] = {
        'email': email,
        'created_at': datetime.now().isoformat(),
        'expires_at': (datetime.now() + timedelta(hours=INVITATION_EXPIRY_HOURS)).isoformat(),
        'used': False
    }
    return token

def validate_invitation_token(token):
    if not token:
        return None
    invite_data = INVITATION_TOKENS.get(token)
    if not invite_data:
        return None
    if invite_data.get('used'):
        return None
    expires_at = datetime.fromisoformat(invite_data['expires_at'])
    if datetime.now() > expires_at:
        del INVITATION_TOKENS[token]
        return None
    return invite_data

def mark_invitation_used(token):
    if token in INVITATION_TOKENS:
        INVITATION_TOKENS[token]['used'] = True
        INVITATION_TOKENS[token]['used_at'] = datetime.now().isoformat()

def build_invitation_link(token):
    base = FRONTEND_URL.rstrip('/')
    if '?' in base:
        base = base.split('?')[0]
    return f"{base}?invite={token}"

def log_invitation_link(email, link):
    banner = "=" * 80
    message = f"\n{banner}\n📧 INVITATION LINK GENERATED\n{banner}\n   To:   {email}\n   Link: {link}\n{banner}\n"
    logger.info(message)
    print(message, flush=True)

# ============================================================
# USER DATABASE
# ============================================================
ADMIN_EMAIL = "p.mwaura@jafaricredit.co.ke"
ADMIN_PASSWORD_HASH = bcrypt.hashpw("admin123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

AUTHORIZED_USERS = {
    ADMIN_EMAIL: {
        "email": ADMIN_EMAIL,
        "name": "Paul Mwaura",
        "role": "admin",
        "password_hash": ADMIN_PASSWORD_HASH,
        "created_at": datetime.now().isoformat(),
        "is_admin": True,
        "status": "active"
    }
}

USER_DB_FILE = "authorized_users.json"
AUDIT_LOG_FILE = "audit_log.json"
AUDIT_LOG_MAX_ENTRIES = 10000

def load_users():
    global AUTHORIZED_USERS
    try:
        if os.path.exists(USER_DB_FILE):
            with open(USER_DB_FILE, 'r') as f:
                data = json.load(f)
                AUTHORIZED_USERS = data
                if ADMIN_EMAIL not in AUTHORIZED_USERS:
                    AUTHORIZED_USERS[ADMIN_EMAIL] = {
                        "email": ADMIN_EMAIL, "name": "Paul Mwaura", "role": "admin",
                        "password_hash": ADMIN_PASSWORD_HASH,
                        "created_at": datetime.now().isoformat(),
                        "is_admin": True, "status": "active"
                    }
                    save_users()
                logger.info(f"📂 Loaded {len(AUTHORIZED_USERS)} users")
        else:
            save_users()
    except Exception as e:
        logger.error(f"❌ Error loading users: {e}")
        AUTHORIZED_USERS = {}

def save_users():
    try:
        with open(USER_DB_FILE, 'w') as f:
            json.dump(AUTHORIZED_USERS, f, indent=2)
    except Exception as e:
        logger.error(f"❌ Error saving users: {e}")

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password, password_hash):
    try:
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    except:
        return False

load_users()

# ============================================================
# AUDIT LOG
# ============================================================
def load_audit_log():
    try:
        if os.path.exists(AUDIT_LOG_FILE):
            with open(AUDIT_LOG_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        logger.error(f"❌ Error loading audit log: {e}")
    return []

def save_audit_log(log_entries):
    try:
        if len(log_entries) > AUDIT_LOG_MAX_ENTRIES:
            log_entries = log_entries[-AUDIT_LOG_MAX_ENTRIES:]
        with open(AUDIT_LOG_FILE, 'w', encoding='utf-8') as f:
            json.dump(log_entries, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"❌ Error saving audit log: {e}")

def add_audit_entry(user_data, form_data, filename):
    try:
        entries = load_audit_log()
        try:
            ip = request.remote_addr if request else 'unknown'
            ua = request.headers.get('User-Agent', 'unknown')[:200] if request else 'unknown'
        except:
            ip, ua = 'unknown', 'unknown'
        
        entry = {
            'id': str(uuid.uuid4()),
            'timestamp': datetime.now().isoformat(),
            'generated_by_email': user_data.get('email', 'unknown'),
            'generated_by_name': user_data.get('name', 'unknown'),
            'generated_by_role': user_data.get('role', 'user'),
            'report_id': form_data.get('report_id', 'N/A'),
            'customer_name': form_data.get('customer_name', form_data.get('Name', 'N/A')),
            'customer_no': form_data.get('No', 'N/A'),
            'customer_id_no': form_data.get('ID_No', 'N/A'),
            'loan_product': form_data.get('loan_product', 'N/A'),
            'loan_amount': form_data.get('loan_amount', 'N/A'),
            'branch': form_data.get('branch', 'N/A'),
            'kyc_status': form_data.get('kyc_status', 'N/A'),
            'agent_code': form_data.get('agent_code', 'N/A'),
            'filename': filename,
            'gps_location': form_data.get('gps_locator', 'N/A'),
            'has_team_leader_sig': bool(form_data.get('team_leader_signature_image')),
            'has_agent_sig': bool(form_data.get('agent_signature_image')),
            'meeting_confirmed': form_data.get('meeting_confirmed', 'N/A'),
            'ip_address': ip,
            'user_agent': ua,
            'data_source': 'MANUAL_ENTRY'  # Flag to distinguish from NAV-sourced
        }
        entries.append(entry)
        save_audit_log(entries)
        logger.info(f"📝 Audit entry: {entry['report_id']} by {entry['generated_by_email']}")
        return entry
    except Exception as e:
        logger.error(f"❌ Audit entry error: {e}")
        return None

# ============================================================
# EMAIL SERVICE
# ============================================================
def send_invitation_email(recipient_email, recipient_name, invitation_token, inviter_name="Admin"):
    invitation_link = build_invitation_link(invitation_token)
    log_invitation_link(recipient_email, invitation_link)
    
    subject = "Welcome to Jafari Credit - Set Up Your Account"
    html_body = f"""
    <!DOCTYPE html><html><head><style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: #123b72; color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; }}
        .content {{ background: #f9fafb; padding: 30px; border-radius: 0 0 8px 8px; }}
        .button {{ display: inline-block; padding: 14px 32px; background: #123b72; color: white; text-decoration: none; border-radius: 8px; font-weight: bold; margin: 20px 0; }}
        .footer {{ text-align: center; color: #6b7280; font-size: 12px; margin-top: 20px; }}
        .info-box {{ background: white; padding: 20px; border-radius: 8px; border-left: 4px solid #123b72; margin: 20px 0; }}
    </style></head><body>
        <div class="container">
            <div class="header"><h1>🏦 Jafari Credit</h1><p>Customer Meeting Report System</p></div>
            <div class="content">
                <h2>Hello {recipient_name or recipient_email.split('@')[0]},</h2>
                <p>You have been invited by <strong>{inviter_name}</strong> to join the Jafari Credit Customer Meeting Report system.</p>
                <div class="info-box">
                    <p><strong>📧 Your Login Email:</strong> {recipient_email}</p>
                </div>
                <p>To complete your account setup, click the button below:</p>
                <div style="text-align: center;"><a href="{invitation_link}" class="button">🔐 Set Up My Password</a></div>
                <p style="word-break: break-all; background: white; padding: 10px; border-radius: 4px; font-size: 12px;">{invitation_link}</p>
                <p><strong>⏰ Expires in {INVITATION_EXPIRY_HOURS} hours.</strong></p>
            </div>
            <div class="footer"><p>© 2024 Jafari Credit</p></div>
        </div>
    </body></html>
    """
    
    text_body = f"Hello {recipient_name or recipient_email.split('@')[0]},\n\nYou've been invited to join the Jafari Credit Customer Meeting Report system.\n\nYour login email: {recipient_email}\n\nSet up your password: {invitation_link}\n\nExpires in {INVITATION_EXPIRY_HOURS} hours."
    
    if DEV_MODE_EMAIL:
        logger.info(f"✉️  DEV MODE — email NOT sent to {recipient_email}")
        return True, invitation_link
    
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = formataddr((SMTP_FROM_NAME, SMTP_FROM))
        msg['To'] = recipient_email
        msg.attach(MIMEText(text_body, 'plain'))
        msg.attach(MIMEText(html_body, 'html'))
        
        context = ssl.create_default_context()
        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30)
        server.ehlo()
        server.starttls(context=context)
        server.ehlo()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.send_message(msg)
        server.quit()
        logger.info(f"✅ Email sent to {recipient_email}")
        return True, invitation_link
    except Exception as e:
        logger.error(f"❌ Email failed: {type(e).__name__}: {e}")
        return False, invitation_link

# ============================================================
# AUTH DECORATORS
# ============================================================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'OPTIONS':
            return '', 200
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'success': False, 'error': 'Authentication required', 'code': 'UNAUTHORIZED'}), 401
        user_data = validate_token(auth_header[7:])
        if not user_data:
            return jsonify({'success': False, 'error': 'Invalid or expired token', 'code': 'UNAUTHORIZED'}), 401
        request.user_data = user_data
        request.token = auth_header[7:]
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'OPTIONS':
            return '', 200
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'success': False, 'error': 'Authentication required', 'code': 'UNAUTHORIZED'}), 401
        user_data = validate_token(auth_header[7:])
        if not user_data:
            return jsonify({'success': False, 'error': 'Invalid or expired token', 'code': 'UNAUTHORIZED'}), 401
        if not user_data.get('is_admin', False):
            return jsonify({'success': False, 'error': 'Admin privileges required', 'code': 'FORBIDDEN'}), 403
        request.user_data = user_data
        request.token = auth_header[7:]
        return f(*args, **kwargs)
    return decorated_function

# ============================================================
# AUTH ENDPOINTS
# ============================================================
@app.route('/api/auth/login', methods=['POST', 'OPTIONS'])
def auth_login():
    if request.method == 'OPTIONS':
        return '', 200
    try:
        data = request.json
        email = data.get('email', '').strip().lower()
        password = data.get('password', '').strip()
        
        if not email or not password:
            return jsonify({'success': False, 'error': 'Email and password required'}), 400
        
        if email not in AUTHORIZED_USERS:
            return jsonify({'success': False, 'error': 'Access denied.'}), 401
        
        user_data = AUTHORIZED_USERS[email]
        
        if not user_data.get('password_hash'):
            return jsonify({'success': False, 'error': 'Please set up your password first.'}), 401
        
        if not verify_password(password, user_data['password_hash']):
            return jsonify({'success': False, 'error': 'Invalid credentials.'}), 401
        
        if user_data.get('status') == 'inactive':
            return jsonify({'success': False, 'error': 'Account deactivated.'}), 401
        
        user_data['last_login'] = datetime.now().isoformat()
        save_users()
        
        token = generate_token({
            'email': email,
            'name': user_data.get('name', email),
            'role': user_data.get('role', 'user'),
            'is_admin': user_data.get('is_admin', False)
        })
        
        logger.info(f"✅ User {email} logged in")
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'token': token,
            'user': {
                'email': email,
                'name': user_data.get('name', email),
                'role': user_data.get('role', 'user'),
                'is_admin': user_data.get('is_admin', False)
            }
        })
    except Exception as e:
        logger.error(f"❌ Login error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/auth/logout', methods=['POST', 'OPTIONS'])
def auth_logout():
    if request.method == 'OPTIONS':
        return '', 200
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        invalidate_token(auth_header[7:])
    return jsonify({'success': True, 'message': 'Logged out'})

@app.route('/api/auth/status', methods=['GET', 'OPTIONS'])
def auth_status():
    if request.method == 'OPTIONS':
        return '', 200
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'success': True, 'authenticated': False})
    user_data = validate_token(auth_header[7:])
    if user_data:
        return jsonify({'success': True, 'authenticated': True, 'user': user_data})
    return jsonify({'success': True, 'authenticated': False})

# ============================================================
# INVITATION ENDPOINTS
# ============================================================
@app.route('/api/auth/validate-invitation/<token>', methods=['GET', 'OPTIONS'])
def validate_invitation(token):
    if request.method == 'OPTIONS':
        return '', 200
    invite_data = validate_invitation_token(token)
    if not invite_data:
        return jsonify({'success': False, 'error': 'Invalid or expired invitation'}), 400
    email = invite_data['email']
    user = AUTHORIZED_USERS.get(email, {})
    return jsonify({
        'success': True,
        'email': email,
        'name': user.get('name', email.split('@')[0]),
        'role': user.get('role', 'user')
    })

@app.route('/api/auth/setup-password', methods=['POST', 'OPTIONS'])
def setup_password():
    if request.method == 'OPTIONS':
        return '', 200
    try:
        data = request.json
        token = data.get('token', '').strip()
        password = data.get('password', '')
        confirm_password = data.get('confirm_password', '')
        
        if not token or not password:
            return jsonify({'success': False, 'error': 'Token and password required'}), 400
        if password != confirm_password:
            return jsonify({'success': False, 'error': 'Passwords do not match'}), 400
        if len(password) < 6:
            return jsonify({'success': False, 'error': 'Password must be 6+ characters'}), 400
        
        invite_data = validate_invitation_token(token)
        if not invite_data:
            return jsonify({'success': False, 'error': 'Invalid or expired invitation'}), 400
        
        email = invite_data['email']
        if email not in AUTHORIZED_USERS:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        AUTHORIZED_USERS[email]['password_hash'] = hash_password(password)
        AUTHORIZED_USERS[email]['password_set_at'] = datetime.now().isoformat()
        AUTHORIZED_USERS[email]['status'] = 'active'
        save_users()
        mark_invitation_used(token)
        logger.info(f"✅ Password set for {email}")
        return jsonify({'success': True, 'message': 'Password set successfully!'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/auth/resend-invitation', methods=['POST', 'OPTIONS'])
def resend_invitation():
    if request.method == 'OPTIONS':
        return '', 200
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    user_data = validate_token(auth_header[7:])
    if not user_data or not user_data.get('is_admin'):
        return jsonify({'success': False, 'error': 'Admin privileges required'}), 403
    try:
        data = request.json
        email = data.get('email', '').strip().lower()
        if email not in AUTHORIZED_USERS:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        user = AUTHORIZED_USERS[email]
        invitation_token = generate_invitation_token(email)
        email_sent, invitation_link = send_invitation_email(
            recipient_email=email,
            recipient_name=user.get('name', ''),
            invitation_token=invitation_token,
            inviter_name=user_data.get('name', 'Admin')
        )
        return jsonify({
            'success': True,
            'message': f'Invitation resent to {email}',
            'email_sent': email_sent,
            'dev_mode': DEV_MODE_EMAIL,
            'invitation_link': invitation_link
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================
# ADMIN USER MANAGEMENT
# ============================================================
@app.route('/api/admin/users', methods=['GET', 'OPTIONS'])
@admin_required
def get_users():
    if request.method == 'OPTIONS':
        return '', 200
    users = []
    for email, data in AUTHORIZED_USERS.items():
        users.append({
            'email': email,
            'name': data.get('name', email),
            'role': data.get('role', 'user'),
            'is_admin': data.get('is_admin', False),
            'status': data.get('status', 'active'),
            'password_set': bool(data.get('password_hash')),
            'created_at': data.get('created_at', datetime.now().isoformat()),
            'last_login': data.get('last_login')
        })
    return jsonify({'success': True, 'count': len(users), 'data': users})

@app.route('/api/admin/users', methods=['POST', 'OPTIONS'])
@admin_required
def add_user():
    if request.method == 'OPTIONS':
        return '', 200
    try:
        data = request.json
        email = data.get('email', '').strip().lower()
        name = data.get('name', '').strip()
        role = data.get('role', 'user')
        
        if not email:
            return jsonify({'success': False, 'error': 'Email required'}), 400
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            return jsonify({'success': False, 'error': 'Invalid email'}), 400
        if email in AUTHORIZED_USERS:
            return jsonify({'success': False, 'error': 'User already exists'}), 400
        
        AUTHORIZED_USERS[email] = {
            'email': email,
            'name': name or email.split('@')[0],
            'role': role,
            'is_admin': False,
            'status': 'pending',
            'password_hash': None,
            'created_at': datetime.now().isoformat(),
            'created_by': request.user_data.get('email')
        }
        save_users()
        
        invitation_token = generate_invitation_token(email)
        email_sent, invitation_link = send_invitation_email(
            recipient_email=email,
            recipient_name=name or email.split('@')[0],
            invitation_token=invitation_token,
            inviter_name=request.user_data.get('name', 'Admin')
        )
        
        response_data = {
            'success': True,
            'message': f'User {email} added.',
            'user': {
                'email': email,
                'name': AUTHORIZED_USERS[email]['name'],
                'role': role,
                'status': 'pending'
            },
            'email_sent': email_sent,
            'dev_mode': DEV_MODE_EMAIL,
            'invitation_link': invitation_link
        }
        
        if DEV_MODE_EMAIL:
            response_data['message'] = f'User {email} added (DEV MODE).'
        elif email_sent:
            response_data['message'] = f'User {email} added. Invitation sent.'
        else:
            response_data['message'] = f'User {email} added but email failed.'
        
        logger.info(f"👤 Admin added user: {email}")
        return jsonify(response_data)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/admin/users/<email>', methods=['DELETE', 'OPTIONS'])
@admin_required
def delete_user(email):
    if request.method == 'OPTIONS':
        return '', 200
    email = email.strip().lower()
    if email == ADMIN_EMAIL:
        return jsonify({'success': False, 'error': 'Cannot delete admin'}), 400
    if email not in AUTHORIZED_USERS:
        return jsonify({'success': False, 'error': 'User not found'}), 404
    if email == request.user_data.get('email'):
        return jsonify({'success': False, 'error': 'Cannot delete yourself'}), 400
    del AUTHORIZED_USERS[email]
    save_users()
    logger.info(f"👤 Admin deleted user: {email}")
    return jsonify({'success': True, 'message': f'User {email} deleted'})

@app.route('/api/admin/users/<email>/reset-password', methods=['POST', 'OPTIONS'])
@admin_required
def admin_reset_password(email):
    if request.method == 'OPTIONS':
        return '', 200
    email = email.strip().lower()
    if email not in AUTHORIZED_USERS:
        return jsonify({'success': False, 'error': 'User not found'}), 404
    user = AUTHORIZED_USERS[email]
    invitation_token = generate_invitation_token(email)
    email_sent, invitation_link = send_invitation_email(
        recipient_email=email,
        recipient_name=user.get('name', ''),
        invitation_token=invitation_token,
        inviter_name=request.user_data.get('name', 'Admin')
    )
    return jsonify({
        'success': True,
        'message': f'Reset link sent to {email}',
        'email_sent': email_sent,
        'dev_mode': DEV_MODE_EMAIL,
        'invitation_link': invitation_link
    })

@app.route('/api/admin/users/<email>/toggle-status', methods=['POST', 'OPTIONS'])
@admin_required
def toggle_user_status(email):
    if request.method == 'OPTIONS':
        return '', 200
    email = email.strip().lower()
    if email not in AUTHORIZED_USERS:
        return jsonify({'success': False, 'error': 'User not found'}), 404
    if email == ADMIN_EMAIL:
        return jsonify({'success': False, 'error': 'Cannot change admin status'}), 400
    user = AUTHORIZED_USERS[email]
    current = user.get('status', 'active')
    new = 'inactive' if current == 'active' else 'active'
    user['status'] = new
    save_users()
    return jsonify({'success': True, 'message': f'User {email} is now {new}', 'status': new})

# ============================================================
# AUDIT LOG ENDPOINTS
# ============================================================
@app.route('/api/admin/audit-log', methods=['GET', 'OPTIONS'])
@admin_required
def get_audit_log():
    if request.method == 'OPTIONS':
        return '', 200
    try:
        entries = load_audit_log()
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        user_email = request.args.get('user_email')
        customer_search = request.args.get('customer')
        limit = int(request.args.get('limit', 500))
        
        entries = sorted(entries, key=lambda x: x.get('timestamp', ''), reverse=True)
        filtered = entries
        if start_date:
            filtered = [e for e in filtered if e.get('timestamp', '') >= start_date]
        if end_date:
            filtered = [e for e in filtered if e.get('timestamp', '') <= end_date + 'T23:59:59']
        if user_email:
            filtered = [e for e in filtered if user_email.lower() in e.get('generated_by_email', '').lower()]
        if customer_search:
            search = customer_search.lower()
            filtered = [e for e in filtered if 
                search in e.get('customer_name', '').lower() or
                search in e.get('customer_no', '').lower() or
                search in e.get('report_id', '').lower()]
        filtered = filtered[:limit]
        return jsonify({'success': True, 'count': len(filtered), 'total': len(entries), 'data': filtered})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/admin/audit-log/<entry_id>', methods=['DELETE', 'OPTIONS'])
@admin_required
def delete_audit_entry(entry_id):
    if request.method == 'OPTIONS':
        return '', 200
    try:
        entries = load_audit_log()
        original_len = len(entries)
        entries = [e for e in entries if e.get('id') != entry_id]
        if len(entries) == original_len:
            return jsonify({'success': False, 'error': 'Entry not found'}), 404
        save_audit_log(entries)
        return jsonify({'success': True, 'message': 'Entry deleted'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/admin/audit-log/export', methods=['GET', 'OPTIONS'])
@admin_required
def export_audit_log():
    if request.method == 'OPTIONS':
        return '', 200
    try:
        import csv
        import io as io_module
        entries = load_audit_log()
        entries = sorted(entries, key=lambda x: x.get('timestamp', ''), reverse=True)
        output = io_module.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            'Timestamp', 'Report ID', 'Generated By', 'Email', 'Role',
            'Customer Name', 'Customer No', 'ID No', 'Loan Product', 'Loan Amount',
            'Branch', 'KYC Status', 'Agent Code', 'Filename',
            'GPS', 'TL Signed', 'Agent Signed', 'Meeting Confirmed', 'IP Address', 'Data Source'
        ])
        for e in entries:
            writer.writerow([
                e.get('timestamp', ''), e.get('report_id', ''),
                e.get('generated_by_name', ''), e.get('generated_by_email', ''),
                e.get('generated_by_role', ''), e.get('customer_name', ''),
                e.get('customer_no', ''), e.get('customer_id_no', ''),
                e.get('loan_product', ''), e.get('loan_amount', ''),
                e.get('branch', ''), e.get('kyc_status', ''),
                e.get('agent_code', ''), e.get('filename', ''),
                e.get('gps_location', ''),
                'Yes' if e.get('has_team_leader_sig') else 'No',
                'Yes' if e.get('has_agent_sig') else 'No',
                e.get('meeting_confirmed', ''),
                e.get('ip_address', ''),
                e.get('data_source', 'MANUAL_ENTRY')
            ])
        csv_content = output.getvalue()
        csv_base64 = base64.b64encode(csv_content.encode('utf-8')).decode('utf-8')
        filename = f"jafari_audit_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        return jsonify({'success': True, 'csv': csv_base64, 'filename': filename, 'count': len(entries)})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================
# SIMPLE HEALTH CHECK (No NAV)
# ============================================================
@app.route('/api/health', methods=['GET', 'OPTIONS'])
def health():
    if request.method == 'OPTIONS':
        return '', 200
    return jsonify({
        'success': True,
        'message': 'Backend is running (manual entry mode)',
        'mode': 'MANUAL_ENTRY',
        'nav_integration': False,
        'timestamp': datetime.now().isoformat()
    })

# ============================================================
# PDF GENERATION
# ============================================================
@app.route('/api/generate', methods=['POST', 'OPTIONS'])
@login_required
def generate_pdf():
    if request.method == 'OPTIONS':
        return '', 200
    try:
        form_data = request.json
        logger.info(f"📄 Generating PDF for: {form_data.get('Name', form_data.get('customer_name', 'Unknown'))}")
        pdf_buffer = generate_pdf_report(form_data)
        pdf_base64 = base64.b64encode(pdf_buffer).decode('utf-8')
        customer_name = form_data.get('Name', form_data.get('customer_name', 'customer'))
        safe_name = re.sub(r'[^a-zA-Z0-9]', '_', customer_name)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"jafari_report_{safe_name}_{timestamp}.pdf"
        add_audit_entry(request.user_data, form_data, filename)
        logger.info(f"✅ PDF generated: {filename}")
        return jsonify({'success': True, 'pdf': pdf_base64, 'filename': filename})
    except Exception as e:
        logger.error(f"❌ PDF error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/generate-batch', methods=['POST', 'OPTIONS'])
@login_required
def generate_batch_pdfs():
    if request.method == 'OPTIONS':
        return '', 200
    try:
        reports = request.json.get('reports', [])
        if not reports:
            return jsonify({'success': False, 'error': 'No reports provided'}), 400
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            for i, report_data in enumerate(reports):
                pdf_buffer = generate_pdf_report(report_data)
                customer_name = report_data.get('Name', report_data.get('customer_name', f'customer_{i}'))
                safe_name = re.sub(r'[^a-zA-Z0-9]', '_', customer_name)
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"jafari_report_{safe_name}_{timestamp}.pdf"
                zip_file.writestr(filename, pdf_buffer)
                add_audit_entry(request.user_data, report_data, filename)
        zip_buffer.seek(0)
        zip_base64 = base64.b64encode(zip_buffer.getvalue()).decode('utf-8')
        return jsonify({
            'success': True,
            'zip': zip_base64,
            'filename': f"jafari_reports_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip",
            'count': len(reports)
        })
    except Exception as e:
        logger.error(f"❌ Batch error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

def generate_pdf_report(form_data):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=72)
    styles = getSampleStyleSheet()
    
    heading_style = ParagraphStyle('CustomHeading', parent=styles['Heading2'],
        fontSize=14, textColor=colors.HexColor('#123b72'), spaceAfter=12, spaceBefore=20)
    normal_style = ParagraphStyle('CustomNormal', parent=styles['Normal'], fontSize=10, spaceAfter=6)
    company_style = ParagraphStyle('CompanyStyle', parent=styles['Normal'],
        fontSize=12, textColor=colors.HexColor('#123b72'), spaceAfter=4, alignment=1)
    confirmation_style = ParagraphStyle('ConfirmationStyle', parent=styles['Normal'],
        fontSize=9, textColor=colors.HexColor('#065f46'), spaceAfter=4)
    
    story = []
    
    try:
        with urllib.request.urlopen("https://jafaricredit.co.ke/wp-content/themes/jafari-website-theme/assets/darklogo.webp", timeout=10) as response:
            img_data = response.read()
            img_buffer = BytesIO(img_data)
            pil_img = PILImage.open(img_buffer)
            if pil_img.mode != 'RGB':
                pil_img = pil_img.convert('RGB')
            png_buffer = BytesIO()
            pil_img.save(png_buffer, format='PNG')
            png_buffer.seek(0)
            story.append(Image(ImageReader(png_buffer), width=1.5*inch, height=0.6*inch))
    except Exception as e:
        logger.warning(f"Could not fetch logo: {e}")
    
    story.append(Paragraph("<b>JAFARI CREDIT</b>", company_style))
    story.append(Paragraph("Customer Meeting Report", company_style))
    story.append(Spacer(1, 0.2 * inch))
    
    story.append(Paragraph(f"<b>Report ID:</b> {form_data.get('report_id', 'N/A')}", normal_style))
    story.append(Paragraph(f"<b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
    story.append(Spacer(1, 0.2 * inch))
    
    # 1. MEETING DETAILS
    story.append(Paragraph("1. MEETING DETAILS", heading_style))
    meeting_dt = form_data.get('meeting_datetime', 'N/A')
    if form_data.get('meeting_date') and form_data.get('meeting_time'):
        meeting_dt = f"{form_data['meeting_date']} {form_data['meeting_time']}"
    
    meeting_data = [
        ['Field', 'Value'],
        ['Date & Time', meeting_dt],
        ['Branch', str(form_data.get('branch', 'N/A')).title()],
        ['Location', form_data.get('meeting_location', 'N/A') or 'N/A'],
        ['GPS', form_data.get('gps_locator', 'N/A') or 'N/A'],
        ['Meeting Confirmed', str(form_data.get('meeting_confirmed', 'N/A')).title()]
    ]
    meeting_table = Table(meeting_data, colWidths=[2*inch, 3.5*inch])
    meeting_table.setStyle(TableStyle([
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ('PADDING', (0, 0), (-1, -1), 6),
        ('BACKGROUND', (0, 1), (0, -1), colors.whitesmoke),
    ]))
    story.append(meeting_table)
    story.append(Spacer(1, 0.2 * inch))
    
    # 2. CUSTOMER INFORMATION
    story.append(Paragraph("2. CUSTOMER INFORMATION", heading_style))
    
    loan_amount = form_data.get('loan_amount', '')
    if loan_amount:
        try:
            loan_amount = f"KES {float(loan_amount):,.2f}"
        except (ValueError, TypeError):
            loan_amount = f"KES {loan_amount}"
    else:
        loan_amount = 'N/A'
    
    customer_data = [
        ['Field', 'Value'],
        ['Name', form_data.get('Name', '') or form_data.get('customer_name', 'N/A')],
        ['Customer No', form_data.get('No', '') or form_data.get('customer_id', 'N/A') or 'N/A'],
        ['Employer Code', form_data.get('Employer_Code', '') or 'N/A'],
        ['ID No', form_data.get('ID_No', '') or 'N/A'],
        ['Email', form_data.get('E_Mail', '') or form_data.get('customer_email', '') or 'N/A'],
        ['Phone', form_data.get('Mobile_Phone_No', '') or form_data.get('customer_phone', '') or 'N/A'],
        ['Address', form_data.get('Address', '') or form_data.get('customer_address', '') or 'N/A'],
        ['Status', form_data.get('Status', '') or 'N/A'],
        ['Sales Team Lead', form_data.get('Sales_Team_Lead', '') or 'N/A'],
        ['State', form_data.get('State', '') or 'N/A'],
    ]
    customer_table = Table(customer_data, colWidths=[2*inch, 3.5*inch])
    customer_table.setStyle(TableStyle([
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ('PADDING', (0, 0), (-1, -1), 6),
        ('BACKGROUND', (0, 1), (0, -1), colors.whitesmoke),
    ]))
    story.append(customer_table)
    story.append(Spacer(1, 0.2 * inch))
    
    # 3. LOAN DETAILS
    story.append(Paragraph("3. LOAN DETAILS", heading_style))
    loan_product_code = form_data.get('loan_product', '')
    loan_product_label = get_loan_product_label(loan_product_code)
    loan_data = [
        ['Field', 'Value'],
        ['Loan Product', loan_product_label],
        ['Product Code', loan_product_code or 'N/A'],
        ['Loan Amount', loan_amount],
    ]
    loan_table = Table(loan_data, colWidths=[2*inch, 3.5*inch])
    loan_table.setStyle(TableStyle([
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ('PADDING', (0, 0), (-1, -1), 6),
        ('BACKGROUND', (0, 1), (0, -1), colors.whitesmoke),
    ]))
    story.append(loan_table)
    story.append(Spacer(1, 0.2 * inch))
    
    # 4. KYC
    story.append(Paragraph("4. KYC STATUS & VERIFICATION", heading_style))
    kyc_status_display = {
        'verified': 'Verified', 'pending': 'Pending',
        'failed': 'Failed', 'not_submitted': 'Not Submitted'
    }.get(str(form_data.get('kyc_status', '')).lower(), str(form_data.get('kyc_status', 'N/A')).title())
    
    kyc_data = [
        ['Field', 'Value'],
        ['KYC Status', kyc_status_display],
        ['ID Type', str(form_data.get('kyc_id_type', 'N/A')).replace('_', ' ').title()],
        ['Date Verified', form_data.get('kyc_date_verified', 'N/A') or 'N/A'],
        ['Verified By', form_data.get('kyc_verified_by', 'N/A') or 'N/A'],
        ['KYC Notes', form_data.get('kyc_notes', 'N/A') or 'N/A']
    ]
    kyc_table = Table(kyc_data, colWidths=[2*inch, 3.5*inch])
    kyc_table.setStyle(TableStyle([
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ('PADDING', (0, 0), (-1, -1), 6),
        ('BACKGROUND', (0, 1), (0, -1), colors.whitesmoke),
    ]))
    story.append(kyc_table)
    story.append(Spacer(1, 0.2 * inch))
    
    # 5. DISCUSSION
    if form_data.get('discussion_summary'):
        story.append(Paragraph("5. DISCUSSION SUMMARY", heading_style))
        story.append(Paragraph(form_data.get('discussion_summary', ''), normal_style))
        story.append(Spacer(1, 0.2 * inch))
    
    # 6. SIGNATURES
    story.append(PageBreak())
    story.append(Paragraph("6. SIGNATURES", heading_style))
    
    tl_confirmed = form_data.get('team_leader_confirmed') or form_data.get('teamLeaderConfirm')
    ag_confirmed = form_data.get('agent_confirmed') or form_data.get('agentConfirm')
    
    if tl_confirmed and ag_confirmed:
        story.append(Paragraph("<b>Signatures Confirmed:</b> Both signatures present.", confirmation_style))
    else:
        missing = []
        if not tl_confirmed: missing.append("Team Leader")
        if not ag_confirmed: missing.append("Sales Agent")
        story.append(Paragraph(f"<b>Signatures Not Confirmed:</b> {', '.join(missing)}",
            ParagraphStyle('WarnStyle', parent=styles['Normal'], fontSize=9,
                textColor=colors.HexColor('#92400e'), spaceAfter=4)))
    story.append(Spacer(1, 0.15 * inch))
    
    for sig_label, sig_key in [("Team Leader Signature", "team_leader_signature_image"),
                                ("Sales Agent Signature", "agent_signature_image")]:
        story.append(Paragraph(f"<b>{sig_label}:</b>", normal_style))
        sig = form_data.get(sig_key, '')
        if sig and sig.startswith('data:image'):
            try:
                image_data = re.sub('^data:image/.+;base64,', '', sig)
                image_bytes = base64.b64decode(image_data)
                img_buffer = BytesIO(image_bytes)
                pil_img = PILImage.open(img_buffer)
                if pil_img.mode != 'RGB':
                    pil_img = pil_img.convert('RGB')
                png_buffer = BytesIO()
                pil_img.save(png_buffer, format='PNG')
                png_buffer.seek(0)
                story.append(Image(ImageReader(png_buffer), width=3*inch, height=1*inch))
            except Exception as e:
                logger.error(f"Signature error: {e}")
                story.append(Paragraph("<i>(Signature could not be embedded)</i>", normal_style))
        else:
            story.append(Paragraph("<i>(No signature provided)</i>", normal_style))
        story.append(Spacer(1, 0.2 * inch))
    
    story.append(Spacer(1, 0.3 * inch))
    story.append(Paragraph("_" * 80, normal_style))
    story.append(Paragraph(
        f"© 2024 Jafari Credit | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8, textColor=colors.grey, alignment=1)
    ))
    
    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()

# ============================================================
# START
# ============================================================
if __name__ == '__main__':
    PORT = int(os.getenv('PORT', 64462))
    HOST = os.getenv('HOST', '0.0.0.0')
    
    print("=" * 80)
    print("🏦 Jafari Credit - Customer Meeting Report Backend")
    print("📝 MODE: MANUAL ENTRY (No NAV Integration)")
    print(f"📍 Server: http://localhost:{PORT}")
    print(f"🌐 Frontend URL: {FRONTEND_URL}")
    print("=" * 80)
    print("\n📧 Email:")
    print(f"   DEV_MODE_EMAIL: {DEV_MODE_EMAIL}")
    print(f"   SMTP_HOST: {SMTP_HOST}")
    print(f"   SMTP_USER: {SMTP_USER}")
    print("\n🔐 Admin:")
    print(f"   Email: {ADMIN_EMAIL}")
    print(f"   Password: admin123")
    print("\n📊 Audit Log:")
    print(f"   File: {AUDIT_LOG_FILE}")
    print("=" * 80)
    print()
    
    app.run(host=HOST, port=PORT, debug=True, threaded=True, use_reloader=False)