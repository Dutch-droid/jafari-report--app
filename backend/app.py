# app.py - COMPLETE WITH EMAIL INVITATION SYSTEM (SMTP FIXED)
from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
import requests
from requests import Session as ReqSession
from requests.auth import HTTPBasicAuth
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
import hashlib
import secrets
from functools import wraps
import uuid
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr
import bcrypt

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', secrets.token_hex(32))

# ===== CORS CONFIGURATION =====
CORS(app, 
     supports_credentials=True,
     origins=[
         "http://localhost:64462", 
         "http://127.0.0.1:64462",
         "http://localhost:5500", 
         "http://127.0.0.1:5500",
         "http://localhost:5501", 
         "http://127.0.0.1:5501",
         "http://localhost:5502",
         "http://127.0.0.1:5502",
         "null",
         "*"
     ],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
     allow_headers=["Content-Type", "Authorization", "Accept", "X-Requested-With", "Origin", "Cache-Control"],
     expose_headers=["Access-Control-Allow-Origin", "Access-Control-Allow-Credentials"],
     max_age=3600)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

# ============================================================
# CONFIGURATION
# ============================================================

def ensure_html_path(url: str) -> str:
    """Ensure FRONTEND_URL points to an HTML file."""
    url = url.rstrip('/')
    if url.endswith('.html'):
        return url
    return f"{url}/website.html"

_raw_frontend_url = os.getenv('FRONTEND_URL', 'http://localhost:5501/website.html')
FRONTEND_URL = ensure_html_path(_raw_frontend_url)
logger.info(f"🔗 FRONTEND_URL: {FRONTEND_URL}")

# ============================================================
# SMTP CONFIGURATION (FIXED)
# ============================================================
SMTP_HOST = os.getenv('SMTP_HOST', 'smtp.office365.com').strip()
SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
SMTP_USER = os.getenv('SMTP_USER', '').strip()
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD', '').strip().strip('"').strip("'")
SMTP_FROM = os.getenv('SMTP_FROM', SMTP_USER).strip()
SMTP_FROM_NAME = os.getenv('SMTP_FROM_NAME', 'Jafari Credit').strip()

# Force TLS to True for Microsoft 365 - this is required
SMTP_USE_TLS = True

# DEV_MODE_EMAIL logic
_dev_mode_raw = os.getenv('DEV_MODE_EMAIL', 'true').lower()
DEV_MODE_EMAIL = _dev_mode_raw in ('true', '1', 'yes', 'on')

# Log configuration on startup (mask password)
logger.info("=" * 60)
logger.info("📧 SMTP CONFIGURATION")
logger.info("=" * 60)
logger.info(f"   DEV_MODE_EMAIL:   {DEV_MODE_EMAIL}")
logger.info(f"   SMTP_HOST:        {SMTP_HOST}")
logger.info(f"   SMTP_PORT:        {SMTP_PORT}")
logger.info(f"   SMTP_USE_TLS:     {SMTP_USE_TLS} (forced True)")
logger.info(f"   SMTP_USER:        {SMTP_USER}")
logger.info(f"   SMTP_PASSWORD:    {'*' * len(SMTP_PASSWORD) if SMTP_PASSWORD else '(EMPTY)'} ({len(SMTP_PASSWORD)} chars)")
logger.info(f"   SMTP_FROM:        {SMTP_FROM}")
logger.info(f"   SMTP_FROM_NAME:   {SMTP_FROM_NAME}")
logger.info("=" * 60)

# Warn if credentials are missing
if not DEV_MODE_EMAIL and (not SMTP_USER or not SMTP_PASSWORD):
    logger.warning("⚠️  DEV_MODE_EMAIL is False but SMTP_USER or SMTP_PASSWORD is empty!")
    logger.warning("⚠️  Emails will fail to send. Please check your .env file.")

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
    """Get the full label for a loan product code."""
    if not code:
        return 'N/A'
    if code in LOAN_PRODUCT_MAP.values():
        return code
    return LOAN_PRODUCT_MAP.get(code.upper(), code)

# ============================================================
# TOKEN STORAGE
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
    message = f"""
{banner}
📧 INVITATION LINK GENERATED
{banner}
   To:   {email}
   Link: {link}
{banner}
"""
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

def load_users():
    global AUTHORIZED_USERS
    try:
        if os.path.exists(USER_DB_FILE):
            with open(USER_DB_FILE, 'r') as f:
                data = json.load(f)
                AUTHORIZED_USERS = data
                if ADMIN_EMAIL not in AUTHORIZED_USERS:
                    AUTHORIZED_USERS[ADMIN_EMAIL] = {
                        "email": ADMIN_EMAIL,
                        "name": "Paul Mwaura",
                        "role": "admin",
                        "password_hash": ADMIN_PASSWORD_HASH,
                        "created_at": datetime.now().isoformat(),
                        "is_admin": True,
                        "status": "active"
                    }
                    save_users()
                logger.info(f"📂 Loaded {len(AUTHORIZED_USERS)} users from file")
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
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        return False

load_users()

# ============================================================
# EMAIL SERVICE (FIXED FOR MICROSOFT 365)
# ============================================================
def send_invitation_email(recipient_email, recipient_name, invitation_token, inviter_name="Admin"):
    """
    Send invitation email to a new user via SMTP.
    Returns a tuple: (success: bool, invitation_link: str)
    """
    invitation_link = build_invitation_link(invitation_token)
    log_invitation_link(recipient_email, invitation_link)
    
    subject = "Welcome to Jafari Credit - Set Up Your Account"
    
    html_body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background: #123b72; color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; }}
            .content {{ background: #f9fafb; padding: 30px; border-radius: 0 0 8px 8px; }}
            .button {{ display: inline-block; padding: 14px 32px; background: #123b72; color: white; text-decoration: none; border-radius: 8px; font-weight: bold; margin: 20px 0; }}
            .footer {{ text-align: center; color: #6b7280; font-size: 12px; margin-top: 20px; }}
            .info-box {{ background: white; padding: 20px; border-radius: 8px; border-left: 4px solid #123b72; margin: 20px 0; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🏦 Jafari Credit</h1>
                <p>Customer Meeting Report System</p>
            </div>
            <div class="content">
                <h2>Hello {recipient_name or recipient_email.split('@')[0]},</h2>
                <p>You have been invited by <strong>{inviter_name}</strong> to join the Jafari Credit Customer Meeting Report system.</p>
                
                <div class="info-box">
                    <p><strong>📧 Your Login Email:</strong> {recipient_email}</p>
                    <p>You'll use this email address to log in after setting up your password.</p>
                </div>
                
                <p>To complete your account setup, please click the button below to create your password:</p>
                
                <div style="text-align: center;">
                    <a href="{invitation_link}" class="button">🔐 Set Up My Password</a>
                </div>
                
                <p>Or copy and paste this link into your browser:</p>
                <p style="word-break: break-all; background: white; padding: 10px; border-radius: 4px; font-size: 12px;">{invitation_link}</p>
                
                <p><strong>⏰ This invitation expires in {INVITATION_EXPIRY_HOURS} hours.</strong></p>
                
                <p>If you didn't expect this invitation, you can safely ignore this email.</p>
            </div>
            <div class="footer">
                <p>© 2024 Jafari Credit | This is an automated message, please do not reply.</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    text_body = f"""
    Hello {recipient_name or recipient_email.split('@')[0]},
    
    You have been invited by {inviter_name} to join the Jafari Credit Customer Meeting Report system.
    
    Your login email: {recipient_email}
    
    To set up your password, please visit:
    {invitation_link}
    
    This invitation expires in {INVITATION_EXPIRY_HOURS} hours.
    
    © 2024 Jafari Credit
    """
    
    if DEV_MODE_EMAIL:
        logger.info(f"✉️  DEV MODE — email NOT sent to {recipient_email}")
        return True, invitation_link
    
    # ============================================================
    # Send the email via SMTP
    # ============================================================
    try:
        logger.info(f"📧 Sending email via SMTP...")
        logger.info(f"   Host: {SMTP_HOST}:{SMTP_PORT}")
        logger.info(f"   From: {SMTP_FROM}")
        logger.info(f"   To:   {recipient_email}")
        
        # Build the message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = formataddr((SMTP_FROM_NAME, SMTP_FROM))
        msg['To'] = recipient_email
        msg.attach(MIMEText(text_body, 'plain'))
        msg.attach(MIMEText(html_body, 'html'))
        
        # Connect and send
        # Use SSL context with proper settings for Microsoft 365
        context = ssl.create_default_context()
        
        # Microsoft 365 on port 587 uses STARTTLS
        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30)
        server.set_debuglevel(0)  # Set to 1 for verbose SMTP debugging
        
        # Step 1: Say hello
        server.ehlo()
        
        # Step 2: Upgrade to TLS BEFORE any auth (required by Microsoft)
        server.starttls(context=context)
        
        # Step 3: Re-say hello after TLS
        server.ehlo()
        
        # Step 4: Now authenticate
        server.login(SMTP_USER, SMTP_PASSWORD)
        
        # Step 5: Send the message
        server.send_message(msg)
        
        # Step 6: Close the connection
        server.quit()
        
        logger.info(f"✅ Invitation email sent to {recipient_email}")
        return True, invitation_link
        
    except smtplib.SMTPAuthenticationError as e:
        error_msg = e.smtp_error.decode() if isinstance(e.smtp_error, bytes) else str(e.smtp_error)
        logger.error(f"❌ SMTP Auth failed for {recipient_email}")
        logger.error(f"   Code: {e.smtp_code}")
        logger.error(f"   Message: {error_msg}")
        logger.error(f"   → Check your SMTP_USER and SMTP_PASSWORD in .env")
        return False, invitation_link
        
    except smtplib.SMTPRecipientsRefused as e:
        logger.error(f"❌ Recipient refused: {recipient_email}")
        logger.error(f"   Details: {e.recipients}")
        return False, invitation_link
        
    except smtplib.SMTPSenderRefused as e:
        logger.error(f"❌ Sender refused: {SMTP_FROM}")
        logger.error(f"   Details: {e}")
        logger.error(f"   → Verify SMTP_FROM is a valid mailbox you have permission to send from")
        return False, invitation_link
        
    except smtplib.SMTPException as e:
        logger.error(f"❌ SMTP error sending to {recipient_email}: {type(e).__name__}: {e}")
        return False, invitation_link
        
    except ssl.SSLError as e:
        logger.error(f"❌ SSL error: {e}")
        logger.error(f"   → Check that SMTP_PORT is 587 and STARTTLS is enabled")
        return False, invitation_link
        
    except Exception as e:
        logger.error(f"❌ Failed to send email to {recipient_email}: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
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
            return jsonify({
                'success': False, 
                'error': 'Authentication required', 
                'code': 'UNAUTHORIZED'
            }), 401
        
        token = auth_header[7:]
        user_data = validate_token(token)
        if not user_data:
            return jsonify({
                'success': False, 
                'error': 'Invalid or expired token', 
                'code': 'UNAUTHORIZED'
            }), 401
        
        request.user_data = user_data
        request.token = token
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'OPTIONS':
            return '', 200
        
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({
                'success': False, 
                'error': 'Authentication required', 
                'code': 'UNAUTHORIZED'
            }), 401
        
        token = auth_header[7:]
        user_data = validate_token(token)
        
        if not user_data:
            return jsonify({
                'success': False, 
                'error': 'Invalid or expired token', 
                'code': 'UNAUTHORIZED'
            }), 401
        
        if not user_data.get('is_admin', False):
            return jsonify({
                'success': False, 
                'error': 'Admin privileges required', 
                'code': 'FORBIDDEN'
            }), 403
        
        request.user_data = user_data
        request.token = token
        return f(*args, **kwargs)
    return decorated_function

# ============================================================
# NAV CONFIGURATION & MOCK DATA
# ============================================================
NAV_BASE_URL = "http://jcl-nav-svr.centum.co.ke:1115/Jafari/ODataV4/Company/JAFARI%20CREDIT%20LIMITED"
AGENT_ENTITY = "Salespeople_Purchasers"
CUSTOMER_ENTITY = "Memberlist"
NAV_USERNAME = os.getenv('NAV_USERNAME', 'pmwaura')
NAV_PASSWORD = os.getenv('NAV_PASSWORD', 'Dutch@9004')
USE_MOCK_DATA = False

MOCK_AGENTS = {
    'AG001': {'code': 'AG001', 'name': 'John Mwangi', 'type': 'Sales Agent', 'phone': '+254 700 123456', 'email': 'john.mwangi@jafari.co.ke', 'blocked': False},
    'AG002': {'code': 'AG002', 'name': 'Mary Akinyi', 'type': 'Team Lead', 'phone': '+254 700 234567', 'email': 'mary.akinyi@jafari.co.ke', 'blocked': False},
    'AG003': {'code': 'AG003', 'name': 'Peter Ochieng', 'type': 'Sales Agent', 'phone': '+254 700 345678', 'email': 'peter.ochieng@jafari.co.ke', 'blocked': False},
}

MOCK_CUSTOMERS = [
    {'Name': 'James Kamau', 'No': 'CUST001', 'Employer_Code': 'EMP001', 'ID_No': '12345678', 
     'E_Mail': 'james@email.com', 'Status': 'Active', 'Sales_Team_Lead': 'John Mwangi', 
     'State': 'Nairobi', 'Mobile_Phone_No': '+254 700 111111', 'Address': '123, Nairobi',
     'Last_Modified_DateTime': datetime.now().isoformat()},
]

def get_nav_session():
    session = ReqSession()
    session.auth = HTTPBasicAuth(NAV_USERNAME, NAV_PASSWORD)
    session.headers.update({'Accept': 'application/json', 'Content-Type': 'application/json'})
    return session

def fetch_from_nav(entity, filter_field=None, filter_value=None, top=100):
    if USE_MOCK_DATA or not NAV_BASE_URL:
        logger.info(f"📡 Using MOCK data for {entity}")
        return fetch_mock_data(entity, filter_field, filter_value, top)
    
    session = get_nav_session()
    try:
        if filter_field and filter_value:
            if isinstance(filter_value, str) and filter_value.startswith('*') and filter_value.endswith('*'):
                search_term = filter_value[1:-1]
                url = f"{NAV_BASE_URL}/{entity}?$filter=contains({filter_field}, '{search_term}')&$top={top}"
            else:
                url = f"{NAV_BASE_URL}/{entity}?$filter={filter_field} eq '{filter_value}'&$top={top}"
        else:
            url = f"{NAV_BASE_URL}/{entity}?$top={top}"
        
        logger.info(f"📡 NAV Request: {url}")
        response = session.get(url, timeout=30)
        logger.info(f"📥 NAV Response: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            records = data.get('value', [])
            logger.info(f"✅ NAV returned {len(records)} records from {entity}")
            return {'success': True, 'data': records, 'count': len(records), 'source': 'NAV'}
        elif response.status_code == 401:
            logger.error(f"❌ NAV 401 Unauthorized")
            return {'success': False, 'error': 'NAV authentication failed', 'nav_status': 401}
        elif response.status_code == 404:
            logger.error(f"❌ NAV 404 — entity '{entity}' not found")
            return {'success': False, 'error': f'Entity "{entity}" not found', 'nav_status': 404}
        else:
            logger.error(f"❌ NAV {response.status_code}: {response.text[:300]}")
            return {'success': False, 'error': f'NAV status {response.status_code}', 'nav_status': response.status_code}
    except requests.exceptions.ConnectionError as e:
        logger.error(f"❌ NAV connection error: {e}")
        return {'success': False, 'error': 'Cannot reach NAV server. Check VPN/network.', 'error_type': 'connection'}
    except requests.exceptions.Timeout:
        logger.error(f"❌ NAV timeout")
        return {'success': False, 'error': 'NAV request timed out', 'error_type': 'timeout'}
    except Exception as e:
        logger.error(f"❌ NAV error: {e}")
        return {'success': False, 'error': str(e)}

def fetch_mock_data(entity, filter_field=None, filter_value=None, top=100):
    if 'agent' in entity.lower() or 'sales' in entity.lower():
        data = list(MOCK_AGENTS.values())
        if filter_field == 'Code' and filter_value:
            data = [a for a in data if a['code'].lower() == filter_value.lower()]
        return {'success': True, 'data': data[:top], 'count': len(data), 'source': 'MOCK'}
    elif 'customer' in entity.lower():
        data = MOCK_CUSTOMERS.copy()
        if filter_field == 'No' and filter_value:
            data = [c for c in data if c.get('No', '').lower() == filter_value.lower()]
        return {'success': True, 'data': data[:top], 'count': len(data), 'source': 'MOCK'}
    return {'success': True, 'data': [], 'count': 0, 'source': 'MOCK'}

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
            return jsonify({
                'success': False,
                'error': 'Email and password are required'
            }), 400
        
        if email not in AUTHORIZED_USERS:
            return jsonify({
                'success': False,
                'error': 'Access denied. Please contact admin for access.'
            }), 401
        
        user_data = AUTHORIZED_USERS[email]
        
        if not user_data.get('password_hash'):
            return jsonify({
                'success': False,
                'error': 'Please check your email and set up your password first.'
            }), 401
        
        if not verify_password(password, user_data['password_hash']):
            return jsonify({
                'success': False,
                'error': 'Invalid credentials. Please try again.'
            }), 401
        
        if user_data.get('status') == 'inactive':
            return jsonify({
                'success': False,
                'error': 'Your account has been deactivated. Please contact admin.'
            }), 401
        
        user_data['last_login'] = datetime.now().isoformat()
        save_users()
        
        token = generate_token({
            'email': email,
            'name': user_data.get('name', email),
            'role': user_data.get('role', 'user'),
            'is_admin': user_data.get('is_admin', False)
        })
        
        logger.info(f"✅ User {email} logged in successfully")
        
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
    
    return jsonify({'success': True, 'message': 'Logged out successfully'})

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
# INVITATION / PASSWORD SETUP ENDPOINTS
# ============================================================

@app.route('/api/auth/validate-invitation/<token>', methods=['GET', 'OPTIONS'])
def validate_invitation(token):
    if request.method == 'OPTIONS':
        return '', 200
    
    invite_data = validate_invitation_token(token)
    
    if not invite_data:
        return jsonify({
            'success': False,
            'error': 'Invalid or expired invitation link'
        }), 400
    
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
            return jsonify({
                'success': False,
                'error': 'Token and password are required'
            }), 400
        
        if password != confirm_password:
            return jsonify({
                'success': False,
                'error': 'Passwords do not match'
            }), 400
        
        if len(password) < 6:
            return jsonify({
                'success': False,
                'error': 'Password must be at least 6 characters long'
            }), 400
        
        invite_data = validate_invitation_token(token)
        if not invite_data:
            return jsonify({
                'success': False,
                'error': 'Invalid or expired invitation link'
            }), 400
        
        email = invite_data['email']
        
        if email not in AUTHORIZED_USERS:
            return jsonify({
                'success': False,
                'error': 'User not found'
            }), 404
        
        AUTHORIZED_USERS[email]['password_hash'] = hash_password(password)
        AUTHORIZED_USERS[email]['password_set_at'] = datetime.now().isoformat()
        AUTHORIZED_USERS[email]['status'] = 'active'
        save_users()
        
        mark_invitation_used(token)
        
        logger.info(f"✅ Password set up for {email}")
        
        return jsonify({
            'success': True,
            'message': 'Password set successfully! You can now log in with your email and password.'
        })
        
    except Exception as e:
        logger.error(f"❌ Password setup error: {e}")
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
        logger.error(f"❌ Resend invitation error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================
# ADMIN USER MANAGEMENT ENDPOINTS
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
            return jsonify({'success': False, 'error': 'Email is required'}), 400
        
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            return jsonify({'success': False, 'error': 'Invalid email format'}), 400
        
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
            'message': f'User {email} added successfully.',
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
            response_data['message'] = f'User {email} added (DEV MODE — no email sent).'
        elif email_sent:
            response_data['message'] = f'User {email} added. Invitation email sent to {email}.'
        else:
            response_data['message'] = f'User {email} added but email failed. Share this link manually.'
        
        logger.info(f"👤 Admin added user: {email}")
        
        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f"❌ Error adding user: {e}")
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
        return jsonify({'success': False, 'error': 'Cannot delete the admin user'}), 400
    
    if email not in AUTHORIZED_USERS:
        return jsonify({'success': False, 'error': 'User not found'}), 404
    
    if email == request.user_data.get('email'):
        return jsonify({'success': False, 'error': 'Cannot delete your own account'}), 400
    
    del AUTHORIZED_USERS[email]
    save_users()
    
    logger.info(f"👤 Admin deleted user: {email}")
    return jsonify({'success': True, 'message': f'User {email} deleted successfully'})

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
        'message': f'Password reset link sent to {email}',
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
    current_status = user.get('status', 'active')
    new_status = 'inactive' if current_status == 'active' else 'active'
    user['status'] = new_status
    save_users()
    
    return jsonify({
        'success': True,
        'message': f'User {email} is now {new_status}',
        'status': new_status
    })

# ============================================================
# SMTP TEST ENDPOINT (Useful for debugging)
# ============================================================
@app.route('/api/admin/test-smtp', methods=['POST', 'OPTIONS'])
@admin_required
def test_smtp():
    """Test SMTP connection and send a test email."""
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        data = request.json or {}
        test_recipient = data.get('email', SMTP_USER or ADMIN_EMAIL)
        
        logger.info(f"🧪 Testing SMTP — sending to {test_recipient}")
        
        msg = MIMEMultipart('alternative')
        msg['Subject'] = "SMTP Test — Jafari Credit"
        msg['From'] = formataddr((SMTP_FROM_NAME, SMTP_FROM))
        msg['To'] = test_recipient
        msg.attach(MIMEText("This is a test email from Jafari Credit. If you received it, SMTP is working!", 'plain'))
        
        context = ssl.create_default_context()
        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30)
        server.ehlo()
        server.starttls(context=context)
        server.ehlo()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.send_message(msg)
        server.quit()
        
        return jsonify({
            'success': True,
            'message': f'Test email sent to {test_recipient}',
            'config': {
                'host': SMTP_HOST,
                'port': SMTP_PORT,
                'user': SMTP_USER,
                'from': SMTP_FROM,
                'tls': SMTP_USE_TLS
            }
        })
        
    except Exception as e:
        logger.error(f"❌ SMTP test failed: {type(e).__name__}: {e}")
        return jsonify({
            'success': False,
            'error': f'{type(e).__name__}: {str(e)}',
            'config': {
                'host': SMTP_HOST,
                'port': SMTP_PORT,
                'user': SMTP_USER,
                'from': SMTP_FROM,
                'tls': SMTP_USE_TLS
            }
        }), 500

# ============================================================
# PROTECTED API ENDPOINTS
# ============================================================

@app.route('/api/dynamics/health', methods=['GET', 'OPTIONS'])
@login_required
def dynamics_health():
    if request.method == 'OPTIONS':
        return '', 200
    
    test_result = fetch_from_nav(CUSTOMER_ENTITY, top=1)
    
    if test_result.get('success'):
        return jsonify({
            'success': True,
            'message': 'Connected to Dynamics NAV',
            'nav': {
                'base_url': NAV_BASE_URL,
                'username': NAV_USERNAME,
                'is_connected': True,
                'using_mock': USE_MOCK_DATA,
                'test_records': test_result.get('count', 0)
            },
            'timestamp': datetime.now().isoformat()
        })
    else:
        return jsonify({
            'success': False,
            'message': 'NAV connection failed',
            'error': test_result.get('error', 'Unknown error'),
            'nav': {
                'base_url': NAV_BASE_URL,
                'username': NAV_USERNAME,
                'is_connected': False,
                'using_mock': USE_MOCK_DATA
            },
            'timestamp': datetime.now().isoformat()
        })

@app.route('/api/dynamics/agents/<agent_code>', methods=['GET', 'OPTIONS'])
@login_required
def fetch_agent(agent_code):
    if request.method == 'OPTIONS':
        return '', 200
        
    logger.info(f"🔍 Fetching agent: {agent_code}")
    result = fetch_from_nav(AGENT_ENTITY, 'Code', agent_code)
    
    if result.get('success') and result.get('data'):
        agent = result['data'][0]
        return jsonify({
            'success': True,
            'method': result.get('source', 'Unknown'),
            'data': {
                'code': agent.get('code', agent.get('Code', '')),
                'name': agent.get('name', agent.get('Name', '')),
                'type': agent.get('type', agent.get('Type', '')),
                'phone': agent.get('phone', agent.get('Phone_No', '')),
                'email': agent.get('email', agent.get('E_Mail', '')),
                'blocked': agent.get('blocked', agent.get('Blocked', False))
            }
        })
    else:
        mock_agent = MOCK_AGENTS.get(agent_code, {
            'code': agent_code, 'name': agent_code, 'type': 'Sales Agent',
            'phone': '', 'email': '', 'blocked': False
        })
        return jsonify({
            'success': True,
            'method': 'FALLBACK',
            'data': mock_agent,
            'warning': result.get('error', 'Using fallback data')
        })

@app.route('/api/dynamics/customers/<identifier_type>/<identifier_value>', methods=['GET', 'OPTIONS'])
@login_required
def fetch_customer(identifier_type, identifier_value):
    if request.method == 'OPTIONS':
        return '', 200
        
    logger.info(f"🔍 Fetching customer: {identifier_type}={identifier_value}")
    
    field_map = {
        'No': 'No',
        'Name': 'Name',
        'Employer_Code': 'Employer_Code', 
        'ID_No': 'ID_No',
        'E_Mail': 'E_Mail',
        'Phone_No': 'Phone_No',
        'Member_No': 'Member_No',
        'Status': 'Status',
        'Sales_Team_Lead': 'Sales_Team_Lead',
        'State': 'State'
    }
    filter_field = field_map.get(identifier_type, 'Name')
    result = fetch_from_nav(CUSTOMER_ENTITY, filter_field, identifier_value)
    
    if result.get('success') and result.get('data'):
        customer = result['data'][0]
        return jsonify({
            'success': True,
            'method': result.get('source', 'Unknown'),
            'data': {
                'Name': customer.get('Name', ''),
                'No': customer.get('No', ''),
                'Employer_Code': customer.get('Employer_Code', ''),
                'ID_No': customer.get('ID_No', '') or customer.get('ID_Number', '') or customer.get('NationalID', ''),
                'E_Mail': customer.get('E_Mail', '') or customer.get('Email', ''),
                'Status': customer.get('Status', ''),
                'Sales_Team_Lead': customer.get('Sales_Team_Lead', '') or customer.get('Salesperson_Code', ''),
                'State': customer.get('State', ''),
                'Mobile_Phone_No': customer.get('Mobile_Phone_No', '') or customer.get('Phone_No', '') or customer.get('Phone', ''),
                'Address': customer.get('Address', ''),
                'Last_Modified_DateTime': customer.get('Last_Modified_DateTime', datetime.now().isoformat()),
                '_source': result.get('source', 'NAV')
            }
        })
    else:
        mock_customer = next((c for c in MOCK_CUSTOMERS if c.get(filter_field, '').lower() == identifier_value.lower()), None)
        if mock_customer:
            return jsonify({'success': True, 'method': 'MOCK', 'data': mock_customer})
        return jsonify({
            'success': False,
            'error': result.get('error', f'Customer not found: {identifier_type}={identifier_value}')
        }), 404

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
        
        logger.info(f"✅ PDF generated: {filename}")
        
        return jsonify({'success': True, 'pdf': pdf_base64, 'filename': filename})
    except Exception as e:
        logger.error(f"❌ Error generating PDF: {e}")
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
        
        zip_buffer.seek(0)
        zip_base64 = base64.b64encode(zip_buffer.getvalue()).decode('utf-8')
        return jsonify({
            'success': True,
            'zip': zip_base64,
            'filename': f"jafari_reports_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip",
            'count': len(reports)
        })
    except Exception as e:
        logger.error(f"❌ Error generating batch: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================
# PDF GENERATION
# ============================================================
def generate_pdf_report(form_data):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, 
                           rightMargin=72, leftMargin=72,
                           topMargin=72, bottomMargin=72)
    styles = getSampleStyleSheet()
    
    heading_style = ParagraphStyle('CustomHeading', parent=styles['Heading2'],
        fontSize=14, textColor=colors.HexColor('#123b72'), spaceAfter=12, spaceBefore=20)
    normal_style = ParagraphStyle('CustomNormal', parent=styles['Normal'],
        fontSize=10, spaceAfter=6)
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
    
    # 4. KYC STATUS
    story.append(Paragraph("4. KYC STATUS & VERIFICATION", heading_style))
    
    kyc_status_display = {
        'verified': 'Verified',
        'pending': 'Pending',
        'failed': 'Failed',
        'not_submitted': 'Not Submitted'
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
    
    # 5. DISCUSSION SUMMARY
    if form_data.get('discussion_summary'):
        story.append(Paragraph("5. DISCUSSION SUMMARY", heading_style))
        story.append(Paragraph(form_data.get('discussion_summary', ''), normal_style))
        story.append(Spacer(1, 0.2 * inch))
    
    # 6. SIGNATURES
    story.append(PageBreak())
    story.append(Paragraph("6. SIGNATURES", heading_style))
    
    team_leader_confirmed = form_data.get('team_leader_confirmed') or form_data.get('teamLeaderConfirm')
    agent_confirmed = form_data.get('agent_confirmed') or form_data.get('agentConfirm')
    
    if team_leader_confirmed and agent_confirmed:
        story.append(Paragraph(
            "<b>Signatures Confirmed:</b> The Team Leader has confirmed that both signatures are present.",
            confirmation_style
        ))
    else:
        missing = []
        if not team_leader_confirmed:
            missing.append("Team Leader")
        if not agent_confirmed:
            missing.append("Sales Agent")
        story.append(Paragraph(
            f"<b>Signatures Not Confirmed:</b> {', '.join(missing)}",
            ParagraphStyle('WarnStyle', parent=styles['Normal'], fontSize=9,
                textColor=colors.HexColor('#92400e'), spaceAfter=4)
        ))
    story.append(Spacer(1, 0.15 * inch))
    
    story.append(Paragraph("<b>Team Leader Signature:</b>", normal_style))
    tl_sig = form_data.get('team_leader_signature_image', '')
    if tl_sig and tl_sig.startswith('data:image'):
        try:
            image_data = re.sub('^data:image/.+;base64,', '', tl_sig)
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
            logger.error(f"Error adding team leader signature: {e}")
            story.append(Paragraph("<i>(Signature could not be embedded)</i>", normal_style))
    else:
        story.append(Paragraph("<i>(No signature provided)</i>", normal_style))
    story.append(Spacer(1, 0.2 * inch))
    
    story.append(Paragraph("<b>Sales Agent Signature:</b>", normal_style))
    ag_sig = form_data.get('agent_signature_image', '')
    if ag_sig and ag_sig.startswith('data:image'):
        try:
            image_data = re.sub('^data:image/.+;base64,', '', ag_sig)
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
            logger.error(f"Error adding agent signature: {e}")
            story.append(Paragraph("<i>(Signature could not be embedded)</i>", normal_style))
    else:
        story.append(Paragraph("<i>(No signature provided)</i>", normal_style))
    
    story.append(Spacer(1, 0.3 * inch))
    story.append(Paragraph("_" * 80, normal_style))
    story.append(Paragraph(
        f"© 2024 Jafari Credit | Report generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8, textColor=colors.grey, alignment=1)
    ))
    
    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()

# ============================================================
# START SERVER
# ============================================================
if __name__ == '__main__':
    PORT = int(os.getenv('PORT', 64462))
    HOST = os.getenv('HOST', '0.0.0.0')
    
    print("=" * 80)
    print("🏦 Jafari Credit - Customer Meeting Report Backend")
    print(f"📍 Server: http://localhost:{PORT}")
    print(f"🌐 Frontend URL (used in invites): {FRONTEND_URL}")
    print("=" * 80)
    print("\n📧 Email Configuration:")
    print(f"   DEV_MODE_EMAIL: {DEV_MODE_EMAIL}")
    if DEV_MODE_EMAIL:
        print("   → Invitation links will be LOGGED to console (no email sent)")
    else:
        print(f"   → SMTP_HOST:  {SMTP_HOST}")
        print(f"   → SMTP_PORT:  {SMTP_PORT}")
        print(f"   → SMTP_USER:  {SMTP_USER}")
        print(f"   → SMTP_FROM:  {SMTP_FROM}")
        print(f"   → TLS:        {SMTP_USE_TLS}")
    print("\n🔐 Authentication:")
    print(f"   Admin Email: {ADMIN_EMAIL}")
    print(f"   Admin Password: admin123")
    print("\n💰 Loan Products:")
    for code, label in LOAN_PRODUCT_MAP.items():
        print(f"   {code:12s} → {label}")
    print("=" * 80)
    print()
    
    app.run(host=HOST, port=PORT, debug=True, threaded=True, use_reloader=False)