"""
Jafari Credit - Customer Meeting Report backend (+ Loan Registry API)

Required environment variables
    MONGODB_URI            Mongo connection string
    JWT_SECRET_KEY         32+ random chars (app refuses to start without it)
    FRONTEND_URL           Public URL of the frontend (used in invite/reset links)

Optional
    SUPER_ADMIN_EMAIL / SUPER_ADMIN_PASSWORD / SUPER_ADMIN_NAME
                           Creates the first super admin ONLY if that email does
                           not exist yet. Never overwrites an existing password.
    CORS_ORIGINS           Comma-separated allowed origins (default: FRONTEND_URL)
    BREVO_API_KEY          Brevo transactional email over HTTPS (use this on Render free,
                           which blocks SMTP). Sender = MAIL_DEFAULT_SENDER
    RESEND_API_KEY         Alternative HTTPS email provider
    MAIL_SERVER / MAIL_PORT / MAIL_USERNAME / MAIL_PASSWORD / MAIL_DEFAULT_SENDER
                           SMTP (last resort; blocked on Render free)
    AT_USERNAME / AT_API_KEY / AT_SENDER_ID / AT_SANDBOX
                           Africa's Talking SMS for customer OTP
    OTP_DEV_MODE=true      Skip SMS and show the code to admins (testing only)
"""

import os
import io
import re
import csv
import json
import base64
import hashlib
import hmac
import secrets
import zipfile
import warnings
import urllib.error
import urllib.request
import urllib.parse
from datetime import datetime, timedelta, timezone
from functools import wraps
from xml.sax.saxutils import escape as xml_escape

from dotenv import load_dotenv
from flask import Flask, jsonify, request, send_from_directory, redirect
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token, get_jwt_identity, jwt_required
)
from flask_mail import Mail, Message
from mongoengine import (
    Document, StringField, EmailField, BooleanField, DateTimeField,
    ReferenceField, ListField, EmbeddedDocumentField, EmbeddedDocument,
    FloatField, IntField, CASCADE, NULLIFY, connect, Q
)
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.utils import ImageReader
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image as RLImage
)
import bcrypt

warnings.filterwarnings("ignore", category=DeprecationWarning)

# ------------------------------------------------------------------
# CONFIG
# ------------------------------------------------------------------
load_dotenv()


def env_bool(name, default=False):
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017/loan-registry")
JWT_SECRET = os.getenv("JWT_SECRET_KEY", "")
if len(JWT_SECRET) < 32 or JWT_SECRET == "change-me-in-prod":
    raise RuntimeError(
        "JWT_SECRET_KEY must be set to a random string of at least 32 characters. "
        "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(48))\""
    )

PORT = int(os.getenv("PORT", 5000))

FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5000").strip().rstrip("/")
if FRONTEND_URL.endswith("/index.html"):
    FRONTEND_URL = FRONTEND_URL[: -len("/index.html")]

# Comma, semicolon or space separated. FRONTEND_URL is always allowed.
CORS_ORIGINS = sorted({o.strip().rstrip("/") for o in
                       re.split(r"[,;\s]+", os.getenv("CORS_ORIGINS", "") + " " + FRONTEND_URL) if o.strip()})

SUPER_ADMIN_EMAIL = os.getenv("SUPER_ADMIN_EMAIL", "").strip().lower()
SUPER_ADMIN_PASSWORD = os.getenv("SUPER_ADMIN_PASSWORD", "")
SUPER_ADMIN_NAME = os.getenv("SUPER_ADMIN_NAME", "Super Admin")
SUPER_ADMIN_ORG = os.getenv("SUPER_ADMIN_ORG", "Jafari Credit")
SUPER_ADMIN_ORG_REG = os.getenv("SUPER_ADMIN_ORG_REG", "REG-JAFARI-001")

OTP_DEV_MODE = env_bool("OTP_DEV_MODE", False)

# Customer verification features. Both are OFF until they are production-ready
# (live Africa's Talking account / live-camera selfie). Turn on with
# FEATURE_OTP=true / FEATURE_SELFIE=true in .env and reload - no code change needed.
FEATURE_OTP = env_bool("FEATURE_OTP", False)
FEATURE_SELFIE = env_bool("FEATURE_SELFIE", False)


def active_checks():
    """Checks that count towards a report's verification level right now."""
    checks = ["customer_signature"]
    if FEATURE_OTP:
        checks.append("otp")
    if FEATURE_SELFIE:
        checks.append("selfie")
    return checks
OTP_TTL_MINUTES = 10
OTP_MAX_ATTEMPTS = 5
OTP_RESEND_COOLDOWN_SECONDS = 60
OTP_TOKEN_VALID_HOURS = 4  # a verified OTP must be used in a report within this window

MIN_PASSWORD_LENGTH = 8
INVITE_TTL = timedelta(days=7)
RESET_TTL = timedelta(hours=24)

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

app = Flask(__name__, static_folder=None)
app.config["JWT_SECRET_KEY"] = JWT_SECRET
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=7)
app.config["MAX_CONTENT_LENGTH"] = 12 * 1024 * 1024  # 12 MB per request
app.config["MAIL_SERVER"] = os.getenv("MAIL_SERVER", "")
app.config["MAIL_PORT"] = int(os.getenv("MAIL_PORT", 587))
app.config["MAIL_USE_TLS"] = env_bool("MAIL_USE_TLS", True)
app.config["MAIL_USE_SSL"] = env_bool("MAIL_USE_SSL", False)
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME", "")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD", "")
app.config["MAIL_DEFAULT_SENDER"] = (os.getenv("MAIL_DEFAULT_SENDER") or os.getenv("BREVO_SENDER_EMAIL")
                                     or "notifications@jafaricredit.co.ke")

# Preflight (OPTIONS) is answered automatically by Flask + Flask-CORS, so views
# never list OPTIONS themselves and auth decorators never see preflight requests.
CORS(app, resources={r"/api/*": {
    "origins": CORS_ORIGINS or "*",
    "methods": ["GET", "POST", "PUT", "PATCH", "DELETE"],
    "allow_headers": ["Content-Type", "Authorization"],
}})

jwt = JWTManager(app)
mail = Mail(app)

def _connect_db():
    if env_bool("USE_MONGOMOCK"):
        import mongomock  # local testing only
        connect("jafari_test", host="mongodb://localhost", mongo_client_class=mongomock.MongoClient)
    else:
        # connect=False: open sockets lazily, after the web server has forked its workers
        # (required on PythonAnywhere/uWSGI; harmless on gunicorn).
        connect(host=MONGODB_URI, connect=False, connectTimeoutMS=30000,
                serverSelectionTimeoutMS=30000, maxPoolSize=10)


_connect_db()


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def iso(dt):
    """Naive-UTC datetime -> ISO string with Z so browsers parse it as UTC."""
    return dt.isoformat() + "Z" if dt else None


def err(message, status=400, **extra):
    body = {"success": False, "error": message, "message": message}
    body.update(extra)
    return jsonify(body), status


def int_arg(name, default, lo=1, hi=1000):
    try:
        return max(lo, min(hi, int(request.args.get(name, default))))
    except (TypeError, ValueError):
        return default


# ------------------------------------------------------------------
# ROLES
# ------------------------------------------------------------------
ROLES = ["super_admin", "admin_agent", "branch_manager", "team_leader", "auditor", "sales_agent"]
ROLE_RANK = {"super_admin": 4, "admin_agent": 3, "branch_manager": 2, "team_leader": 2, "auditor": 1, "sales_agent": 1}
# Who can sign off (approve) an agent's meeting report
APPROVER_ROLES = ("team_leader", "branch_manager")
REPORT_STATUSES = ("pending_signoff", "final", "returned")
USER_ADMIN_ROLES = ("super_admin", "admin_agent")
AUDIT_VIEW_ROLES = ("super_admin", "admin_agent", "auditor")


def grantable_roles(actor):
    """Roles an actor may assign. Super admin: any. Others: strictly lower rank."""
    if actor.role == "super_admin":
        return list(ROLES)
    return [r for r in ROLES if ROLE_RANK[r] < ROLE_RANK.get(actor.role, 0)]


def can_manage(actor, target):
    """Actor may act on target only if target is in scope and strictly lower rank."""
    if target.id == actor.id:
        return False
    if actor.role == "super_admin":
        return True
    if target.organization != actor.organization:
        return False
    return ROLE_RANK.get(target.role, 0) < ROLE_RANK.get(actor.role, 0)


BRANCH_NAMES = {
    "narok": "Narok - Olma House 2nd Floor",
    "mombasa": "Mombasa - Makadara Building 2nd Floor Room 3",
    "kisumu": "Kisumu - Tuffoam Mall 1st Floor",
    "nakuru": "Nakuru - Cigma Business Center Room 3F",
    "eldoret": "Eldoret - Tamarind Place",
    "nyeri": "Nyeri - Lymo Plaza 1st Floor Room 1.5",
    "malindi": "Malindi - Market Village Stall 10",
    "kajiado": "Kajiado - Emerald Business Center 2nd Floor",
    "kisii": "Kisii - Twin Towers 2nd Floor Room 203",
    "kakamega": "Kakamega - Shivcom Building 2nd Floor Room FB",
    "machakos": "Machakos - Elice Center Ground Floor",
    "garissa": "Garissa - Maalim House Next to KCB",
    "isiolo": "Isiolo - Ibada Plaza Office C3",
    "bomet": "Bomet - Kosal Plaza 2nd Floor Room 28",
    "embu": "Embu - Housing Finance 4th Floor",
    "homabay": "HomaBay - Glory Building 1st Floor",
    "kilifi": "Kilifi - Boabab Plaza 1st Floor Room 9",
    "coast": "Coast - Yusuf Ali Mansion Building 4th Floor",
    "nairobi": "Nairobi - Caxton House 2nd Floor, Kenyatta Avenue",
}

OFFICER_ROLE_NAMES = {
    "team_lead": "Team Lead",
    "sales_agent": "Sales Agent",
    "region_lead": "Region Lead",
    "branch_coordinator": "Branch Coordinator",
    "junior_team_leader": "Junior Team Leader",
}


def normalize_phone(raw):
    """Normalise Kenyan numbers to +2547XXXXXXXX / +2541XXXXXXXX. Returns None if invalid."""
    if not raw:
        return None
    s = "".join(ch for ch in str(raw) if ch.isdigit() or ch == "+")
    if s.startswith("+"):
        digits = s[1:]
    else:
        digits = s
        if digits.startswith("0") and len(digits) == 10:
            digits = "254" + digits[1:]
        elif len(digits) == 9 and digits[0] in "17":
            digits = "254" + digits
    if not digits.isdigit() or len(digits) < 10 or len(digits) > 15:
        return None
    return "+" + digits


# ------------------------------------------------------------------
# MODELS
# ------------------------------------------------------------------
class Organization(Document):
    name = StringField(required=True)
    registration_number = StringField(required=True, unique=True)
    license_number = StringField()
    address = StringField()
    contact_email = EmailField()
    contact_phone = StringField()
    is_active = BooleanField(default=True)
    created_at = DateTimeField(default=utcnow)
    updated_at = DateTimeField(default=utcnow)

    meta = {"collection": "organizations"}

    def to_dict(self):
        return {
            "_id": str(self.id),
            "name": self.name,
            "registrationNumber": self.registration_number,
            "isActive": self.is_active,
        }


class Branch(Document):
    name = StringField(required=True)
    code = StringField(required=True)
    organization = ReferenceField(Organization, required=True, reverse_delete_rule=CASCADE)
    address = StringField()
    manager_name = StringField()
    contact_email = EmailField()
    contact_phone = StringField()
    is_active = BooleanField(default=True)
    created_at = DateTimeField(default=utcnow)

    meta = {
        "collection": "branches",
        "indexes": [{"fields": ["organization", "code"], "unique": True}],
    }

    def to_dict(self):
        return {
            "_id": str(self.id),
            "name": self.name,
            "code": self.code,
            "organizationId": str(self.organization.id) if self.organization else None,
            "address": {"city": self.address} if self.address else {},
            "managerName": self.manager_name,
            "contactEmail": self.contact_email,
            "contactPhone": self.contact_phone,
            "isActive": self.is_active,
        }


class User(Document):
    name = StringField(required=True)
    email = EmailField(required=True, unique=True)
    password_hash = StringField()
    role = StringField(choices=ROLES, default="admin_agent")
    organization = ReferenceField(Organization, required=True, reverse_delete_rule=CASCADE)
    assigned_branches = ListField(ReferenceField(Branch))
    is_active = BooleanField(default=True)
    last_login = DateTimeField()
    must_change_password = BooleanField(default=False)
    created_at = DateTimeField(default=utcnow)

    meta = {"collection": "users", "strict": False}

    def set_password(self, raw):
        self.password_hash = bcrypt.hashpw(raw.encode(), bcrypt.gensalt()).decode()

    def check_password(self, raw):
        if not self.password_hash:
            return False
        try:
            return bcrypt.checkpw(raw.encode(), self.password_hash.encode())
        except Exception:
            return False

    def to_dict(self):
        status = "pending" if not self.password_hash else ("active" if self.is_active else "inactive")
        return {
            "id": str(self.id),
            "_id": str(self.id),
            "name": self.name,
            "email": self.email,
            "role": self.role,
            "organization": self.organization.to_dict() if self.organization else None,
            "isActive": self.is_active,
            "hasPassword": bool(self.password_hash),
            "password_set": bool(self.password_hash),
            "status": status,
            "lastLogin": iso(self.last_login),
            "mustChangePassword": bool(self.must_change_password),
            "createdAt": iso(self.created_at),
        }


class Invitation(Document):
    """Used for both new-user invites (purpose=invite) and password resets (purpose=reset)."""
    email = EmailField(required=True)
    name = StringField()
    # Stored in the existing "token" column (keeps the old unique index valid).
    # New rows hold a SHA-256 of the token; legacy rows hold the raw token.
    token_hash = StringField(db_field="token", required=True, unique=True)
    purpose = StringField(choices=["invite", "reset"], default="invite")
    role = StringField(choices=ROLES, default="admin_agent")
    organization = ReferenceField(Organization, required=True, reverse_delete_rule=CASCADE)
    invited_by = ReferenceField(User, reverse_delete_rule=NULLIFY)
    assigned_branches = ListField(ReferenceField(Branch))
    status = StringField(choices=["pending", "accepted", "revoked", "expired"], default="pending")
    expires_at = DateTimeField(required=True)
    accepted_at = DateTimeField()
    created_at = DateTimeField(default=utcnow)

    meta = {"collection": "invitations", "indexes": ["email", "status"], "strict": False}

    def is_valid(self):
        return self.status == "pending" and self.expires_at and self.expires_at > utcnow()

    def to_dict(self):
        return {
            "_id": str(self.id),
            "email": self.email,
            "name": self.name,
            "purpose": self.purpose,
            "role": self.role,
            "status": self.status,
            "expiresAt": iso(self.expires_at),
            "acceptedAt": iso(self.accepted_at),
            "createdAt": iso(self.created_at),
            "invitedBy": self.invited_by.name if self.invited_by else None,
        }


def hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


class OtpCode(Document):
    """Customer OTP. Stored in Mongo so it works across workers/machines and restarts."""
    phone = StringField(required=True)
    code_hash = StringField(required=True)
    requested_by = ReferenceField(User, reverse_delete_rule=NULLIFY)
    organization = ReferenceField(Organization, reverse_delete_rule=CASCADE)
    expires_at = DateTimeField(required=True)
    attempts = IntField(default=0)
    verified = BooleanField(default=False)
    verified_at = DateTimeField()
    token_hash = StringField()
    consumed = BooleanField(default=False)
    consumed_by_report = StringField()
    created_at = DateTimeField(default=utcnow)
    purge_at = DateTimeField(required=True)

    meta = {
        "collection": "otp_codes",
        "indexes": [
            "phone",
            "token_hash",
            {"fields": ["purge_at"], "expireAfterSeconds": 0},
        ],
    }


class Borrower(EmbeddedDocument):
    full_name = StringField(required=True)
    id_number = StringField(required=True)
    phone = StringField()
    email = StringField()
    address = StringField()
    occupation = StringField()

    def to_dict(self):
        return {
            "fullName": self.full_name,
            "idNumber": self.id_number,
            "phone": self.phone,
            "email": self.email,
            "address": self.address,
            "occupation": self.occupation,
        }


class Loan(Document):
    loan_number = StringField(required=True, unique=True)
    organization = ReferenceField(Organization, required=True, reverse_delete_rule=CASCADE)
    branch = ReferenceField(Branch, required=True, reverse_delete_rule=CASCADE)
    borrower = EmbeddedDocumentField(Borrower, required=True)
    loan_type = StringField(
        choices=["personal", "business", "mortgage", "auto", "education", "agriculture"],
        required=True,
    )
    principal_amount = FloatField(required=True)
    interest_rate = FloatField(required=True)
    term_months = IntField(required=True)
    total_repayable = FloatField(default=0)
    amount_paid = FloatField(default=0)
    outstanding_balance = FloatField(default=0)
    currency = StringField(default="KES")
    status = StringField(
        choices=["pending", "approved", "active", "disbursed", "repaying",
                 "completed", "defaulted", "rejected", "written_off"],
        default="pending",
    )
    disbursement_date = DateTimeField()
    maturity_date = DateTimeField()
    next_payment_date = DateTimeField()
    notes = StringField()
    created_by = ReferenceField(User, reverse_delete_rule=NULLIFY)
    approved_by = ReferenceField(User, reverse_delete_rule=NULLIFY)
    created_at = DateTimeField(default=utcnow)
    updated_at = DateTimeField(default=utcnow)

    meta = {
        "collection": "loans",
        "indexes": ["organization", "branch", "status", "loan_number"],
    }

    def save(self, *args, **kwargs):
        rate = self.interest_rate / 100
        self.total_repayable = self.principal_amount * (1 + rate * (self.term_months / 12))
        self.outstanding_balance = max(0, self.total_repayable - self.amount_paid)
        self.updated_at = utcnow()
        return super().save(*args, **kwargs)

    def to_dict(self):
        return {
            "_id": str(self.id),
            "loanNumber": self.loan_number,
            "organizationId": str(self.organization.id) if self.organization else None,
            "branchId": (
                {"_id": str(self.branch.id), "name": self.branch.name, "code": self.branch.code}
                if self.branch else None
            ),
            "borrower": self.borrower.to_dict() if self.borrower else {},
            "loanType": self.loan_type,
            "principalAmount": self.principal_amount,
            "interestRate": self.interest_rate,
            "termMonths": self.term_months,
            "totalRepayable": self.total_repayable,
            "amountPaid": self.amount_paid,
            "outstandingBalance": self.outstanding_balance,
            "currency": self.currency,
            "status": self.status,
            "nextPaymentDate": iso(self.next_payment_date),
            "createdAt": iso(self.created_at),
            "updatedAt": iso(self.updated_at),
        }


# Fields copied verbatim from the form into MeetingReport (all strings).
REPORT_TEXT_FIELDS = [
    "created_by", "user_role", "agent_code", "meeting_date", "meeting_time",
    "meeting_datetime", "branch", "meeting_location",
    "customer_name", "customer_id", "customer_id_no", "customer_phone",
    "customer_email", "customer_employer", "customer_address", "customer_status",
    "customer_sales_lead",
    "gps_locator", "gps_accuracy",
    "loan_product", "meeting_confirmed",
    "kyc_status", "kyc_id_type", "kyc_date_verified", "kyc_verified_by",
    "discussion_summary",
    "customer_signed_at", "customer_signed_gps",
    "selfie_gps", "selfie_timestamp", "officer_gps_at_signature",
    "unverified_reason",
]
REPORT_IMAGE_FIELDS = [
    "team_leader_signature_image", "agent_signature_image",
    "customer_signature_image", "selfie_image",
]
REPORT_REQUIRED = [
    "created_by", "user_role", "agent_code", "meeting_datetime", "branch",
    "meeting_confirmed", "customer_name", "discussion_summary", "kyc_status",
]


class MeetingReport(Document):
    report_id = StringField(required=True, unique=True)
    organization = ReferenceField(Organization, required=True, reverse_delete_rule=CASCADE)
    generated_by = ReferenceField(User, reverse_delete_rule=NULLIFY)
    generated_by_email = StringField()
    generated_by_name = StringField()

    # form fields (dynamic-ish, all strings)
    created_by = StringField()
    user_role = StringField()
    agent_code = StringField()
    meeting_date = StringField()
    meeting_time = StringField()
    meeting_datetime = StringField()
    branch = StringField()
    meeting_location = StringField()
    customer_name = StringField()
    customer_id = StringField()
    customer_id_no = StringField()
    customer_phone = StringField()
    customer_email = StringField()
    customer_employer = StringField()
    customer_address = StringField()
    customer_status = StringField()
    customer_sales_lead = StringField()
    gps_locator = StringField()
    gps_accuracy = StringField()
    loan_product = StringField()
    loan_amount = FloatField()
    meeting_confirmed = StringField()
    kyc_status = StringField()
    kyc_id_type = StringField()
    kyc_date_verified = StringField()
    kyc_verified_by = StringField()
    kyc_notes = StringField()  # no longer collected; kept so older reports still load
    discussion_summary = StringField()
    customer_signed_at = StringField()
    customer_signed_gps = StringField()
    selfie_gps = StringField()
    selfie_timestamp = StringField()
    officer_gps_at_signature = StringField()
    unverified_reason = StringField()

    team_leader_signature_image = StringField()
    agent_signature_image = StringField()
    customer_signature_image = StringField()
    selfie_image = StringField()

    team_leader_confirmed = BooleanField(default=False)
    agent_confirmed = BooleanField(default=False)
    customer_confirmed = BooleanField(default=False)

    # server-verified
    otp_verified = BooleanField(default=False)
    otp_phone = StringField()
    otp_verified_at = DateTimeField()
    verification_level = StringField(choices=["full", "partial", "unverified"], default="unverified")
    verification_checks = StringField()  # e.g. "customer_signature,otp" - which checks applied
    payload_hash = StringField()
    ip_address = StringField()
    created_at = DateTimeField(default=utcnow)

    # Two-step workflow: agent submits (pending_signoff) -> team leader signs (final) or returns it
    status = StringField(choices=REPORT_STATUSES, default="final")  # reports made before this feature are final
    assigned_team_leader = ReferenceField(User, reverse_delete_rule=NULLIFY)
    assigned_team_leader_name = StringField()
    assigned_team_leader_email = StringField()
    tl_signed_by = ReferenceField(User, reverse_delete_rule=NULLIFY)
    tl_signed_by_name = StringField()
    tl_signed_by_email = StringField()
    tl_signed_at = DateTimeField()
    tl_signed_gps = StringField()
    tl_comment = StringField()
    returned_by_name = StringField()
    returned_at = DateTimeField()
    return_reason = StringField()
    final_hash = StringField()

    voided = BooleanField(default=False)
    voided_by = ReferenceField(User, reverse_delete_rule=NULLIFY)
    voided_at = DateTimeField()
    void_reason = StringField()

    meta = {
        "collection": "meeting_reports",
        "indexes": ["organization", "-created_at", "generated_by_email", "customer_name",
                    "status", "assigned_team_leader", "generated_by"],
    }

    def canonical(self):
        """Stable dict used for the tamper-evidence hash."""
        d = {f: getattr(self, f) or "" for f in REPORT_TEXT_FIELDS + REPORT_IMAGE_FIELDS}
        d.update({
            "report_id": self.report_id,
            "loan_amount": self.loan_amount,
            "generated_by_email": self.generated_by_email,
            "otp_verified": self.otp_verified,
            "otp_phone": self.otp_phone or "",
            "otp_verified_at": iso(self.otp_verified_at) or "",
            "verification_level": self.verification_level,
            "verification_checks": self.verification_checks or "",
            "created_at": iso(self.created_at),
        })
        return d

    def compute_hash(self):
        raw = json.dumps(self.canonical(), sort_keys=True, default=str).encode()
        return hashlib.sha256(raw).hexdigest()

    def compute_final_hash(self):
        """Hash of the submitted data (payload_hash) plus the team leader's sign-off."""
        d = {
            "payload_hash": self.payload_hash,
            "team_leader_signature_image": self.team_leader_signature_image or "",
            "tl_signed_by_email": self.tl_signed_by_email or "",
            "tl_signed_at": iso(self.tl_signed_at) or "",
            "tl_signed_gps": self.tl_signed_gps or "",
            "tl_comment": self.tl_comment or "",
        }
        return hashlib.sha256(json.dumps(d, sort_keys=True).encode()).hexdigest()

    @property
    def effective_status(self):
        return self.status or "final"

    def workflow_dict(self):
        waiting = None
        if self.effective_status == "pending_signoff" and self.created_at:
            waiting = round((utcnow() - self.created_at).total_seconds() / 3600, 1)
        return {
            "status": self.effective_status,
            "assigned_team_leader_name": self.assigned_team_leader_name,
            "assigned_team_leader_email": self.assigned_team_leader_email,
            "tl_signed_by_name": self.tl_signed_by_name,
            "tl_signed_at": iso(self.tl_signed_at),
            "tl_comment": self.tl_comment,
            "returned_by_name": self.returned_by_name,
            "returned_at": iso(self.returned_at),
            "return_reason": self.return_reason,
            "waiting_hours": waiting,
            "final_hash": self.final_hash,
        }

    def to_audit_dict(self):
        return {
            "id": str(self.id),
            "_id": str(self.id),
            "report_id": self.report_id,
            "timestamp": iso(self.created_at),
            "createdAt": iso(self.created_at),
            "generated_by_name": self.generated_by_name,
            "generated_by_email": self.generated_by_email,
            "officer_name": self.created_by,
            "agent_code": self.agent_code,
            "customer_name": self.customer_name,
            "customer_no": self.customer_id,
            "customer_phone": self.customer_phone,
            "loan_product": self.loan_product,
            "loan_amount": self.loan_amount,
            "branch": BRANCH_NAMES.get(self.branch, self.branch),
            "branch_code": self.branch,
            "gps": self.gps_locator,
            "verification_level": self.verification_level,
            "verification_checks": self.verification_checks or "",
            "has_team_leader_sig": bool(self.team_leader_signature_image),
            "has_agent_sig": bool(self.agent_signature_image),
            "has_customer_sig": bool(self.customer_signature_image),
            "has_selfie": bool(self.selfie_image),
            "otp_verified": self.otp_verified,
            "unverified_reason": self.unverified_reason,
            "payload_hash": self.payload_hash,
            **self.workflow_dict(),
        }


class AuditLog(Document):
    """System events (logins, invites, user changes, report creation/voiding)."""
    organization = ReferenceField(Organization, required=True, reverse_delete_rule=CASCADE)
    user = ReferenceField(User, reverse_delete_rule=NULLIFY)
    user_email = StringField()
    action = StringField(required=True)
    entity_type = StringField()
    entity_id = StringField()
    details = StringField()
    ip_address = StringField()
    created_at = DateTimeField(default=utcnow)

    meta = {"collection": "audit_logs", "indexes": ["organization", "-created_at"]}

    def to_dict(self):
        return {
            "_id": str(self.id),
            "id": str(self.id),
            "action": self.action,
            "entityType": self.entity_type,
            "entityId": self.entity_id,
            "details": self.details,
            "userName": self.user.name if self.user else "System",
            "userEmail": self.user_email or (self.user.email if self.user else None),
            "ipAddress": self.ip_address,
            "createdAt": iso(self.created_at),
            "timestamp": iso(self.created_at),
        }


def client_ip():
    fwd = request.headers.get("Fly-Client-IP") or request.headers.get("X-Forwarded-For", "")
    return (fwd.split(",")[0].strip() if fwd else None) or request.remote_addr


def log_action(user, action, entity_type=None, entity_id=None, details=None):
    try:
        AuditLog(
            organization=user.organization,
            user=user,
            user_email=user.email,
            action=action,
            entity_type=entity_type,
            entity_id=str(entity_id) if entity_id else None,
            details=details,
            ip_address=client_ip(),
        ).save()
    except Exception as e:
        print(f"[audit] failed: {e}")


# ------------------------------------------------------------------
# AUTH HELPERS
# ------------------------------------------------------------------
def current_user():
    uid = get_jwt_identity()
    if not uid:
        return None
    try:
        return User.objects.get(id=uid)
    except Exception:
        return None


# Endpoints a user may call while must_change_password is set.
PASSWORD_CHANGE_ALLOWED = {"me", "logout", "change_password"}


def auth_required(*roles):
    """@auth_required() for any active user, @auth_required('super_admin', ...) to restrict."""
    def decorator(fn):
        @wraps(fn)
        @jwt_required()
        def wrapper(*args, **kwargs):
            user = current_user()
            if not user or not user.is_active or not user.password_hash:
                return err("User not found or inactive", 401)
            if user.must_change_password and fn.__name__ not in PASSWORD_CHANGE_ALLOWED:
                return err("You must set a new password before continuing", 403, mustChangePassword=True)
            if roles and user.role not in roles:
                return err("Insufficient permissions", 403)
            return fn(user, *args, **kwargs)
        return wrapper
    return decorator


def parse_date(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).replace(tzinfo=None)
    except Exception:
        return None


# ------------------------------------------------------------------
# EMAIL + SMS
# ------------------------------------------------------------------
BREVO_API_URL = os.getenv("BREVO_API_URL", "https://api.brevo.com/v3/smtp/email")
RESEND_API_URL = os.getenv("RESEND_API_URL", "https://api.resend.com/emails")


def _post_json(url, payload, headers, label):
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(), method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json", **headers},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            if 200 <= r.status < 300:
                return True
            print(f"[mail] {label} HTTP {r.status}")
    except urllib.error.HTTPError as e:
        print(f"[mail] {label} HTTP {e.code}: {e.read()[:300]!r}")
    except Exception as e:
        print(f"[mail] {label} failed: {e}")
    return False


def send_email(to, subject, html):
    """
    Tries, in order:
      1. Brevo HTTP API  (BREVO_API_KEY)   - works on hosts that block SMTP (Render free)
      2. Resend HTTP API (RESEND_API_KEY)
      3. SMTP            (MAIL_SERVER/MAIL_USERNAME/MAIL_PASSWORD)
    Returns True if one of them accepted the message.
    """
    cfg = app.config
    sender = cfg["MAIL_DEFAULT_SENDER"]
    sender_name = os.getenv("MAIL_SENDER_NAME") or os.getenv("BREVO_SENDER_NAME") or "Jafari Credit"

    brevo_key = os.getenv("BREVO_API_KEY")
    if brevo_key and _post_json(BREVO_API_URL, {
        "sender": {"email": sender, "name": sender_name},
        "to": [{"email": to}],
        "subject": subject,
        "htmlContent": html,
    }, {"api-key": brevo_key}, "Brevo API"):
        return True

    resend_key = os.getenv("RESEND_API_KEY")
    if resend_key and _post_json(RESEND_API_URL, {
        "from": f"{sender_name} <{sender}>", "to": [to], "subject": subject, "html": html,
    }, {"Authorization": f"Bearer {resend_key}"}, "Resend API"):
        return True

    if cfg["MAIL_SERVER"] and cfg["MAIL_USERNAME"] and cfg["MAIL_PASSWORD"]:
        import socket
        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(15)  # a blocked SMTP port must not hang the request
        try:
            mail.send(Message(subject=subject, recipients=[to], html=html))
            return True
        except Exception as e:
            print(f"[mail] SMTP failed: {e}")
        finally:
            socket.setdefaulttimeout(old)

    print("[mail] no working mail transport; link must be shared manually")
    return False


def send_invite_email(invite, inviter, link):
    org_name = xml_escape(invite.organization.name if invite.organization else "Jafari Credit")
    inviter_name = xml_escape(inviter.name if inviter else "An administrator")
    link_e = xml_escape(link)
    if invite.purpose == "reset":
        subject = "Reset your Jafari Credit password"
        body = f"""
            <p>Hello{(' ' + xml_escape(invite.name)) if invite.name else ''},</p>
            <p><strong>{inviter_name}</strong> has sent you a password reset link for the
            Customer Meeting Report app.</p>
            <p><a href="{link_e}">Set a new password</a></p>
            <p>Or paste this link into your browser:<br>{link_e}</p>
            <p>This link expires in 24 hours. If you didn't expect it, you can ignore this email.</p>"""
    else:
        role = xml_escape(invite.role.replace("_", " ").title())
        subject = f"You're invited to {org_name} - Customer Meeting Report"
        body = f"""
            <p>Hello{(' ' + xml_escape(invite.name)) if invite.name else ''},</p>
            <p><strong>{inviter_name}</strong> has invited you to join <strong>{org_name}</strong>
            as <strong>{role}</strong>.</p>
            <p><a href="{link_e}">Accept invitation and set your password</a></p>
            <p>Or paste this link into your browser:<br>{link_e}</p>
            <p>This invitation expires in 7 days.</p>"""
    return send_email(invite.email, subject, body)


def sms_configured():
    return bool(os.getenv("AT_USERNAME") and os.getenv("AT_API_KEY"))


def send_sms(phone, message):
    """Africa's Talking bulk SMS API. Returns (ok, detail)."""
    username = os.getenv("AT_USERNAME")
    api_key = os.getenv("AT_API_KEY")
    sandbox = env_bool("AT_SANDBOX", username == "sandbox")
    url = ("https://api.sandbox.africastalking.com/version1/messaging" if sandbox
           else "https://api.africastalking.com/version1/messaging")
    params = {"username": username, "to": phone, "message": message}
    if os.getenv("AT_SENDER_ID"):
        params["from"] = os.getenv("AT_SENDER_ID")
    req = urllib.request.Request(
        url, data=urllib.parse.urlencode(params).encode(), method="POST",
        headers={"apiKey": api_key, "Accept": "application/json",
                 "Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read().decode() or "{}")
        recipients = (data.get("SMSMessageData") or {}).get("Recipients") or []
        ok = any(str(rc.get("statusCode")) in ("100", "101", "102") for rc in recipients)
        return ok, (recipients[0].get("status") if recipients else data.get("SMSMessageData", {}).get("Message"))
    except Exception as e:
        return False, str(e)


# ------------------------------------------------------------------
# INVITE / RESET HELPERS
# ------------------------------------------------------------------
def build_link(token):
    # Query-string form works on any static host without rewrite rules.
    return f"{FRONTEND_URL}/?invite={urllib.parse.quote(token)}"


def issue_token(email, purpose, role, organization, actor, name=None, branches=None):
    """Revoke any pending token of the same purpose for this email, then issue a new one."""
    Invitation.objects(email=email, purpose=purpose, status="pending").update(set__status="revoked")
    raw = secrets.token_urlsafe(32)
    invite = Invitation(
        email=email, name=name or None, token_hash=hash_token(raw), purpose=purpose,
        role=role, organization=organization, invited_by=actor,
        assigned_branches=branches or [],
        expires_at=utcnow() + (RESET_TTL if purpose == "reset" else INVITE_TTL),
    ).save()
    link = build_link(raw)
    emailed = send_invite_email(invite, actor, link)
    return invite, link, emailed


def find_invite(raw_token):
    if not raw_token:
        return None
    return (Invitation.objects(token_hash=hash_token(raw_token)).first()
            or Invitation.objects(token_hash=raw_token).first())  # legacy plaintext links


# ------------------------------------------------------------------
# HEALTH
# ------------------------------------------------------------------
@app.route("/api/config", methods=["GET"])
def public_config():
    """Which optional features the frontend should show."""
    return jsonify({"success": True, "features": {"otp": FEATURE_OTP, "selfie": FEATURE_SELFIE}})


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "OK", "timestamp": iso(utcnow())})


# ------------------------------------------------------------------
# AUTH
# ------------------------------------------------------------------
# NOTE: public self-registration has been removed on purpose. Users join only
# through an admin invitation.


@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    if not email or not password:
        return err("Email and password required", 400)
    user = User.objects(email=email).first()
    if not user or not user.check_password(password):
        return err("Invalid email or password", 401)
    if not user.is_active:
        return err("Account deactivated. Contact your administrator.", 403)
    user.last_login = utcnow()
    user.save()
    log_action(user, "user.login", "user", user.id)
    token = create_access_token(identity=str(user.id))
    return jsonify({"success": True, "token": token, "user": user.to_dict()})


@app.route("/api/auth/me", methods=["GET"])
@auth_required()
def me(user):
    return jsonify({"success": True, "user": user.to_dict(), "grantableRoles": grantable_roles(user)})


@app.route("/api/auth/logout", methods=["POST"])
@auth_required()
def logout(user):
    # JWTs are stateless; the client discards the token.
    return jsonify({"success": True})


@app.route("/api/auth/change-password", methods=["POST"])
@auth_required()
def change_password(user):
    data = request.get_json(silent=True) or {}
    current = data.get("current_password") or ""
    new = data.get("new_password") or ""
    if not user.check_password(current):
        return err("Current password is incorrect", 400)
    if len(new) < MIN_PASSWORD_LENGTH:
        return err(f"New password must be at least {MIN_PASSWORD_LENGTH} characters", 400)
    if new == current:
        return err("New password must be different", 400)
    user.set_password(new)
    user.must_change_password = False
    user.save()
    log_action(user, "user.change_password", "user", user.id)
    return jsonify({"success": True, "message": "Password changed", "user": user.to_dict()})


@app.route("/api/auth/validate-invitation/<path:token>", methods=["GET"])
def auth_validate_invitation(token):
    invite = find_invite(token)
    if not invite:
        return err("This link is invalid. Ask your administrator for a new one.", 404)
    if not invite.is_valid():
        msg = {
            "accepted": "This link has already been used. Sign in with your email and password.",
            "revoked": "This link has been replaced by a newer one. Check your email or ask your administrator.",
        }.get(invite.status, "This link has expired. Ask your administrator for a new one.")
        return err(msg, 400, invite_status=invite.status)
    return jsonify({
        "success": True,
        "email": invite.email,
        "name": invite.name,
        "purpose": invite.purpose,
        "role": invite.role,
        "organization": invite.organization.name if invite.organization else "",
        "expiresAt": iso(invite.expires_at),
    })


@app.route("/api/auth/setup-password", methods=["POST"])
def auth_setup_password():
    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    password = data.get("password") or ""
    confirm = data.get("confirm_password")
    if not token:
        return err("Missing invitation token", 400)
    if len(password) < MIN_PASSWORD_LENGTH:
        return err(f"Password must be at least {MIN_PASSWORD_LENGTH} characters", 400)
    if confirm is not None and password != confirm:
        return err("Passwords do not match", 400)

    invite = find_invite(token)
    if not invite:
        return err("This link is invalid. Ask your administrator for a new one.", 404)
    if not invite.is_valid():
        return err("This link has expired or was already used.", 400)

    existing = User.objects(email=invite.email).first()
    if invite.purpose == "reset":
        if not existing:
            return err("Account no longer exists", 404)
        user = existing
        user.set_password(password)
        user.save()
        action = "user.password_reset"
    else:
        if existing and existing.password_hash:
            return err("An account with this email already exists. Sign in instead.", 400)
        name = (data.get("name") or "").strip() or invite.name or \
            invite.email.split("@")[0].replace(".", " ").replace("_", " ").title()
        user = existing or User(email=invite.email)
        user.name = name
        user.role = invite.role
        user.organization = invite.organization
        user.assigned_branches = invite.assigned_branches
        user.is_active = True
        user.set_password(password)
        user.save()
        action = "user.accept_invite"

    user.must_change_password = False
    invite.status = "accepted"
    invite.accepted_at = utcnow()
    invite.save()
    # Any other outstanding tokens for this email are now pointless.
    Invitation.objects(email=invite.email, status="pending").update(set__status="revoked")

    user.last_login = utcnow()
    user.save()
    log_action(user, action, "user", user.id)
    jwt_token = create_access_token(identity=str(user.id))
    return jsonify({"success": True, "token": jwt_token, "user": user.to_dict()}), 201


# ------------------------------------------------------------------
# ADMIN USER MANAGEMENT
# ------------------------------------------------------------------
def pending_invites_for(actor):
    qs = Invitation.objects(status="pending", purpose="invite")
    if actor.role != "super_admin":
        qs = qs.filter(organization=actor.organization)
    return [i for i in qs if i.is_valid() and not User.objects(email=i.email, password_hash__ne=None).first()]


@app.route("/api/admin/users", methods=["GET"])
@auth_required(*AUDIT_VIEW_ROLES)
def admin_list_users(actor):
    qs = User.objects if actor.role == "super_admin" else User.objects(organization=actor.organization)
    data = []
    for u in qs.order_by("name"):
        d = u.to_dict()
        d["canManage"] = actor.role in USER_ADMIN_ROLES and can_manage(actor, u)
        data.append(d)

    # Show invited-but-not-yet-accepted people as "pending" rows.
    known = {d["email"] for d in data}
    for inv in pending_invites_for(actor):
        if inv.email in known:
            continue
        known.add(inv.email)
        data.append({
            "id": None, "_id": None, "email": inv.email, "name": inv.name or "",
            "role": inv.role, "status": "pending", "hasPassword": False, "password_set": False,
            "isActive": True, "invitedAt": iso(inv.created_at), "expiresAt": iso(inv.expires_at),
            "canManage": actor.role == "super_admin" or (
                actor.role in USER_ADMIN_ROLES and ROLE_RANK[inv.role] < ROLE_RANK[actor.role]),
            "isInvitation": True,
        })
    return jsonify({"success": True, "data": data, "users": data,
                    "grantableRoles": grantable_roles(actor) if actor.role in USER_ADMIN_ROLES else []})


@app.route("/api/admin/users", methods=["POST"])
@auth_required(*USER_ADMIN_ROLES)
def admin_create_user(actor):
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    name = (data.get("name") or "").strip()
    role = data.get("role") or "branch_manager"
    if not email or "@" not in email:
        return err("A valid email is required", 400)
    if role not in grantable_roles(actor):
        return err(f"You can't invite someone as {role.replace('_', ' ')}", 403)
    if User.objects(email=email, password_hash__ne=None).first():
        return err("A user with this email already exists", 400)

    invite, link, emailed = issue_token(email, "invite", role, actor.organization, actor, name=name)
    log_action(actor, "invitation.create", "invitation", invite.id, f"email={email}, role={role}")
    return jsonify({
        "success": True,
        "message": "Invitation emailed" if emailed else "Invitation created - email not sent, share the link manually",
        "invitation": invite.to_dict(),
        "invitation_link": link,
        "emailed": emailed,
    }), 201


@app.route("/api/auth/resend-invitation", methods=["POST"])
@auth_required(*USER_ADMIN_ROLES)
def resend_invitation(actor):
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    if not email:
        return err("Email required", 400)
    if User.objects(email=email, password_hash__ne=None).first():
        return err("This user already has an account. Use password reset instead.", 400)
    qs = Invitation.objects(email=email, purpose="invite")
    if actor.role != "super_admin":
        qs = qs.filter(organization=actor.organization)
    last = qs.order_by("-created_at").first()
    if not last:
        return err("No invitation found for this email", 404)
    if last.role not in grantable_roles(actor):
        return err("Insufficient permissions", 403)
    invite, link, emailed = issue_token(email, "invite", last.role, last.organization, actor,
                                        name=last.name, branches=last.assigned_branches)
    log_action(actor, "invitation.resend", "invitation", invite.id, f"email={email}")
    return jsonify({"success": True, "invitation_link": link, "emailed": emailed,
                    "message": "Invitation re-sent" if emailed else "New link created - share it manually"})


@app.route("/api/admin/invitations/<path:email>", methods=["DELETE"])
@auth_required(*USER_ADMIN_ROLES)
def revoke_invitation(actor, email):
    email = email.strip().lower()
    qs = Invitation.objects(email=email, status="pending")
    if actor.role != "super_admin":
        qs = qs.filter(organization=actor.organization)
    invites = [i for i in qs if i.role in grantable_roles(actor)]
    if not invites:
        return err("No pending invitation found", 404)
    for i in invites:
        i.status = "revoked"
        i.save()
    log_action(actor, "invitation.revoke", "invitation", None, f"email={email}")
    return jsonify({"success": True, "message": "Invitation revoked"})


def _get_target(actor, email):
    target = User.objects(email=email.strip().lower()).first()
    if not target or (actor.role != "super_admin" and target.organization != actor.organization):
        return None, err("User not found", 404)
    if not can_manage(actor, target):
        return None, err("You can't manage this user", 403)
    return target, None


@app.route("/api/admin/users/<path:email>/toggle-status", methods=["POST"])
@auth_required(*USER_ADMIN_ROLES)
def admin_toggle_user(actor, email):
    target, e = _get_target(actor, email)
    if e:
        return e
    target.is_active = not target.is_active
    target.save()
    log_action(actor, "user.activate" if target.is_active else "user.deactivate", "user", target.id,
               f"email={target.email}")
    return jsonify({"success": True, "message": f"User {'activated' if target.is_active else 'deactivated'}"})


@app.route("/api/admin/users/<path:email>/reset-password", methods=["POST"])
@auth_required(*USER_ADMIN_ROLES)
def admin_reset_password(actor, email):
    target, e = _get_target(actor, email)
    if e:
        return e
    invite, link, emailed = issue_token(target.email, "reset", target.role, target.organization, actor,
                                        name=target.name)
    log_action(actor, "user.reset_link", "user", target.id, f"email={target.email}")
    return jsonify({"success": True, "invitation_link": link, "emailed": emailed,
                    "message": "Reset link emailed" if emailed else "Reset link created - share it manually"})


@app.route("/api/admin/users/<path:email>", methods=["DELETE"])
@auth_required(*USER_ADMIN_ROLES)
def admin_delete_user(actor, email):
    target, e = _get_target(actor, email)
    if e:
        return e
    target_email, target_id = target.email, target.id
    Invitation.objects(email=target_email, status="pending").update(set__status="revoked")
    target.delete()
    log_action(actor, "user.delete", "user", target_id, f"email={target_email}")
    return jsonify({"success": True, "message": "User removed"})


# ------------------------------------------------------------------
# OTP
# ------------------------------------------------------------------
def _otp_hash(phone, code):
    return hmac.new(JWT_SECRET.encode(), f"{phone}:{code}".encode(), hashlib.sha256).hexdigest()


@app.route("/api/otp/send", methods=["POST"])
@auth_required()
def otp_send(user):
    if not FEATURE_OTP:
        return err("Customer OTP verification is switched off", 404)
    data = request.get_json(silent=True) or {}
    phone = normalize_phone(data.get("phone"))
    if not phone:
        return err("Enter a valid phone number, e.g. 0712 345 678", 400)

    now = utcnow()
    recent = OtpCode.objects(phone=phone, created_at__gte=now - timedelta(seconds=OTP_RESEND_COOLDOWN_SECONDS)).first()
    if recent:
        wait = OTP_RESEND_COOLDOWN_SECONDS - int((now - recent.created_at).total_seconds())
        return err(f"Please wait {max(wait, 1)}s before sending another code", 429)
    hourly = OtpCode.objects(requested_by=user, created_at__gte=now - timedelta(hours=1)).count()
    if hourly >= 20:
        return err("Too many codes requested this hour", 429)

    if not sms_configured() and not OTP_DEV_MODE:
        return err("SMS is not configured on the server. Use the 'Cannot verify customer' reason instead.", 503)

    code = f"{secrets.randbelow(1_000_000):06d}"
    # Invalidate older unverified codes for this phone
    OtpCode.objects(phone=phone, verified=False).update(set__expires_at=now)
    OtpCode(
        phone=phone, code_hash=_otp_hash(phone, code), requested_by=user,
        organization=user.organization,
        expires_at=now + timedelta(minutes=OTP_TTL_MINUTES),
        purge_at=now + timedelta(days=2),
    ).save()

    resp = {"success": True, "phone": phone, "expiresInMinutes": OTP_TTL_MINUTES}
    if sms_configured():
        ok, detail = send_sms(phone, f"Your Jafari Credit verification code is {code}. "
                                     f"Share it only with the officer meeting you now. Valid {OTP_TTL_MINUTES} min.")
        if not ok:
            print(f"[OTP] SMS to {phone} failed: {detail}")
            if not OTP_DEV_MODE:
                return err(f"SMS could not be sent ({detail}). Try again or record an unverified reason.", 502)
        resp["message"] = f"Code sent to {phone}"
    else:
        resp["message"] = f"DEV MODE: SMS not sent to {phone}"
    if OTP_DEV_MODE and user.role in USER_ADMIN_ROLES:
        resp["devCode"] = code
    return jsonify(resp)


@app.route("/api/otp/verify", methods=["POST"])
@auth_required()
def otp_verify(user):
    if not FEATURE_OTP:
        return err("Customer OTP verification is switched off", 404)
    data = request.get_json(silent=True) or {}
    phone = normalize_phone(data.get("phone"))
    code = (data.get("code") or "").strip()
    if not phone or not code:
        return err("Phone and code required", 400)
    rec = OtpCode.objects(phone=phone, requested_by=user, verified=False).order_by("-created_at").first()
    if not rec:
        return err("No code was sent to this number. Send a new code.", 400)
    if utcnow() > rec.expires_at:
        return err("Code expired. Send a new one.", 400)
    if rec.attempts >= OTP_MAX_ATTEMPTS:
        return err("Too many wrong attempts. Send a new code.", 429)
    if not hmac.compare_digest(rec.code_hash, _otp_hash(phone, code)):
        rec.attempts += 1
        rec.save()
        left = OTP_MAX_ATTEMPTS - rec.attempts
        return err(f"Invalid code. {left} attempt{'s' if left != 1 else ''} left." if left else
                   "Too many wrong attempts. Send a new code.", 400)
    token = secrets.token_urlsafe(24)
    rec.verified = True
    rec.verified_at = utcnow()
    rec.token_hash = hash_token(token)
    rec.save()
    return jsonify({
        "success": True, "phone": phone,
        "verificationToken": token, "verifiedAt": iso(rec.verified_at),
    })


# ------------------------------------------------------------------
# REPORT PDF
# ------------------------------------------------------------------
def _decode_data_url(s, max_bytes=6 * 1024 * 1024):
    if not s or not isinstance(s, str) or not s.startswith("data:image/"):
        return None
    try:
        header, b64 = s.split(",", 1)
        raw = base64.b64decode(b64, validate=False)
        return raw if len(raw) <= max_bytes else None
    except Exception:
        return None


def _rl_image(data_url, max_w, max_h):
    raw = _decode_data_url(data_url)
    if not raw:
        return None
    try:
        reader = ImageReader(io.BytesIO(raw))
        iw, ih = reader.getSize()
        scale = min(max_w / iw, max_h / ih)
        return RLImage(io.BytesIO(raw), width=iw * scale, height=ih * scale)
    except Exception as e:
        print(f"[pdf] image failed: {e}")
        return None


def build_report_pdf(r):
    """r is a MeetingReport."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=36, rightMargin=36, topMargin=36, bottomMargin=36,
                            title=f"Customer Meeting Report {r.report_id}")
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("H1", parent=styles["Heading1"], fontSize=17, textColor=colors.HexColor("#123b72"),
                        spaceAfter=4)
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=11, textColor=colors.HexColor("#123b72"),
                        spaceBefore=6, spaceAfter=4)
    cell = ParagraphStyle("Cell", parent=styles["BodyText"], fontSize=8.5, leading=11)
    small = ParagraphStyle("Small", parent=styles["BodyText"], fontSize=7, leading=9,
                           textColor=colors.HexColor("#64748b"))
    width = A4[0] - 72

    def P(v, style=cell):
        text = "-" if v in (None, "") else str(v)
        return Paragraph(xml_escape(text).replace("\n", "<br/>"), style)

    el = []
    el.append(Paragraph("Jafari Credit - Customer Meeting Report", h1))
    level = (r.verification_level or "unverified").upper()
    level_color = {"FULL": "#065f46", "PARTIAL": "#92400e"}.get(level, "#991b1b")
    el.append(Paragraph(
        f"Report ID: <b>{xml_escape(r.report_id)}</b> &nbsp;|&nbsp; Generated: {xml_escape(iso(r.created_at) or '')} UTC"
        f" &nbsp;|&nbsp; Verification: <font color='{level_color}'><b>{level}</b></font>",
        cell))
    status = r.effective_status
    status_text = {
        "pending_signoff": f"<font color='#92400e'><b>DRAFT - awaiting sign-off by team leader "
                           f"{xml_escape(r.assigned_team_leader_name or '')}</b></font>",
        "returned": f"<font color='#991b1b'><b>RETURNED by {xml_escape(r.returned_by_name or 'team leader')}</b>: "
                    f"{xml_escape(r.return_reason or '')}</font>",
        "final": (f"<font color='#065f46'><b>FINAL - signed off by {xml_escape(r.tl_signed_by_name or '')}"
                  f" on {xml_escape(iso(r.tl_signed_at) or '')} UTC</b></font>" if r.tl_signed_at else
                  "<font color='#065f46'><b>FINAL</b></font>"),
    }[status]
    el.append(Paragraph("Status: " + status_text, cell))
    if r.voided:
        el.append(Paragraph(f"<font color='#991b1b'><b>VOIDED</b> {xml_escape(iso(r.voided_at) or '')} - "
                            f"{xml_escape(r.void_reason or '')}</font>", cell))
    el.append(Spacer(1, 8))

    def section(title, pairs):
        el.append(Paragraph(title, h2))
        rows = [[P(k), P(v)] for k, v in pairs]
        t = Table(rows, colWidths=[width * 0.3, width * 0.7])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        el.append(t)

    section("Field Officer", [
        ("Name", r.created_by),
        ("Role", OFFICER_ROLE_NAMES.get(r.user_role, r.user_role)),
        ("Agent Code", r.agent_code),
        ("Team Leader", r.assigned_team_leader_name or r.tl_signed_by_name),
        ("Account", f"{r.generated_by_name or ''} <{r.generated_by_email or ''}>"),
        ("Branch", BRANCH_NAMES.get(r.branch, r.branch)),
        ("Meeting date/time", r.meeting_datetime.replace("T", " ") if r.meeting_datetime else None),
        ("Meeting location", r.meeting_location),
        ("GPS", f"{r.gps_locator or '-'} (±{r.gps_accuracy or '?'} m)"),
    ])
    section("Customer", [
        ("Name", r.customer_name),
        ("Customer No", r.customer_id),
        ("ID No", r.customer_id_no),
        ("Phone", r.customer_phone),
        ("Email", r.customer_email),
        ("Employer Code", r.customer_employer),
        ("Address", r.customer_address),
        ("Status", r.customer_status),
        ("Sales Team Lead", r.customer_sales_lead),
    ])
    section("Loan & KYC", [
        ("Product", r.loan_product),
        ("Amount (KES)", f"{r.loan_amount:,.2f}" if r.loan_amount is not None else None),
        ("Meeting confirmed", "Yes" if r.meeting_confirmed == "yes" else "No"),
        ("KYC status", r.kyc_status),
        ("ID type", r.kyc_id_type),
        ("Date verified", r.kyc_date_verified),
        ("Verified by", r.kyc_verified_by),
    ])
    section("Discussion", [("Summary", r.discussion_summary)])
    # Older reports have no verification_checks recorded: they used all three checks.
    applied = (r.verification_checks or "customer_signature,otp,selfie").split(",")
    labels = {"customer_signature": "Customer signature", "otp": "SMS OTP", "selfie": "Selfie"}
    rows = [("Checks applied", ", ".join(labels.get(c, c) for c in applied))]
    rows.append(("Customer signature", f"Signed at {r.customer_signed_at or '-'}, GPS {r.customer_signed_gps or '-'}"
                 if r.customer_signature_image else "Not signed"))
    if "otp" in applied:
        rows.append(("SMS OTP", f"Verified - {r.otp_phone} at {iso(r.otp_verified_at)}" if r.otp_verified else "Not verified"))
        rows.append(("Unverified reason", r.unverified_reason))
    if "selfie" in applied:
        rows.append(("Selfie", f"Captured at {r.selfie_timestamp or '-'}, GPS {r.selfie_gps or '-'}" if r.selfie_image else "None"))
    section("Customer Verification", rows)

    if r.assigned_team_leader_email or r.tl_signed_at:
        approval = [("Assigned team leader", f"{r.assigned_team_leader_name or '-'} <{r.assigned_team_leader_email or '-'}>")]
        if r.tl_signed_at:
            approval += [("Signed off by", f"{r.tl_signed_by_name} <{r.tl_signed_by_email}>"),
                         ("Signed off at", f"{iso(r.tl_signed_at)} UTC"),
                         ("Sign-off GPS", r.tl_signed_gps),
                         ("Team leader comment", r.tl_comment)]
        elif status == "returned":
            approval += [("Returned at", f"{iso(r.returned_at)} UTC"), ("Reason", r.return_reason)]
        else:
            approval += [("Sign-off", "Pending")]
        section("Team Leader Sign-off", approval)

    # Signatures side by side
    sig_cells, sig_labels = [], []
    tl_label = "Team Leader" + (f" - {r.tl_signed_by_name}" if r.tl_signed_by_name else "")
    for label, img, confirmed in [
        (tl_label, r.team_leader_signature_image, r.team_leader_confirmed),
        ("Sales Agent", r.agent_signature_image, r.agent_confirmed),
        ("Customer", r.customer_signature_image, r.customer_confirmed),
    ]:
        im = _rl_image(img, width / 3 - 12, 70)
        sig_cells.append(im or P("Awaiting sign-off" if label.startswith("Team Leader") and status == "pending_signoff"
                                 else "Not signed"))
        sig_labels.append(P(f"{label}{' (confirmed)' if confirmed else ''}"))
    el.append(Paragraph("Signatures", h2))
    st = Table([sig_cells, sig_labels], colWidths=[width / 3] * 3, rowHeights=[80, None])
    st.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#f1f5f9")),
    ]))
    el.append(st)

    selfie = _rl_image(r.selfie_image, 220, 220)
    if selfie:
        el.append(Paragraph("Geotagged Selfie with Customer", h2))
        el.append(selfie)
        el.append(P(f"GPS {r.selfie_gps or '-'} | {r.selfie_timestamp or '-'}", small))

    el.append(Spacer(1, 12))
    el.append(Paragraph(
        f"Submission hash (SHA-256): {xml_escape(r.payload_hash or '')}<br/>"
        + (f"Final sign-off hash (SHA-256): {xml_escape(r.final_hash)}<br/>" if r.final_hash else "")
        + "These hashes are stored on the server. Any change to the recorded data produces a different hash.",
        small))

    watermark = {"pending_signoff": "DRAFT", "returned": "RETURNED"}.get(status)
    if r.voided:
        watermark = "VOID"

    def _decorate(canvas, _doc):
        if not watermark:
            return
        canvas.saveState()
        canvas.setFont("Helvetica-Bold", 90)
        canvas.setFillColor(colors.Color(0.8, 0.1, 0.1, alpha=0.12))
        canvas.translate(A4[0] / 2, A4[1] / 2)
        canvas.rotate(40)
        canvas.drawCentredString(0, -30, watermark)
        canvas.restoreState()

    doc.build(el, onFirstPage=_decorate, onLaterPages=_decorate)
    return buf.getvalue()


def new_report_id():
    for _ in range(10):
        rid = f"RPT-{utcnow().strftime('%Y%m%d')}-{secrets.token_hex(3).upper()}"
        if not MeetingReport.objects(report_id=rid).first():
            return rid
    raise RuntimeError("Could not allocate report id")


def report_scope(user):
    qs = MeetingReport.objects if user.role == "super_admin" else MeetingReport.objects(organization=user.organization)
    return qs


def can_read_report(user, report):
    if user.role == "super_admin":
        return True
    if report.organization != user.organization:
        return False
    return (user.role in AUDIT_VIEW_ROLES or report.generated_by == user
            or report.assigned_team_leader == user)


def _find_report(report_id):
    return MeetingReport.objects(report_id=report_id).first()


def _approver(user_id, org):
    try:
        tl = User.objects(id=user_id).first()
    except Exception:
        return None
    if not tl or not tl.is_active or not tl.password_hash or tl.role not in APPROVER_ROLES:
        return None
    if org is not None and tl.organization != org:
        return None
    return tl


# ------------------------------------------------------------------
# REPORT ENDPOINTS
# ------------------------------------------------------------------
@app.route("/api/generate", methods=["POST"])
@auth_required()
def generate_report(user):
    data = request.get_json(silent=True) or {}

    def s(k, limit=5000):
        v = data.get(k)
        return str(v).strip()[:limit] if v not in (None, "") else ""

    missing = [f for f in REPORT_REQUIRED if not s(f)]
    try:
        loan_amount = float(data.get("loan_amount"))
        if loan_amount <= 0:
            raise ValueError
    except (TypeError, ValueError):
        missing.append("loan_amount")
    if missing:
        return err("Please fill: " + ", ".join(m.replace("_", " ") for m in missing), 400, missing=missing)

    # ---- team leader who will sign off ----
    tl = _approver(s("team_leader_id", 64), user.organization)
    if not tl:
        return err("Choose the team leader who will sign off this report.", 400, missing=["team_leader_id"])
    if tl == user:
        return err("You can't sign off your own report - choose another team leader.", 400)

    # ---- server-side OTP check (only when the feature is on) ----
    otp_rec = None
    token = s("otp_verification_token", 200) if FEATURE_OTP else ""
    if token:
        otp_rec = OtpCode.objects(token_hash=hash_token(token), verified=True).first()
        if not otp_rec or otp_rec.requested_by != user:
            return err("OTP verification not recognised. Verify the customer again.", 400)
        if otp_rec.consumed:
            return err("This OTP verification was already used for another report. Verify again.", 400)
        if utcnow() - otp_rec.verified_at > timedelta(hours=OTP_TOKEN_VALID_HOURS):
            return err("OTP verification is too old. Verify the customer again.", 400)
        cust_phone = normalize_phone(s("customer_phone"))
        if cust_phone and cust_phone != otp_rec.phone:
            return err(f"The verified phone ({otp_rec.phone}) doesn't match the customer phone "
                       f"({cust_phone}).", 400)
    if FEATURE_OTP and not otp_rec and not s("unverified_reason"):
        return err("Verify the customer by OTP or give a reason why you can't.", 400)

    report = MeetingReport(
        report_id=new_report_id(),
        organization=user.organization,
        generated_by=user,
        generated_by_email=user.email,
        generated_by_name=user.name,
        loan_amount=loan_amount,
        team_leader_confirmed=bool(data.get("team_leader_confirmed")),
        agent_confirmed=bool(data.get("agent_confirmed")),
        customer_confirmed=bool(data.get("customer_confirmed")),
        ip_address=client_ip(),
    )
    for f in REPORT_TEXT_FIELDS:
        setattr(report, f, s(f))
    for f in REPORT_IMAGE_FIELDS:
        v = data.get(f) or ""
        setattr(report, f, v if _decode_data_url(v) else "")

    # The team leader signs later, on their own account.
    report.team_leader_signature_image = ""
    report.team_leader_confirmed = False
    report.status = "pending_signoff"
    report.assigned_team_leader = tl
    report.assigned_team_leader_name = tl.name
    report.assigned_team_leader_email = tl.email

    if not FEATURE_SELFIE:
        report.selfie_image = report.selfie_gps = report.selfie_timestamp = ""
    if not FEATURE_OTP:
        report.unverified_reason = ""

    if otp_rec:
        report.otp_verified = True
        report.otp_phone = otp_rec.phone
        report.otp_verified_at = otp_rec.verified_at
        if not report.customer_phone:
            report.customer_phone = otp_rec.phone
        report.unverified_reason = ""

    checks = active_checks()
    passed = {
        "customer_signature": bool(report.customer_signature_image),
        "otp": bool(report.otp_verified),
        "selfie": bool(report.selfie_image),
    }
    n_passed = sum(1 for c in checks if passed[c])
    report.verification_checks = ",".join(checks)
    if n_passed == len(checks):
        report.verification_level = "full"
    elif n_passed:
        report.verification_level = "partial"
    else:
        report.verification_level = "unverified"

    report.created_at = utcnow()
    report.payload_hash = report.compute_hash()

    try:
        pdf_bytes = build_report_pdf(report)
    except Exception as e:
        print(f"[generate] PDF build failed: {e}")
        return err(f"PDF build failed: {e}", 500)

    report.save()
    if otp_rec:
        otp_rec.consumed = True
        otp_rec.consumed_by_report = report.report_id
        otp_rec.save()
    log_action(user, "report.create", "report", report.report_id,
               f"customer={report.customer_name}, level={report.verification_level}, team_leader={tl.email}")

    return jsonify({
        "success": True,
        "status": report.status,
        "assigned_team_leader_name": tl.name,
        "report_id": report.report_id,
        "pdf": base64.b64encode(pdf_bytes).decode(),
        "filename": f"{report.report_id}.pdf",
        "verification_level": report.verification_level,
        "payload_hash": report.payload_hash,
        "created_at": iso(report.created_at),
    })


@app.route("/api/reports/<report_id>/pdf", methods=["GET"])
@auth_required()
def report_pdf(user, report_id):
    r = MeetingReport.objects(report_id=report_id).first()
    if not r or not can_read_report(user, r):
        return err("Report not found", 404)
    return jsonify({"success": True, "pdf": base64.b64encode(build_report_pdf(r)).decode(),
                    "filename": f"{r.report_id}.pdf"})


def _report_summary(r, with_images=False):
    d = {
        "report_id": r.report_id,
        "created_at": iso(r.created_at),
        "officer_name": r.created_by,
        "agent_code": r.agent_code,
        "generated_by_email": r.generated_by_email,
        "branch": BRANCH_NAMES.get(r.branch, r.branch),
        "meeting_datetime": r.meeting_datetime,
        "meeting_location": r.meeting_location,
        "customer_name": r.customer_name,
        "customer_no": r.customer_id,
        "customer_id_no": r.customer_id_no,
        "customer_phone": r.customer_phone,
        "loan_product": r.loan_product,
        "loan_amount": r.loan_amount,
        "kyc_status": r.kyc_status,
        "kyc_verified_by": r.kyc_verified_by,
        "meeting_confirmed": r.meeting_confirmed,
        "discussion_summary": r.discussion_summary,
        "gps": r.gps_locator,
        "verification_level": r.verification_level,
        "voided": bool(r.voided),
        **r.workflow_dict(),
    }
    if with_images:
        d["customer_signature_image"] = r.customer_signature_image or ""
        d["agent_signature_image"] = r.agent_signature_image or ""
        d["customer_signed_at"] = r.customer_signed_at
    return d


@app.route("/api/team-leaders", methods=["GET"])
@auth_required()
def list_team_leaders(user):
    qs = User.objects(organization=user.organization, role__in=list(APPROVER_ROLES), is_active=True,
                      password_hash__ne=None).order_by("name")
    return jsonify({"success": True, "data": [
        {"id": str(u.id), "name": u.name, "email": u.email, "role": u.role}
        for u in qs if u.id != user.id
    ]})


@app.route("/api/reports/mine", methods=["GET"])
@auth_required()
def my_reports(user):
    qs = MeetingReport.objects(generated_by=user, voided__ne=True).exclude(*REPORT_IMAGE_FIELDS)\
        .order_by("-created_at").limit(int_arg("limit", 100))
    return jsonify({"success": True, "data": [_report_summary(r) for r in qs]})


@app.route("/api/reports/awaiting", methods=["GET"])
@auth_required()
def reports_awaiting_me(user):
    qs = MeetingReport.objects(assigned_team_leader=user, status="pending_signoff", voided__ne=True)\
        .exclude(*REPORT_IMAGE_FIELDS).order_by("created_at").limit(int_arg("limit", 200))
    data = [_report_summary(r) for r in qs]
    return jsonify({"success": True, "data": data, "count": len(data)})


@app.route("/api/reports/<report_id>", methods=["GET"])
@auth_required()
def report_detail(user, report_id):
    r = _find_report(report_id)
    if not r or not can_read_report(user, r):
        return err("Report not found", 404)
    return jsonify({"success": True, "report": _report_summary(r, with_images=True)})


@app.route("/api/reports/<report_id>/signoff", methods=["POST"])
@auth_required()
def report_signoff(user, report_id):
    r = _find_report(report_id)
    if not r or not can_read_report(user, r):
        return err("Report not found", 404)
    if r.voided:
        return err("This report has been voided", 400)
    if r.effective_status != "pending_signoff":
        return err(f"This report is already {r.effective_status.replace('_', ' ')}", 400)
    if r.assigned_team_leader != user:
        return err("Only the assigned team leader can sign off this report", 403)
    data = request.get_json(silent=True) or {}
    sig = data.get("signature_image") or ""
    if not _decode_data_url(sig):
        return err("Please sign in the signature box", 400)
    if not data.get("confirm"):
        return err("Please confirm you have reviewed the report", 400)
    r.team_leader_signature_image = sig
    r.team_leader_confirmed = True
    r.tl_signed_by = user
    r.tl_signed_by_name = user.name
    r.tl_signed_by_email = user.email
    r.tl_signed_at = utcnow()
    r.tl_signed_gps = str(data.get("gps") or "")[:100]
    r.tl_comment = str(data.get("comment") or "").strip()[:1000]
    r.status = "final"
    r.final_hash = r.compute_final_hash()
    r.save()
    log_action(user, "report.signoff", "report", r.report_id, f"agent={r.generated_by_email}")
    return jsonify({"success": True, "report": _report_summary(r),
                    "pdf": base64.b64encode(build_report_pdf(r)).decode(), "filename": f"{r.report_id}.pdf"})


@app.route("/api/reports/<report_id>/return", methods=["POST"])
@auth_required()
def report_return(user, report_id):
    r = _find_report(report_id)
    if not r or not can_read_report(user, r):
        return err("Report not found", 404)
    if r.effective_status != "pending_signoff" or r.voided:
        return err("Only reports awaiting sign-off can be returned", 400)
    if r.assigned_team_leader != user:
        return err("Only the assigned team leader can return this report", 403)
    reason = str((request.get_json(silent=True) or {}).get("reason") or "").strip()
    if not reason:
        return err("Please give a reason so the agent knows what to fix", 400)
    r.status = "returned"
    r.returned_by_name = user.name
    r.returned_at = utcnow()
    r.return_reason = reason[:1000]
    r.save()
    log_action(user, "report.return", "report", r.report_id, reason[:500])
    return jsonify({"success": True, "report": _report_summary(r)})


@app.route("/api/reports/<report_id>/reassign", methods=["POST"])
@auth_required()
def report_reassign(user, report_id):
    r = _find_report(report_id)
    if not r or not can_read_report(user, r):
        return err("Report not found", 404)
    if r.effective_status != "pending_signoff" or r.voided:
        return err("Only reports awaiting sign-off can be reassigned", 400)
    if not (r.generated_by == user or user.role in USER_ADMIN_ROLES):
        return err("Only the agent who created it or an admin can reassign it", 403)
    tl = _approver((request.get_json(silent=True) or {}).get("team_leader_id"), r.organization)
    if not tl:
        return err("Choose a valid team leader", 400)
    if tl == r.generated_by:
        return err("The agent can't sign off their own report", 400)
    old = r.assigned_team_leader_email
    r.assigned_team_leader = tl
    r.assigned_team_leader_name = tl.name
    r.assigned_team_leader_email = tl.email
    r.save()
    log_action(user, "report.reassign", "report", r.report_id, f"{old} -> {tl.email}")
    return jsonify({"success": True, "report": _report_summary(r)})


@app.route("/api/generate-batch", methods=["POST"])
@auth_required()
def generate_batch(user):
    data = request.get_json(silent=True) or {}
    ids = [str(i) for i in (data.get("report_ids") or [])][:50]
    if not ids:
        return err("No reports selected", 400)
    reports = [r for r in MeetingReport.objects(report_id__in=ids) if can_read_report(user, r)]
    if not reports:
        return err("No matching reports", 404)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for r in reports:
            zf.writestr(f"{r.report_id}.pdf", build_report_pdf(r))
    return jsonify({
        "success": True,
        "zip": base64.b64encode(buf.getvalue()).decode(),
        "filename": f"reports-{utcnow().strftime('%Y%m%d-%H%M%S')}.zip",
        "count": len(reports),
    })


# ------------------------------------------------------------------
# REPORT AUDIT LOG (meeting reports)
# ------------------------------------------------------------------
def _filtered_reports(user):
    qs = report_scope(user).filter(voided__ne=True)
    if request.args.get("include_voided") == "1":
        qs = report_scope(user)
    user_email = (request.args.get("user_email") or "").strip().lower()
    if user_email:
        qs = qs.filter(generated_by_email__icontains=user_email)
    customer = (request.args.get("customer") or "").strip()
    if customer:
        qs = qs.filter(Q(customer_name__icontains=customer) | Q(customer_id__icontains=customer) |
                       Q(report_id__icontains=customer) | Q(customer_id_no__icontains=customer))
    d = parse_date(request.args.get("start_date"))
    if d:
        qs = qs.filter(created_at__gte=d - timedelta(hours=3))  # dates are picked in EAT (UTC+3)
    d = parse_date(request.args.get("end_date"))
    if d:
        qs = qs.filter(created_at__lt=d + timedelta(days=1) - timedelta(hours=3))  # inclusive end day
    level = request.args.get("level")
    if level in ("full", "partial", "unverified"):
        qs = qs.filter(verification_level=level)
    status = request.args.get("status")
    if status == "final":
        qs = qs.filter(Q(status="final") | Q(status__exists=False) | Q(status=None))
    elif status in REPORT_STATUSES:
        qs = qs.filter(status=status)
    return qs.order_by("-created_at")


@app.route("/api/admin/audit-log", methods=["GET"])
@auth_required(*AUDIT_VIEW_ROLES)
def admin_audit_log(user):
    qs = _filtered_reports(user).exclude(*REPORT_IMAGE_FIELDS).limit(int_arg("limit", 500))
    data = [r.to_audit_dict() for r in qs]
    # has_* flags need the images; fetch cheaply via only() on a second query
    flags = {r.report_id: r for r in _filtered_reports(user).only("report_id", *REPORT_IMAGE_FIELDS)
             .limit(int_arg("limit", 500))}
    for d in data:
        r = flags.get(d["report_id"])
        if r:
            d["has_team_leader_sig"] = bool(r.team_leader_signature_image)
            d["has_agent_sig"] = bool(r.agent_signature_image)
            d["has_customer_sig"] = bool(r.customer_signature_image)
            d["has_selfie"] = bool(r.selfie_image)
    return jsonify({"success": True, "data": data, "logs": data, "count": len(data)})


@app.route("/api/admin/audit-log/<entry_id>", methods=["DELETE"])
@auth_required("super_admin")
def admin_void_report(user, entry_id):
    """Reports are never deleted - they are voided with a reason and stay in the record."""
    data = request.get_json(silent=True) or {}
    reason = (data.get("reason") or "").strip()
    if not reason:
        return err("A reason is required to void a report", 400)
    r = MeetingReport.objects(Q(report_id=entry_id)).first()
    if not r:
        try:
            r = MeetingReport.objects(id=entry_id).first()
        except Exception:
            r = None
    if not r:
        return err("Report not found", 404)
    r.voided = True
    r.voided_by = user
    r.voided_at = utcnow()
    r.void_reason = reason[:500]
    r.save()
    log_action(user, "report.void", "report", r.report_id, reason[:500])
    return jsonify({"success": True, "message": "Report voided"})


@app.route("/api/admin/audit-log/export", methods=["GET"])
@auth_required(*AUDIT_VIEW_ROLES)
def admin_export_audit(user):
    qs = _filtered_reports(user).exclude(*REPORT_IMAGE_FIELDS)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Created (UTC)", "Report ID", "Officer", "Account Email", "Agent Code", "Branch",
                "Customer", "Customer No", "Customer Phone", "Loan Product", "Loan Amount",
                "Verification", "OTP Verified", "OTP Phone", "Unverified Reason", "GPS", "Payload Hash",
                "Status", "Assigned Team Leader", "Signed Off By", "Signed Off (UTC)", "Return Reason", "Final Hash"])
    count = 0
    for r in qs:
        w.writerow([
            iso(r.created_at), r.report_id, r.created_by, r.generated_by_email, r.agent_code,
            BRANCH_NAMES.get(r.branch, r.branch), r.customer_name, r.customer_id, r.customer_phone,
            r.loan_product, r.loan_amount, r.verification_level, "yes" if r.otp_verified else "no",
            r.otp_phone or "", r.unverified_reason or "", r.gps_locator or "", r.payload_hash,
            r.effective_status, r.assigned_team_leader_email or "", r.tl_signed_by_email or "",
            iso(r.tl_signed_at) or "", r.return_reason or "", r.final_hash or "",
        ])
        count += 1
    return jsonify({
        "success": True,
        "csv": base64.b64encode(buf.getvalue().encode("utf-8-sig")).decode(),
        "filename": f"meeting-reports-{utcnow().strftime('%Y%m%d-%H%M%S')}.csv",
        "count": count,
    })


# System event log (logins, invites, user changes)
@app.route("/api/audit", methods=["GET"])
@auth_required(*AUDIT_VIEW_ROLES)
def list_audit(user):
    qs = AuditLog.objects if user.role == "super_admin" else AuditLog.objects(organization=user.organization)
    logs = qs.order_by("-created_at").limit(int_arg("limit", 100))
    return jsonify({"success": True, "logs": [l.to_dict() for l in logs]})


# ------------------------------------------------------------------
# BRANCHES / DASHBOARD (loan registry)
# ------------------------------------------------------------------
@app.route("/api/branches", methods=["GET"])
@auth_required()
def list_branches(user):
    if user.role == "super_admin":
        branches = Branch.objects(is_active=True).order_by("name")
    else:
        branches = Branch.objects(organization=user.organization, is_active=True).order_by("name")
    return jsonify({"success": True, "branches": [b.to_dict() for b in branches]})


@app.route("/api/dashboard/stats", methods=["GET"])
@auth_required()
def dashboard_stats(user):
    qs = Loan.objects() if user.role == "super_admin" else Loan.objects(organization=user.organization)
    branch_id = request.args.get("branchId")
    if branch_id:
        try:
            qs = qs.filter(branch=Branch.objects.get(id=branch_id))
        except Exception:
            pass
    totals = {"totalLoans": 0, "totalDisbursed": 0, "totalOutstanding": 0, "totalCollected": 0}
    status_stats, branch_stats, type_stats = {}, {}, {}
    for loan in qs:
        totals["totalLoans"] += 1
        totals["totalDisbursed"] += loan.principal_amount
        totals["totalOutstanding"] += loan.outstanding_balance
        totals["totalCollected"] += loan.amount_paid
        s = status_stats.setdefault(loan.status, {"_id": loan.status, "count": 0, "amount": 0})
        s["count"] += 1
        s["amount"] += loan.principal_amount
        if loan.branch:
            b = branch_stats.setdefault(str(loan.branch.id), {
                "branchName": loan.branch.name, "branchCode": loan.branch.code,
                "count": 0, "totalDisbursed": 0, "totalOutstanding": 0, "totalCollected": 0,
            })
            b["count"] += 1
            b["totalDisbursed"] += loan.principal_amount
            b["totalOutstanding"] += loan.outstanding_balance
            b["totalCollected"] += loan.amount_paid
        t = type_stats.setdefault(loan.loan_type, {"_id": loan.loan_type, "count": 0, "amount": 0})
        t["count"] += 1
        t["amount"] += loan.principal_amount
    return jsonify({
        "success": True,
        "totals": totals,
        "statusStats": list(status_stats.values()),
        "branchStats": list(branch_stats.values()),
        "typeStats": list(type_stats.values()),
    })


@app.route("/api/dashboard/recent-loans", methods=["GET"])
@auth_required()
def recent_loans(user):
    qs = Loan.objects() if user.role == "super_admin" else Loan.objects(organization=user.organization)
    loans = qs.order_by("-created_at").limit(10)
    return jsonify({"success": True, "loans": [l.to_dict() for l in loans]})


# ------------------------------------------------------------------
# FRONTEND (optional): if ./static/index.html exists, serve it from this app
# so invite links work on the same domain with no extra hosting.
# ------------------------------------------------------------------
def _frontend_available():
    return os.path.isfile(os.path.join(STATIC_DIR, "index.html"))


@app.route("/", methods=["GET"])
def frontend_index():
    if _frontend_available():
        resp = send_from_directory(STATIC_DIR, "index.html")
        resp.headers["Cache-Control"] = "no-cache"
        return resp
    return jsonify({"success": True, "message": "Jafari Meeting Report API. See /api/health."})


@app.route("/accept-invite/<path:token>", methods=["GET"])
def accept_invite_redirect(token):
    # Older links used this path form; normalise to the query-string form.
    return redirect(f"/?invite={urllib.parse.quote(token)}", code=302)


# ------------------------------------------------------------------
# ERROR HANDLERS
# ------------------------------------------------------------------
@app.errorhandler(404)
def not_found(e):
    return err("Not found", 404)


@app.errorhandler(405)
def method_not_allowed(e):
    return err("Method not allowed", 405)


@app.errorhandler(413)
def too_large(e):
    return err("Request too large. Retake the selfie or clear and redo the signatures.", 413)


@app.errorhandler(500)
def server_error(e):
    return err("Internal server error", 500)


@jwt.unauthorized_loader
def missing_token(reason):
    return err("Authentication required", 401)


@jwt.invalid_token_loader
def invalid_token(reason):
    return err("Invalid token", 401)


@jwt.expired_token_loader
def expired_token(jwt_header, jwt_payload):
    return err("Session expired", 401)


# ------------------------------------------------------------------
# BOOTSTRAP (runs on import - covers gunicorn)
# ------------------------------------------------------------------
def ensure_super_admin():
    """
    Makes sure SUPER_ADMIN_EMAIL exists and is an active super admin.

    - New account: created with SUPER_ADMIN_PASSWORD and flagged so the first
      sign-in must choose a new password (so a simple starter password such as
      admin123 is only ever usable once).
    - Existing account: promoted to super_admin if needed. Its password is
      never overwritten unless it has none yet.
    """
    org = Organization.objects(registration_number=SUPER_ADMIN_ORG_REG).first()
    if not org:
        org = Organization(
            name=SUPER_ADMIN_ORG,
            registration_number=SUPER_ADMIN_ORG_REG,
            address="Nairobi, Kenya",
            is_active=True,
        ).save()
        print(f"[BOOT] Created organization: {org.name}")

    # Older versions of this app created admins with default passwords and reset them on
    # every boot. Any admin still using one must choose a new password at next sign-in.
    known_defaults = {"admin123", "password", "password123", "changeme"}
    if SUPER_ADMIN_PASSWORD and len(SUPER_ADMIN_PASSWORD) < 12:
        known_defaults.add(SUPER_ADMIN_PASSWORD)
    for admin in User.objects(role__in=["super_admin", "admin_agent"], must_change_password__ne=True):
        if admin.password_hash and any(admin.check_password(pw) for pw in known_defaults):
            admin.must_change_password = True
            admin.save()
            print(f"[BOOT] {admin.email} is on a default password - must change it at next sign-in")

    if not SUPER_ADMIN_EMAIL:
        return
    user = User.objects(email=SUPER_ADMIN_EMAIL).first()
    if user:
        changed = []
        if user.role != "super_admin":
            user.role = "super_admin"
            changed.append("role -> super_admin")
        if not user.is_active:
            user.is_active = True
            changed.append("activated")
        if not user.password_hash and SUPER_ADMIN_PASSWORD:
            user.set_password(SUPER_ADMIN_PASSWORD)
            user.must_change_password = True
            changed.append("starter password set")
        elif (SUPER_ADMIN_PASSWORD and len(SUPER_ADMIN_PASSWORD) < 12 and not user.must_change_password
              and user.check_password(SUPER_ADMIN_PASSWORD)):
            # Still using the (weak) starter password from the environment - require a change.
            user.must_change_password = True
            changed.append("must change starter password")
        if changed:
            user.save()
            print(f"[BOOT] Super admin {user.email}: {', '.join(changed)}")
        return
    if len(SUPER_ADMIN_PASSWORD) < 6:
        print("[BOOT] SUPER_ADMIN_PASSWORD missing - super admin NOT created")
        return
    user = User(name=SUPER_ADMIN_NAME, email=SUPER_ADMIN_EMAIL, role="super_admin",
                organization=org, is_active=True, must_change_password=True)
    user.set_password(SUPER_ADMIN_PASSWORD)
    user.save()
    print(f"[BOOT] Super admin created: {user.email} (must set a new password at first sign-in)")


try:
    ensure_super_admin()
except Exception as e:
    print(f"[BOOT] ensure_super_admin failed: {e}")

if not env_bool("USE_MONGOMOCK"):
    # The bootstrap query opened a connection in the parent process; drop it so each
    # forked worker opens its own (PyMongo clients are not fork-safe).
    from mongoengine.connection import disconnect
    disconnect()
    _connect_db()

print(f"[BOOT] FRONTEND_URL = {FRONTEND_URL} | CORS = {CORS_ORIGINS} | "
      f"OTP = {'on' if FEATURE_OTP else 'off'} | SELFIE = {'on' if FEATURE_SELFIE else 'off'} | "
      f"SMS = {'on' if sms_configured() else 'off'} | OTP_DEV_MODE = {OTP_DEV_MODE}")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=False)
