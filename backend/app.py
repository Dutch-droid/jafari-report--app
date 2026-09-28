"""
Loan Registry / Customer Meeting Report - Flask Backend (Extended)
Features:
  - Organizations, branches, users, invitations
  - Loans CRUD, payments, status changes
  - CSV export, PDF statements, CSV bulk import
  - Audit log with customer signature, selfie, and OTP verification
  - Africa's Talking SMS for OTP
  - SHA-256 report hash for tamper detection
  - Role-based access (super_admin, admin_agent, branch_manager, auditor)
"""

import os
import io
import csv
import math
import json
import hashlib
import secrets
import warnings
from datetime import datetime, timedelta, timezone
from functools import wraps

import requests
from dotenv import load_dotenv
from flask import (
    Flask, jsonify, request, send_file, Response, make_response
)
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token, get_jwt_identity, jwt_required,
    verify_jwt_in_request
)
from flask_mail import Mail, Message
from mongoengine import (
    Document, StringField, EmailField, BooleanField, DateTimeField,
    ReferenceField, ListField, EmbeddedDocumentField, EmbeddedDocument,
    FloatField, IntField, CASCADE, NULLIFY, connect, Q
)
from reportlab.lib.pagesizes import LETTER
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
)
import bcrypt

warnings.filterwarnings("ignore", category=DeprecationWarning)

# ------------------------------------------------------------------
# CONFIG
# ------------------------------------------------------------------
load_dotenv()

MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017/loan-registry")
JWT_SECRET = os.getenv("JWT_SECRET_KEY", "change-me")
PORT = int(os.getenv("PORT", 5000))
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")

# Africa's Talking - key must come from .env
AT_API_KEY = (os.getenv("AT_API_KEY") or "").strip()
AT_USERNAME = (os.getenv("AT_USERNAME") or "sandbox").strip()
AT_BASE_URL = (os.getenv("AT_BASE_URL") or "https://api.sandbox.africastalking.com").rstrip("/")
AT_SENDER_ID = (os.getenv("AT_SENDER_ID") or "").strip()

OTP_EXPIRY_MINUTES = int(os.getenv("OTP_EXPIRY_MINUTES", "10"))
OTP_LENGTH = int(os.getenv("OTP_LENGTH", "6"))
GEO_MAX_DISTANCE_METERS = int(os.getenv("GEO_MAX_DISTANCE_METERS", "500"))

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = JWT_SECRET
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=7)
app.config["MAIL_SERVER"] = os.getenv("MAIL_SERVER", "")
app.config["MAIL_PORT"] = int(os.getenv("MAIL_PORT", 587))
app.config["MAIL_USE_TLS"] = os.getenv("MAIL_USE_TLS", "true").lower() == "true"
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME", "")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD", "")
app.config["MAIL_DEFAULT_SENDER"] = os.getenv("MAIL_DEFAULT_SENDER", "noreply@loanregistry.local")

CORS(app, resources={r"/api/*": {"origins": "*"}})


@app.before_request
def handle_preflight():
    """Ensure CORS preflight requests are answered before any auth check."""
    if request.method == "OPTIONS":
        response = make_response()
        response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add("Access-Control-Allow-Headers",
                             "Content-Type, Authorization, Accept, X-Requested-With")
        response.headers.add("Access-Control-Allow-Methods",
                             "GET, POST, PUT, DELETE, OPTIONS, PATCH")
        return response


jwt = JWTManager(app)
mail = Mail(app)
connect(host=MONGODB_URI)


def utcnow():
    """Naive UTC - matches what MongoDB round-trips back."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def iso_utc(dt):
    """ISO 8601 string with explicit Z suffix so browsers parse as UTC."""
    if not dt:
        return None
    if dt.tzinfo is None:
        return dt.isoformat() + "Z"
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


# ------------------------------------------------------------------
# HELPERS - GEO, HASH, OTP
# ------------------------------------------------------------------
def haversine_meters(lat1, lon1, lat2, lon2):
    """Distance between two GPS points in meters."""
    R = 6371000.0
    d_lat = math.radians(lat2 - lat1)
    d_lon = math.radians(lon2 - lon1)
    a = (math.sin(d_lat / 2) ** 2 +
         math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) *
         math.sin(d_lon / 2) ** 2)
    return 2 * R * math.asin(math.sqrt(a))


def parse_gps(value):
    """Accept 'lat, lng' string, return (lat, lng) or None."""
    if not value or not isinstance(value, str):
        return None
    try:
        parts = [float(x.strip()) for x in value.split(",")]
        if len(parts) != 2:
            return None
        return parts[0], parts[1]
    except (ValueError, AttributeError):
        return None


def sha256_hex(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def canonicalize(obj):
    """Deterministic JSON serialization for stable hashing."""
    if obj is None:
        return "null"
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, (int, float)):
        return json.dumps(obj)
    if isinstance(obj, str):
        return json.dumps(obj, ensure_ascii=False)
    if isinstance(obj, list):
        return "[" + ",".join(canonicalize(x) for x in obj) + "]"
    if isinstance(obj, dict):
        keys = sorted(obj.keys())
        return "{" + ",".join(json.dumps(k) + ":" + canonicalize(obj[k]) for k in keys) + "}"
    return json.dumps(str(obj))


def compute_report_hash(payload):
    """SHA-256 of the canonical report payload."""
    fields = {
        "report_id": payload.get("report_id"),
        "created_by": payload.get("created_by"),
        "customer_name": payload.get("customer_name"),
        "customer_no": payload.get("customer_id"),
        "customer_id_no": payload.get("customer_id_no"),
        "customer_phone": payload.get("customer_phone"),
        "loan_product": payload.get("loan_product"),
        "loan_amount": payload.get("loan_amount"),
        "branch": payload.get("branch"),
        "kyc_status": payload.get("kyc_status"),
        "agent_code": payload.get("agent_code"),
        "officer_gps": payload.get("gps_locator"),
        "customer_signed_gps": payload.get("customer_signed_gps"),
        "selfie_gps": payload.get("selfie_gps"),
        "has_team_leader_sig": bool(payload.get("team_leader_signature_image")),
        "has_agent_sig": bool(payload.get("agent_signature_image")),
        "has_customer_sig": bool(payload.get("customer_signature_image")),
        "has_selfie": bool(payload.get("selfie_image")),
        "otp_verified": bool(payload.get("otp_verified")),
        "otp_verified_at": payload.get("otp_verified_at"),
        "meeting_datetime": payload.get("meeting_datetime"),
    }
    return sha256_hex(canonicalize(fields))


def compute_verification_level(payload):
    """Returns 'full' | 'partial' | 'unverified'."""
    has_customer_sig = bool(payload.get("customer_signature_image"))
    has_selfie = bool(payload.get("selfie_image"))
    otp_ok = bool(payload.get("otp_verified"))
    officer_gps = parse_gps(payload.get("gps_locator"))
    selfie_gps = parse_gps(payload.get("selfie_gps"))

    if otp_ok and (has_customer_sig or has_selfie) and officer_gps:
        if selfie_gps and officer_gps:
            d = haversine_meters(officer_gps[0], officer_gps[1], selfie_gps[0], selfie_gps[1])
            if d > GEO_MAX_DISTANCE_METERS:
                return "partial"
        return "full"

    evidence_count = sum([bool(otp_ok), has_customer_sig, has_selfie, bool(officer_gps)])
    if evidence_count >= 2:
        return "partial"
    return "unverified"


def send_sms(to_phone, message):
    """Send an SMS via Africa's Talking. Returns (ok: bool, error: str | None)."""
    if not AT_API_KEY:
        return False, "AT_API_KEY not configured"

    phone = (to_phone or "").strip().replace(" ", "").replace("-", "")
    if not phone.startswith("+"):
        if phone.startswith("0"):
            phone = "+254" + phone[1:]
        elif phone.startswith("254"):
            phone = "+" + phone
        else:
            phone = "+" + phone

    payload = {
        "username": AT_USERNAME,
        "to": phone,
        "message": message,
    }
    if AT_SENDER_ID:
        payload["from"] = AT_SENDER_ID

    try:
        resp = requests.post(
            f"{AT_BASE_URL}/version1/messaging",
            data=payload,
            headers={
                "apiKey": AT_API_KEY,
                "Accept": "application/json",
            },
            timeout=20,
        )
        if resp.status_code >= 400:
            return False, f"AT HTTP {resp.status_code}: {resp.text[:200]}"

        data = resp.json()
        recipients = (data.get("SMSMessageData") or {}).get("Recipients") or []
        if recipients and recipients[0].get("status") == "Success":
            return True, None
        return False, (recipients[0].get("status") if recipients else resp.text[:200])
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


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
            "licenseNumber": self.license_number,
            "address": self.address,
            "contactEmail": self.contact_email,
            "contactPhone": self.contact_phone,
            "isActive": self.is_active,
            "createdAt": iso_utc(self.created_at),
            "updatedAt": iso_utc(self.updated_at),
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
    role = StringField(
        choices=["super_admin", "admin_agent", "branch_manager", "auditor"],
        default="admin_agent"
    )
    organization = ReferenceField(Organization, required=True, reverse_delete_rule=CASCADE)
    assigned_branches = ListField(ReferenceField(Branch))
    is_active = BooleanField(default=True)
    last_login = DateTimeField()
    created_at = DateTimeField(default=utcnow)

    meta = {"collection": "users"}

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
        return {
            "id": str(self.id),
            "name": self.name,
            "email": self.email,
            "role": self.role,
            "is_admin": self.role in ("super_admin", "admin_agent"),
            "organization": self.organization.to_dict() if self.organization else None,
            "assignedBranches": [str(b.id) for b in self.assigned_branches],
            "isActive": self.is_active,
            "hasPassword": bool(self.password_hash),
            "lastLogin": iso_utc(self.last_login),
            "createdAt": iso_utc(self.created_at),
        }


class Invitation(Document):
    email = EmailField(required=True)
    token = StringField(required=True, unique=True)
    role = StringField(
        choices=["super_admin", "admin_agent", "branch_manager", "auditor"],
        default="admin_agent"
    )
    organization = ReferenceField(Organization, required=True, reverse_delete_rule=CASCADE)
    invited_by = ReferenceField(User, reverse_delete_rule=NULLIFY)
    assigned_branches = ListField(ReferenceField(Branch))
    status = StringField(
        choices=["pending", "accepted", "revoked", "expired"],
        default="pending"
    )
    expires_at = DateTimeField(required=True)
    accepted_at = DateTimeField()
    created_at = DateTimeField(default=utcnow)

    meta = {"collection": "invitations"}

    def is_valid(self):
        if self.status != "pending":
            return False
        if not self.expires_at:
            return False
        exp = self.expires_at
        now = utcnow()
        if exp.tzinfo is not None:
            exp = exp.astimezone(timezone.utc).replace(tzinfo=None)
        if now.tzinfo is not None:
            now = now.astimezone(timezone.utc).replace(tzinfo=None)
        return exp > now

    def to_dict(self):
        return {
            "_id": str(self.id),
            "email": self.email,
            "role": self.role,
            "status": self.status,
            "expiresAt": iso_utc(self.expires_at),
            "acceptedAt": iso_utc(self.accepted_at),
            "createdAt": iso_utc(self.created_at),
            "invitedBy": self.invited_by.name if self.invited_by else None,
        }


class CustomerOtp(Document):
    """One-time password records for customer phone verification."""
    phone = StringField(required=True, index=True)
    code_hash = StringField(required=True)
    salt = StringField(required=True)
    attempts = IntField(default=0)
    verified = BooleanField(default=False)
    verified_at = DateTimeField()
    verified_token = StringField()
    verified_token_expires_at = DateTimeField()
    created_at = DateTimeField(default=utcnow)
    expires_at = DateTimeField(required=True)

    meta = {"collection": "customer_otps"}

    def is_expired(self):
        exp = self.expires_at
        now = utcnow()
        if exp.tzinfo is not None:
            exp = exp.astimezone(timezone.utc).replace(tzinfo=None)
        return exp < now

    def check_code(self, code):
        return sha256_hex(code + self.salt) == self.code_hash


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
        required=True
    )
    principal_amount = FloatField(required=True)
    interest_rate = FloatField(required=True)
    term_months = IntField(required=True)
    total_repayable = FloatField(default=0)
    amount_paid = FloatField(default=0)
    outstanding_balance = FloatField(default=0)
    currency = StringField(default="USD")
    status = StringField(
        choices=["pending", "approved", "active", "disbursed", "repaying",
                 "completed", "defaulted", "rejected", "written_off"],
        default="pending"
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
            "nextPaymentDate": iso_utc(self.next_payment_date),
            "createdAt": iso_utc(self.created_at),
            "updatedAt": iso_utc(self.updated_at),
        }


class AuditLog(Document):
    organization = ReferenceField(Organization, required=True, reverse_delete_rule=CASCADE)
    user = ReferenceField(User, reverse_delete_rule=NULLIFY)

    # Core report
    report_id = StringField()
    customer_name = StringField()
    customer_no = StringField()
    customer_id_no = StringField()
    customer_phone = StringField()
    loan_product = StringField()
    loan_amount = StringField()
    branch = StringField()
    kyc_status = StringField()
    agent_code = StringField()
    filename = StringField()
    meeting_confirmed = StringField()

    # NEW: meeting summary captured for the audit log
    discussion_summary = StringField()
    meeting_location = StringField()
    meeting_datetime = StringField()
    officer_name = StringField()
    officer_role = StringField()

    # GPS captures
    officer_gps = StringField()
    officer_gps_at_signature = StringField()
    customer_signed_gps = StringField()
    selfie_gps = StringField()

    # Signatures
    has_team_leader_sig = BooleanField(default=False)
    has_agent_sig = BooleanField(default=False)
    has_customer_sig = BooleanField(default=False)
    customer_signed_at = DateTimeField()

    # Selfie
    has_selfie = BooleanField(default=False)
    selfie_timestamp = DateTimeField()
    selfie_image_hash = StringField()

    # OTP
    otp_verified = BooleanField(default=False)
    otp_verified_at = DateTimeField()
    otp_phone = StringField()

    # Verification meta
    verification_level = StringField(
        choices=["full", "partial", "unverified"], default="unverified"
    )
    unverified_reason = StringField()
    payload_hash = StringField()

    # Audit context
    action = StringField(required=True, default="report.create")
    entity_type = StringField(default="report")
    entity_id = StringField()
    details = StringField()
    ip_address = StringField()
    user_agent = StringField()
    created_at = DateTimeField(default=utcnow)

    meta = {"collection": "audit_logs", "indexes": ["organization", "-created_at"]}

    def to_dict(self):
        return {
            "_id": str(self.id),
            "timestamp": iso_utc(self.created_at),
            "report_id": self.report_id,
            "generated_by_email": self.user.email if self.user else None,
            "generated_by_name": self.user.name if self.user else self.officer_name,
            "generated_by_role": self.user.role if self.user else self.officer_role,
            "customer_name": self.customer_name,
            "customer_no": self.customer_no,
            "customer_id_no": self.customer_id_no,
            "customer_phone": self.customer_phone,
            "loan_product": self.loan_product,
            "loan_amount": self.loan_amount,
            "branch": self.branch,
            "kyc_status": self.kyc_status,
            "agent_code": self.agent_code,
            "filename": self.filename,
            "meeting_confirmed": self.meeting_confirmed,
            "discussion_summary": self.discussion_summary,
            "meeting_location": self.meeting_location,
            "meeting_datetime": self.meeting_datetime,
            "officer_name": self.officer_name,
            "officer_role": self.officer_role,
            "officer_gps": self.officer_gps,
            "officer_gps_at_signature": self.officer_gps_at_signature,
            "customer_signed_gps": self.customer_signed_gps,
            "selfie_gps": self.selfie_gps,
            "has_team_leader_sig": self.has_team_leader_sig,
            "has_agent_sig": self.has_agent_sig,
            "has_customer_sig": self.has_customer_sig,
            "customer_signed_at": iso_utc(self.customer_signed_at),
            "has_selfie": self.has_selfie,
            "selfie_timestamp": iso_utc(self.selfie_timestamp),
            "selfie_image_hash": self.selfie_image_hash,
            "otp_verified": self.otp_verified,
            "otp_verified_at": iso_utc(self.otp_verified_at),
            "otp_phone": self.otp_phone,
            "verification_level": self.verification_level,
            "unverified_reason": self.unverified_reason,
            "payload_hash": self.payload_hash,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "action": self.action,
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "details": self.details,
        }


def log_action(user, action, entity_type=None, entity_id=None, details=None, extra=None):
    try:
        entry = AuditLog(
            organization=user.organization,
            user=user,
            action=action,
            entity_type=entity_type,
            entity_id=str(entity_id) if entity_id else None,
            details=details,
            ip_address=request.remote_addr if request else None,
            user_agent=(request.headers.get("User-Agent", "")[:200] if request else None),
        )
        if extra:
            for k, v in extra.items():
                setattr(entry, k, v)
        entry.save()
    except Exception as e:
        print(f"[audit] failed: {e}")
        import traceback
        traceback.print_exc()


# ------------------------------------------------------------------
# AUTH HELPERS
# ------------------------------------------------------------------
def current_user():
    uid = get_jwt_identity()
    try:
        return User.objects.get(id=uid)
    except User.DoesNotExist:
        return None


def role_required(*roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if request.method == "OPTIONS":
                return jsonify({}), 200
            verify_jwt_in_request()
            user = current_user()
            if not user or not user.is_active:
                return jsonify({"message": "User not found or inactive"}), 401
            if user.role not in roles:
                return jsonify({"message": "Insufficient permissions"}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def auth_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if request.method == "OPTIONS":
            return jsonify({}), 200
        verify_jwt_in_request()
        user = current_user()
        if not user or not user.is_active:
            return jsonify({"message": "User not found or inactive"}), 401
        return fn(*args, **kwargs)
    return wrapper


def parse_date(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


# ------------------------------------------------------------------
# AUTH ROUTES
# ------------------------------------------------------------------
@app.route("/api/auth/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    for r in ["name", "email", "password", "organizationId"]:
        if not data.get(r):
            return jsonify({"message": f"{r} is required"}), 400
    if User.objects(email=data["email"]).first():
        return jsonify({"message": "Email already registered"}), 400
    try:
        org = Organization.objects.get(id=data["organizationId"])
    except Organization.DoesNotExist:
        return jsonify({"message": "Organization not found"}), 400

    user = User(
        name=data["name"], email=data["email"],
        role=data.get("role", "admin_agent"), organization=org,
    )
    user.set_password(data["password"])
    user.save()

    token = create_access_token(identity=str(user.id))
    return jsonify({"success": True, "token": token, "user": user.to_dict()}), 201


@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    email, password = data.get("email"), data.get("password")
    if not email or not password:
        return jsonify({"success": False, "error": "Email and password required"}), 400

    user = User.objects(email=email).first()
    if not user or not user.check_password(password):
        return jsonify({"success": False, "error": "Invalid credentials"}), 401
    if not user.is_active:
        return jsonify({"success": False, "error": "Account deactivated"}), 403

    user.last_login = utcnow()
    user.save()
    log_action(user, "user.login", "user", user.id)

    token = create_access_token(identity=str(user.id))
    return jsonify({"success": True, "token": token, "user": user.to_dict()})


@app.route("/api/auth/me", methods=["GET"])
@auth_required
def me():
    return jsonify({"success": True, "user": current_user().to_dict()})


@app.route("/api/auth/logout", methods=["POST", "OPTIONS"])
@auth_required
def logout():
    return jsonify({"success": True, "message": "Logged out"})


# ------------------------------------------------------------------
# INVITATIONS
# ------------------------------------------------------------------
@app.route("/api/invitations", methods=["GET"])
@role_required("super_admin", "admin_agent")
def list_invitations():
    user = current_user()
    invites = Invitation.objects(organization=user.organization).order_by("-created_at")
    return jsonify({"success": True, "invitations": [i.to_dict() for i in invites]})


@app.route("/api/invitations", methods=["POST"])
@role_required("super_admin", "admin_agent")
def create_invitation():
    user = current_user()
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    role = data.get("role", "admin_agent")
    branch_ids = data.get("assignedBranches") or []

    if not email:
        return jsonify({"success": False, "error": "Email is required"}), 400
    if role not in ["super_admin", "admin_agent", "branch_manager", "auditor"]:
        return jsonify({"success": False, "error": "Invalid role"}), 400
    if User.objects(email=email).first():
        return jsonify({"success": False, "error": "A user with this email already exists"}), 400
    if Invitation.objects(organization=user.organization, email=email, status="pending").first():
        return jsonify({"success": False, "error": "A pending invitation already exists for this email"}), 400

    branches = []
    for bid in branch_ids:
        try:
            branches.append(Branch.objects.get(id=bid, organization=user.organization))
        except Branch.DoesNotExist:
            pass

    token = secrets.token_urlsafe(32)
    invite = Invitation(
        email=email, token=token, role=role,
        organization=user.organization, invited_by=user,
        assigned_branches=branches,
        expires_at=utcnow() + timedelta(days=7),
    ).save()

    accept_url = f"{FRONTEND_URL}/accept-invite/{token}"

    try:
        if app.config["MAIL_USERNAME"] and app.config["MAIL_PASSWORD"]:
            msg = Message(
                subject=f"You're invited to {user.organization.name} on LoanRegistry",
                recipients=[email],
                html=f"""
                    <p>Hello,</p>
                    <p><strong>{user.name}</strong> has invited you to join
                    <strong>{user.organization.name}</strong> as a
                    <strong>{role.replace('_',' ')}</strong>.</p>
                    <p><a href="{accept_url}">Accept Invitation</a></p>
                    <p>Or paste this link: {accept_url}</p>
                    <p>Expires in 7 days.</p>
                """,
            )
            mail.send(msg)
            emailed = True
        else:
            emailed = False
    except Exception as e:
        print(f"[invite] mail failed: {e}")
        emailed = False

    print(f"\n[INVITE] {email} -> {accept_url}\n")
    log_action(user, "invitation.create", "invitation", invite.id, f"email={email}, role={role}")

    return jsonify({
        "success": True,
        "invitation": invite.to_dict(),
        "acceptUrl": accept_url,
        "invitation_link": accept_url,
        "emailed": emailed,
    }), 201


@app.route("/api/invitations/<invite_id>", methods=["DELETE"])
@role_required("super_admin", "admin_agent")
def revoke_invitation(invite_id):
    user = current_user()
    try:
        invite = Invitation.objects.get(id=invite_id, organization=user.organization)
    except Invitation.DoesNotExist:
        return jsonify({"success": False, "error": "Invitation not found"}), 404
    invite.status = "revoked"
    invite.save()
    log_action(user, "invitation.revoke", "invitation", invite.id)
    return jsonify({"success": True, "message": "Invitation revoked"})


@app.route("/api/invitations/verify/<token>", methods=["GET"])
def verify_invite(token):
    invite = Invitation.objects(token=token).first()
    if not invite:
        return jsonify({"success": False, "error": "Invitation not found"}), 404
    if not invite.is_valid():
        return jsonify({"success": False, "error": "Invitation expired or already used"}), 400
    return jsonify({
        "success": True,
        "email": invite.email,
        "role": invite.role,
        "organization": invite.organization.name,
    })


@app.route("/api/invitations/accept/<token>", methods=["POST"])
def accept_invite(token):
    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    password = data.get("password") or ""

    if not name or len(password) < 6:
        return jsonify({"success": False, "error": "Name and password (min 6 chars) are required"}), 400

    invite = Invitation.objects(token=token).first()
    if not invite or not invite.is_valid():
        return jsonify({"success": False, "error": "Invitation expired or invalid"}), 400
    if User.objects(email=invite.email).first():
        return jsonify({"success": False, "error": "A user with this email already exists"}), 400

    user = User(
        name=name, email=invite.email, role=invite.role,
        organization=invite.organization,
        assigned_branches=invite.assigned_branches,
    )
    user.set_password(password)
    user.save()

    invite.status = "accepted"
    invite.accepted_at = utcnow()
    invite.save()

    log_action(user, "user.accept_invite", "user", user.id)
    jwt_token = create_access_token(identity=str(user.id))
    return jsonify({"success": True, "token": jwt_token, "user": user.to_dict()}), 201


@app.route("/api/auth/resend-invitation", methods=["POST", "OPTIONS"])
@role_required("super_admin", "admin_agent")
def resend_invitation():
    user = current_user()
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    if not email:
        return jsonify({"success": False, "error": "Email required"}), 400

    target = User.objects(email=email).first()
    if not target:
        return jsonify({"success": False, "error": "User not found"}), 404

    token = secrets.token_urlsafe(32)
    invite = Invitation(
        email=email, token=token, role=target.role,
        organization=user.organization, invited_by=user,
        expires_at=utcnow() + timedelta(days=7),
    ).save()

    accept_url = f"{FRONTEND_URL}/accept-invite/{token}"
    print(f"\n[INVITE] {email} -> {accept_url}\n")
    log_action(user, "invitation.resend", "invitation", invite.id, f"email={email}")

    return jsonify({
        "success": True,
        "message": f"Invitation resent to {email}",
        "invitation_link": accept_url,
    })


# ------------------------------------------------------------------
# OTP - CUSTOMER VERIFICATION
# ------------------------------------------------------------------
@app.route("/api/otp/send", methods=["POST", "OPTIONS"])
@auth_required
def otp_send():
    try:
        data = request.get_json() or {}
        phone = (data.get("phone") or "").strip()
        if not phone:
            return jsonify({"success": False, "error": "Phone required"}), 400

        normalized = phone.replace(" ", "").replace("-", "")
        if not normalized.startswith("+"):
            if normalized.startswith("0"):
                normalized = "+254" + normalized[1:]
            elif normalized.startswith("254"):
                normalized = "+" + normalized
            else:
                normalized = "+" + normalized

        code = "".join(str(secrets.randbelow(10)) for _ in range(OTP_LENGTH))
        salt = secrets.token_hex(16)
        code_hash = sha256_hex(code + salt)

        CustomerOtp.objects(phone=normalized).delete()
        CustomerOtp(
            phone=normalized,
            code_hash=code_hash,
            salt=salt,
            expires_at=utcnow() + timedelta(minutes=OTP_EXPIRY_MINUTES),
        ).save()

        message = (
            f"JAFARICR: Your customer verification code is {code}. "
            f"Read it to the officer. Expires in {OTP_EXPIRY_MINUTES} min. Do not share."
        )
        ok, error = send_sms(normalized, message)
        if not ok:
            print(f"[OTP] SMS failed: {error}")
            return jsonify({"success": False, "error": f"SMS failed: {error}"}), 500

        print(f"[OTP] Sent to {normalized} (code={code})")

        is_sandbox = "sandbox" in AT_BASE_URL
        return jsonify({
            "success": True,
            "message": f"Code sent to {normalized}",
            "expiresInMinutes": OTP_EXPIRY_MINUTES,
            "devCode": code if is_sandbox else None,
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/otp/verify", methods=["POST", "OPTIONS"])
@auth_required
def otp_verify():
    try:
        data = request.get_json() or {}
        phone = (data.get("phone") or "").strip()
        code = (data.get("code") or "").strip()
        if not phone or not code:
            return jsonify({"success": False, "error": "Phone and code required"}), 400

        normalized = phone.replace(" ", "").replace("-", "")
        if not normalized.startswith("+"):
            if normalized.startswith("0"):
                normalized = "+254" + normalized[1:]
            elif normalized.startswith("254"):
                normalized = "+" + normalized
            else:
                normalized = "+" + normalized

        otp = CustomerOtp.objects(phone=normalized).first()
        if not otp:
            return jsonify({"success": False, "error": "No active code for this number"}), 400
        if otp.is_expired():
            return jsonify({"success": False, "error": "Code expired"}), 400
        if otp.attempts >= 5:
            return jsonify({"success": False, "error": "Too many attempts. Request a new code."}), 429

        if not otp.check_code(code):
            otp.attempts += 1
            otp.save()
            return jsonify({"success": False, "error": "Incorrect code"}), 400

        otp.verified = True
        otp.verified_at = utcnow()
        otp.verified_token = secrets.token_urlsafe(24)
        otp.verified_token_expires_at = utcnow() + timedelta(minutes=30)
        otp.save()

        return jsonify({
            "success": True,
            "message": "Verified",
            "verificationToken": otp.verified_token,
            "phone": normalized,
            "verifiedAt": iso_utc(otp.verified_at),
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


def consume_verification_token(token):
    """Return the CustomerOtp if the token is valid, else None."""
    if not token:
        return None
    otp = CustomerOtp.objects(verified_token=token).first()
    if not otp or not otp.verified:
        return None
    exp = otp.verified_token_expires_at
    now = utcnow()
    if exp:
        if exp.tzinfo is not None:
            exp = exp.astimezone(timezone.utc).replace(tzinfo=None)
        if exp < now:
            return None
    return otp


# ------------------------------------------------------------------
# USERS
# ------------------------------------------------------------------
@app.route("/api/users", methods=["GET"])
@role_required("super_admin", "admin_agent", "auditor")
def list_users():
    user = current_user()
    users = User.objects(organization=user.organization).order_by("name")
    return jsonify({"success": True, "users": [u.to_dict() for u in users]})


@app.route("/api/users/<user_id>", methods=["PATCH"])
@role_required("super_admin", "admin_agent")
def update_user(user_id):
    actor = current_user()
    data = request.get_json() or {}
    try:
        target = User.objects.get(id=user_id, organization=actor.organization)
    except User.DoesNotExist:
        return jsonify({"success": False, "error": "User not found"}), 404

    if "role" in data and data["role"] in ["super_admin", "admin_agent", "branch_manager", "auditor"]:
        target.role = data["role"]
    if "isActive" in data:
        target.is_active = bool(data["isActive"])
    if "name" in data and data["name"].strip():
        target.name = data["name"].strip()

    target.save()
    log_action(actor, "user.update", "user", target.id,
               f"role={target.role}, active={target.is_active}")
    return jsonify({"success": True, "user": target.to_dict()})


# ------------------------------------------------------------------
# BRANCHES
# ------------------------------------------------------------------
@app.route("/api/branches", methods=["GET"])
@auth_required
def list_branches():
    user = current_user()
    branches = Branch.objects(organization=user.organization, is_active=True).order_by("name")
    return jsonify({"success": True, "branches": [b.to_dict() for b in branches]})


@app.route("/api/branches/<branch_id>", methods=["GET"])
@auth_required
def get_branch(branch_id):
    user = current_user()
    try:
        branch = Branch.objects.get(id=branch_id, organization=user.organization)
    except Exception:
        return jsonify({"success": False, "error": "Branch not found"}), 404

    loans = Loan.objects(branch=branch)
    summary = {}
    for loan in loans:
        s = summary.setdefault(loan.status, {"_id": loan.status, "count": 0,
                                             "totalAmount": 0, "totalOutstanding": 0})
        s["count"] += 1
        s["totalAmount"] += loan.principal_amount
        s["totalOutstanding"] += loan.outstanding_balance
    return jsonify({"success": True, "branch": branch.to_dict(),
                    "summary": list(summary.values())})


@app.route("/api/branches", methods=["POST"])
@role_required("super_admin", "admin_agent")
def create_branch():
    data = request.get_json() or {}
    user = current_user()
    branch = Branch(
        name=data.get("name"), code=data.get("code"),
        organization=user.organization,
        address=data.get("address"),
        manager_name=data.get("managerName"),
        contact_email=data.get("contactEmail"),
        contact_phone=data.get("contactPhone"),
    )
    branch.save()
    log_action(user, "branch.create", "branch", branch.id, f"name={branch.name}")
    return jsonify({"success": True, "branch": branch.to_dict()}), 201


@app.route("/api/branches/<branch_id>", methods=["PUT"])
@role_required("super_admin", "admin_agent")
def update_branch(branch_id):
    data = request.get_json() or {}
    user = current_user()
    try:
        branch = Branch.objects.get(id=branch_id, organization=user.organization)
    except Exception:
        return jsonify({"success": False, "error": "Branch not found"}), 404

    for field, camel in [
        ("name", "name"), ("code", "code"),
        ("manager_name", "managerName"), ("address", "address"),
        ("contact_email", "contactEmail"), ("contact_phone", "contactPhone"),
    ]:
        if camel in data:
            setattr(branch, field, data[camel])
    branch.save()
    log_action(user, "branch.update", "branch", branch.id)
    return jsonify({"success": True, "branch": branch.to_dict()})


# ------------------------------------------------------------------
# ADMIN - USERS
# ------------------------------------------------------------------
@app.route("/api/admin/users", methods=["GET"])
@role_required("super_admin", "admin_agent")
def admin_list_users():
    user = current_user()
    users = User.objects(organization=user.organization).order_by("name")
    return jsonify({"success": True, "data": [u.to_dict() for u in users]})


@app.route("/api/admin/users", methods=["POST"])
@role_required("super_admin", "admin_agent")
def admin_create_user():
    user = current_user()
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    name = (data.get("name") or "").strip()
    role = data.get("role", "admin_agent")

    if not email:
        return jsonify({"success": False, "error": "Email required"}), 400
    if User.objects(email=email).first():
        return jsonify({"success": False, "error": "User already exists"}), 400
    if role not in ["super_admin", "admin_agent", "branch_manager", "auditor"]:
        return jsonify({"success": False, "error": "Invalid role"}), 400

    new_user = User(
        name=name or email.split("@")[0],
        email=email,
        role=role,
        organization=user.organization,
        is_active=False,  # activated after password set
    )
    new_user.save()

    token = secrets.token_urlsafe(32)
    invite = Invitation(
        email=email, token=token, role=role,
        organization=user.organization, invited_by=user,
        expires_at=utcnow() + timedelta(days=7),
    ).save()

    accept_url = f"{FRONTEND_URL}/accept-invite/{token}"
    print(f"\n[INVITE] {email} -> {accept_url}\n")
    log_action(user, "user.create_invite", "user", new_user.id, f"email={email}, role={role}")

    return jsonify({
        "success": True,
        "message": f"User {email} added. Share the invite link.",
        "user": new_user.to_dict(),
        "invitation_link": accept_url,
    }), 201


@app.route("/api/admin/users/<email>", methods=["DELETE"])
@role_required("super_admin", "admin_agent")
def admin_delete_user(email):
    user = current_user()
    email = email.strip().lower()
    if email == user.email:
        return jsonify({"success": False, "error": "Cannot delete yourself"}), 400
    try:
        target = User.objects.get(email=email, organization=user.organization)
    except User.DoesNotExist:
        return jsonify({"success": False, "error": "User not found"}), 404
    target.delete()
    log_action(user, "user.delete", "user", None, f"email={email}")
    return jsonify({"success": True, "message": f"User {email} deleted"})


@app.route("/api/admin/users/<email>/toggle-status", methods=["POST"])
@role_required("super_admin", "admin_agent")
def admin_toggle_user(email):
    user = current_user()
    email = email.strip().lower()
    if email == user.email:
        return jsonify({"success": False, "error": "Cannot deactivate yourself"}), 400
    try:
        target = User.objects.get(email=email, organization=user.organization)
    except User.DoesNotExist:
        return jsonify({"success": False, "error": "User not found"}), 404
    target.is_active = not target.is_active
    target.save()
    log_action(user, "user.toggle", "user", target.id, f"active={target.is_active}")
    return jsonify({
        "success": True,
        "message": f"User {email} is now {'active' if target.is_active else 'inactive'}",
    })


@app.route("/api/admin/users/<email>/reset-password", methods=["POST"])
@role_required("super_admin", "admin_agent")
def admin_reset_password(email):
    user = current_user()
    email = email.strip().lower()
    try:
        target = User.objects.get(email=email, organization=user.organization)
    except User.DoesNotExist:
        return jsonify({"success": False, "error": "User not found"}), 404

    token = secrets.token_urlsafe(32)
    Invitation.objects(organization=user.organization, email=email, status="pending").delete()
    Invitation(
        email=email, token=token, role=target.role,
        organization=user.organization, invited_by=user,
        expires_at=utcnow() + timedelta(days=7),
    ).save()

    accept_url = f"{FRONTEND_URL}/accept-invite/{token}"
    print(f"\n[RESET] {email} -> {accept_url}\n")
    log_action(user, "user.reset_password", "user", target.id, f"email={email}")

    return jsonify({
        "success": True,
        "message": f"Reset link sent to {email}",
        "invitation_link": accept_url,
    })


# ------------------------------------------------------------------
# LOANS (kept unchanged)
# ------------------------------------------------------------------
def build_loan_query(user):
    qs = Loan.objects(organization=user.organization)
    branch_id = request.args.get("branchId")
    status = request.args.get("status")
    loan_type = request.args.get("loanType")
    search = request.args.get("search")
    start_date = request.args.get("startDate")
    end_date = request.args.get("endDate")
    min_amount = request.args.get("minAmount")
    max_amount = request.args.get("maxAmount")

    if branch_id:
        try:
            qs = qs.filter(branch=Branch.objects.get(id=branch_id))
        except Exception:
            pass
    if status:
        qs = qs.filter(status=status)
    if loan_type:
        qs = qs.filter(loan_type=loan_type)
    if start_date:
        qs = qs.filter(created_at__gte=parse_date(start_date))
    if end_date:
        qs = qs.filter(created_at__lte=parse_date(end_date))
    if min_amount:
        qs = qs.filter(principal_amount__gte=float(min_amount))
    if max_amount:
        qs = qs.filter(principal_amount__lte=float(max_amount))
    if search:
        qs = qs.filter(
            Q(loan_number__icontains=search)
            | Q(borrower__full_name__icontains=search)
            | Q(borrower__id_number__icontains=search)
        )
    return qs


@app.route("/api/loans", methods=["GET"])
@auth_required
def list_loans():
    user = current_user()
    page = int(request.args.get("page", 1))
    limit = int(request.args.get("limit", 20))
    sort_by = request.args.get("sortBy", "created_at")
    sort_order = request.args.get("sortOrder", "desc")

    qs = build_loan_query(user)
    sort_field = "-" + sort_by if sort_order == "desc" else sort_by
    qs = qs.order_by(sort_field)
    total = qs.count()
    loans = qs.skip((page - 1) * limit).limit(limit)

    return jsonify({
        "success": True,
        "loans": [l.to_dict() for l in loans],
        "pagination": {
            "page": page, "limit": limit, "total": total,
            "pages": (total + limit - 1) // limit,
        }
    })


@app.route("/api/loans/<loan_id>", methods=["GET"])
@auth_required
def get_loan(loan_id):
    user = current_user()
    try:
        loan = Loan.objects.get(id=loan_id, organization=user.organization)
    except Exception:
        return jsonify({"success": False, "error": "Loan not found"}), 404
    return jsonify({"success": True, "loan": loan.to_dict()})


# ------------------------------------------------------------------
# REPORT GENERATION (extended with verification)
# ------------------------------------------------------------------
def generate_report_pdf(payload, user):
    """Build a PDF from the report payload using reportlab."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=LETTER,
                            leftMargin=40, rightMargin=40, topMargin=40, bottomMargin=40)
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("H1", parent=styles["Heading1"], fontSize=18,
                        textColor=colors.HexColor("#123b72"))
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=12,
                        textColor=colors.HexColor("#123b72"))
    body = styles["BodyText"]
    small = ParagraphStyle("small", parent=body, fontSize=8, textColor=colors.grey)

    story = []
    story.append(Paragraph("JAFARI CREDIT", h1))
    story.append(Paragraph("Customer Meeting Report", body))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"<b>Report ID:</b> {payload.get('report_id', 'N/A')}", body))
    story.append(Paragraph(f"<b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", body))
    story.append(Spacer(1, 12))

    # 1. Meeting details
    story.append(Paragraph("1. Meeting Details", h2))
    md = [
        ["Field", "Value"],
        ["Officer", payload.get("created_by", "")],
        ["Role", payload.get("user_role", "")],
        ["Agent Code", payload.get("agent_code", "")],
        ["Date/Time", payload.get("meeting_datetime", "")],
        ["Branch", payload.get("branch", "")],
        ["Location", payload.get("meeting_location", "")],
        ["GPS", payload.get("gps_locator", "")],
        ["Meeting Confirmed", payload.get("meeting_confirmed", "")],
    ]
    t = Table(md, colWidths=[130, 370])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(t)
    story.append(Spacer(1, 12))

    # 2. Customer
    story.append(Paragraph("2. Customer", h2))
    cd = [
        ["Field", "Value"],
        ["Name", payload.get("customer_name", "")],
        ["Customer No", payload.get("customer_id", "")],
        ["ID Number", payload.get("customer_id_no", "")],
        ["Phone", payload.get("customer_phone", "")],
        ["Email", payload.get("customer_email", "")],
        ["Address", payload.get("customer_address", "")],
    ]
    t = Table(cd, colWidths=[130, 370])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(t)
    story.append(Spacer(1, 12))

    # 3. Loan
    story.append(Paragraph("3. Loan", h2))
    ld = [
        ["Field", "Value"],
        ["Product", payload.get("loan_product", "")],
        ["Amount (KES)", payload.get("loan_amount", "")],
    ]
    t = Table(ld, colWidths=[130, 370])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(t)
    story.append(Spacer(1, 12))

    # 3b. KYC
    story.append(Paragraph("4. KYC Status", h2))
    kd = [
        ["Field", "Value"],
        ["KYC Status", payload.get("kyc_status", "")],
        ["ID Type", payload.get("kyc_id_type", "")],
        ["Verified By", payload.get("kyc_verified_by", "")],
        ["Date Verified", payload.get("kyc_date_verified", "")],
        ["KYC Notes", payload.get("kyc_notes", "")],
    ]
    t = Table(kd, colWidths=[130, 370])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(t)
    story.append(Spacer(1, 12))

    # 5. Summary of discussion (the actual meeting summary)
    story.append(Paragraph("5. Summary of Discussion", h2))
    summary_text = payload.get("discussion_summary") or "(No summary recorded)"
    story.append(Paragraph(str(summary_text).replace("\n", "<br/>"), body))
    story.append(Spacer(1, 12))

    # 6. Verification summary
    story.append(Paragraph("6. Verification Summary", h2))
    vs = [
        ["Check", "Status"],
        ["OTP Verified", "Yes" if payload.get("otp_verified") else "No"],
        ["OTP Verified At", payload.get("otp_verified_at") or "-"],
        ["OTP Phone", payload.get("otp_phone") or "-"],
        ["Team Leader Signature", "Present" if payload.get("team_leader_signature_image") else "Missing"],
        ["Agent Signature", "Present" if payload.get("agent_signature_image") else "Missing"],
        ["Customer Signature", "Present" if payload.get("customer_signature_image") else "Missing"],
        ["Geotagged Selfie", "Present" if payload.get("selfie_image") else "Missing"],
        ["Officer GPS", payload.get("gps_locator") or "-"],
        ["Selfie GPS", payload.get("selfie_gps") or "-"],
        ["Verification Level", (payload.get("verification_level") or "unverified").upper()],
        ["Payload SHA-256", (payload.get("payload_hash") or "")[:32] + "..."],
    ]
    t = Table(vs, colWidths=[180, 320])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(t)
    story.append(Spacer(1, 12))

    # 7. Signatures images
    story.append(Paragraph("7. Signatures", h2))
    for label, key in [("Team Leader", "team_leader_signature_image"),
                       ("Agent", "agent_signature_image"),
                       ("Customer", "customer_signature_image")]:
        story.append(Paragraph(f"<b>{label}:</b>", body))
        img = payload.get(key, "")
        if img and img.startswith("data:image"):
            try:
                raw = img.split(",", 1)[1]
                from reportlab.platypus import Image as RLImage
                import base64 as b64
                img_bytes = b64.b64decode(raw)
                story.append(RLImage(io.BytesIO(img_bytes), width=200, height=60))
            except Exception:
                story.append(Paragraph("<i>(signature could not be embedded)</i>", small))
        else:
            story.append(Paragraph("<i>(no signature)</i>", small))
        story.append(Spacer(1, 6))

    # 8. Selfie
    if payload.get("selfie_image", "").startswith("data:image"):
        story.append(Paragraph("8. Geotagged Selfie", h2))
        try:
            import base64 as b64
            from reportlab.platypus import Image as RLImage
            raw = payload["selfie_image"].split(",", 1)[1]
            story.append(RLImage(io.BytesIO(b64.b64decode(raw)), width=280, height=210))
        except Exception:
            story.append(Paragraph("<i>(selfie could not be embedded)</i>", small))

    story.append(Spacer(1, 20))
    story.append(Paragraph(
        "This document is computer-generated and includes cryptographic verification hashes.",
        small,
    ))

    doc.build(story)
    buf.seek(0)
    return buf.getvalue()


@app.route("/api/generate", methods=["POST", "OPTIONS"])
@auth_required
def generate_report():
    try:
        payload = request.get_json() or {}
        user = current_user()

        # ---- OTP enforcement ----
        verification_token = payload.get("otp_verification_token")
        unverified_reason = (payload.get("unverified_reason") or "").strip()

        otp_doc = None
        if verification_token:
            otp_doc = consume_verification_token(verification_token)
            if not otp_doc:
                return jsonify({
                    "success": False,
                    "error": "OTP verification token invalid or expired. Re-verify the customer.",
                }), 400
            payload["otp_verified"] = True
            payload["otp_verified_at"] = iso_utc(otp_doc.verified_at)
            payload["otp_phone"] = otp_doc.phone
        else:
            if not unverified_reason:
                return jsonify({
                    "success": False,
                    "error": "Customer verification is required. Send OTP or provide an unverified reason.",
                }), 400
            payload["otp_verified"] = False

        # ---- Verification level ----
        payload["verification_level"] = compute_verification_level(payload)

        # ---- Payload hash ----
        payload["payload_hash"] = compute_report_hash(payload)

        # ---- Build PDF ----
        pdf_bytes = generate_report_pdf(payload, user)
        safe_name = (payload.get("customer_name") or "customer").replace(" ", "_")
        filename = f"jafari_report_{safe_name}_{int(datetime.now().timestamp())}.pdf"

        # ---- Audit entry with all evidence ----
        try:
            extra = {
                "report_id": payload.get("report_id"),
                "customer_name": payload.get("customer_name"),
                "customer_no": payload.get("customer_id"),
                "customer_id_no": payload.get("customer_id_no"),
                "customer_phone": payload.get("customer_phone"),
                "loan_product": payload.get("loan_product"),
                "loan_amount": payload.get("loan_amount"),
                "branch": payload.get("branch"),
                "kyc_status": payload.get("kyc_status"),
                "agent_code": payload.get("agent_code"),
                "filename": filename,
                "meeting_confirmed": payload.get("meeting_confirmed"),
                "discussion_summary": payload.get("discussion_summary"),
                "meeting_location": payload.get("meeting_location"),
                "meeting_datetime": payload.get("meeting_datetime"),
                "officer_name": payload.get("created_by"),
                "officer_role": payload.get("user_role"),
                "officer_gps": payload.get("gps_locator"),
                "officer_gps_at_signature": payload.get("officer_gps_at_signature"),
                "customer_signed_gps": payload.get("customer_signed_gps"),
                "selfie_gps": payload.get("selfie_gps"),
                "has_team_leader_sig": bool(payload.get("team_leader_signature_image")),
                "has_agent_sig": bool(payload.get("agent_signature_image")),
                "has_customer_sig": bool(payload.get("customer_signature_image")),
                "customer_signed_at": parse_date(payload.get("customer_signed_at")),
                "has_selfie": bool(payload.get("selfie_image")),
                "selfie_timestamp": parse_date(payload.get("selfie_timestamp")),
                "selfie_image_hash": (
                    sha256_hex(payload.get("selfie_image", "")) if payload.get("selfie_image") else None
                ),
                "otp_verified": bool(payload.get("otp_verified")),
                "otp_verified_at": parse_date(payload.get("otp_verified_at")),
                "otp_phone": payload.get("otp_phone"),
                "verification_level": payload.get("verification_level"),
                "unverified_reason": unverified_reason or None,
                "payload_hash": payload.get("payload_hash"),
            }
            log_action(user, "report.generate", "report", None,
                       f"report_id={payload.get('report_id')} level={payload.get('verification_level')}",
                       extra=extra)
        except Exception as e:
            print(f"[audit] report log failed: {e}")

        import base64
        return jsonify({
            "success": True,
            "filename": filename,
            "pdf": base64.b64encode(pdf_bytes).decode("utf-8"),
            "verification_level": payload.get("verification_level"),
            "payload_hash": payload.get("payload_hash"),
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "error": str(e)}), 500


# ------------------------------------------------------------------
# AUDIT LOG - ADMIN PANEL
# ------------------------------------------------------------------
@app.route("/api/admin/audit-log", methods=["GET", "OPTIONS"])
@role_required("super_admin", "admin_agent", "auditor")
def get_admin_audit_log():
    if request.method == "OPTIONS":
        return "", 200
    try:
        user = current_user()

        start_date = request.args.get("start_date")
        end_date = request.args.get("end_date")
        user_email = request.args.get("user_email")
        customer_search = request.args.get("customer")
        limit = int(request.args.get("limit", 500))

        qs = AuditLog.objects(organization=user.organization)

        if start_date:
            try:
                qs = qs.filter(created_at__gte=datetime.fromisoformat(start_date))
            except Exception:
                pass

        if end_date:
            try:
                qs = qs.filter(created_at__lte=datetime.fromisoformat(end_date + "T23:59:59"))
            except Exception:
                pass

        if user_email:
            matching_users = User.objects(email__icontains=user_email)
            qs = qs.filter(user__in=matching_users)

        if customer_search:
            qs = qs.filter(
                Q(customer_name__icontains=customer_search) |
                Q(customer_no__icontains=customer_search) |
                Q(report_id__icontains=customer_search)
            )

        qs = qs.order_by("-created_at").limit(limit)

        return jsonify({
            "success": True,
            "count": qs.count(),
            "total": AuditLog.objects(organization=user.organization).count(),
            "data": [l.to_dict() for l in qs],
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/admin/audit-log/<entry_id>", methods=["DELETE", "OPTIONS"])
@role_required("super_admin", "admin_agent")
def delete_audit_entry(entry_id):
    if request.method == "OPTIONS":
        return "", 200
    user = current_user()
    try:
        entry = AuditLog.objects.get(id=entry_id, organization=user.organization)
    except Exception:
        return jsonify({"success": False, "error": "Entry not found"}), 404
    entry.delete()
    log_action(user, "audit.delete", "audit", entry_id)
    return jsonify({"success": True, "message": "Entry deleted"})


@app.route("/api/admin/audit-log/export", methods=["GET", "OPTIONS"])
@role_required("super_admin", "admin_agent", "auditor")
def export_audit_log():
    if request.method == "OPTIONS":
        return "", 200
    try:
        import base64
        user = current_user()
        entries = AuditLog.objects(organization=user.organization).order_by("-created_at")

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Timestamp", "Report ID", "Officer", "Officer Email",
            "Customer Name", "Customer No", "Loan Product", "Loan Amount",
            "Branch", "KYC Status", "Verification Level",
            "OTP Verified", "TL Sig", "Agent Sig", "Customer Sig", "Selfie",
            "Discussion Summary", "Officer GPS", "Selfie GPS",
        ])
        for e in entries:
            writer.writerow([
                iso_utc(e.created_at),
                e.report_id or "",
                e.user.name if e.user else e.officer_name or "",
                e.user.email if e.user else "",
                e.customer_name or "",
                e.customer_no or "",
                e.loan_product or "",
                e.loan_amount or "",
                e.branch or "",
                e.kyc_status or "",
                e.verification_level or "",
                "Yes" if e.otp_verified else "No",
                "Yes" if e.has_team_leader_sig else "No",
                "Yes" if e.has_agent_sig else "No",
                "Yes" if e.has_customer_sig else "No",
                "Yes" if e.has_selfie else "No",
                (e.discussion_summary or "").replace("\n", " "),
                e.officer_gps or "",
                e.selfie_gps or "",
            ])

        csv_content = output.getvalue()
        csv_base64 = base64.b64encode(csv_content.encode("utf-8")).decode("utf-8")
        filename = f"jafari_audit_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        return jsonify({
            "success": True,
            "csv": csv_base64,
            "filename": filename,
            "count": entries.count(),
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "error": str(e)}), 500


# ------------------------------------------------------------------
# HEALTH + ERRORS
# ------------------------------------------------------------------
@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "OK",
        "timestamp": iso_utc(utcnow()),
        "sms_provider": "africastalking",
        "sms_configured": bool(AT_API_KEY),
    })


@app.errorhandler(404)
def not_found(e):
    return jsonify({"success": False, "message": "Not found"}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({"success": False, "message": "Internal server error"}), 500


@jwt.unauthorized_loader
def missing_token(reason):
    return jsonify({"success": False, "message": "Authentication required"}), 401


@jwt.invalid_token_loader
def invalid_token(reason):
    return jsonify({"success": False, "message": "Invalid token"}), 401


@jwt.expired_token_loader
def expired_token(jwt_header, jwt_payload):
    return jsonify({"success": False, "message": "Token expired"}), 401


# ------------------------------------------------------------------
# SEED
# ------------------------------------------------------------------
def seed_demo_data():
    if Organization.objects(registration_number="REG-DEMO-001").first():
        print("Demo data already exists. Skipping seed.")
        return

    org = Organization(
        name="Acme Microfinance",
        registration_number="REG-DEMO-001",
        license_number="LIC-2024-001",
        address="New York, USA",
        contact_email="info@acme.com",
    ).save()

    branches = []
    for name, code, city, manager in [
        ("Downtown Branch", "DWN-01", "New York", "John Smith"),
        ("Uptown Branch", "UPT-01", "New York", "Sarah Lee"),
        ("Brooklyn Branch", "BKL-01", "Brooklyn", "Mike Ross"),
    ]:
        b = Branch(name=name, code=code, organization=org,
                   address=city, manager_name=manager).save()
        branches.append(b)

    admin = User(
        name="Paul Mwaura", email="p.mwaura@jafaricredit.co.ke",
        role="super_admin", organization=org,
        assigned_branches=branches,
    )
    admin.set_password("admin123")
    admin.save()

    print("\n[OK] Demo data seeded successfully!")
    print("[MAIL] Login: p.mwaura@jafaricredit.co.ke")
    print("[KEY] Password: admin123\n")


# ------------------------------------------------------------------
# START
# ------------------------------------------------------------------
if __name__ == "__main__":
    print("[BOOT] MongoDB connected")
    seed_demo_data()
    print(f"[RUN] Server running on http://localhost:{PORT}")
    print(f"[SMS] Africa's Talking base URL: {AT_BASE_URL}")
    print(f"[SMS] Configured: {bool(AT_API_KEY)}")
    app.run(host="0.0.0.0", port=PORT, debug=True, use_reloader=False)