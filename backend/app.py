"""
Loan Registry Tracking API + Customer Meeting Report Backend
Auto-bootstraps a super admin on startup.
"""

import os
import io
import csv
import base64
import random
import secrets
import zipfile
import warnings
from datetime import datetime, timedelta, timezone
from functools import wraps

from dotenv import load_dotenv
from flask import Flask, jsonify, request, send_file, Response
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
JWT_SECRET = os.getenv("JWT_SECRET_KEY", "change-me-in-prod")
PORT = int(os.getenv("PORT", 5000))

FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000").rstrip("/")
if FRONTEND_URL.endswith("/index.html"):
    FRONTEND_URL = FRONTEND_URL[: -len("/index.html")]

SUPER_ADMIN_EMAIL = os.getenv("SUPER_ADMIN_EMAIL", "pmwaura@jafaricredit.co.ke")
SUPER_ADMIN_PASSWORD = os.getenv("SUPER_ADMIN_PASSWORD", "admin123")
SUPER_ADMIN_NAME = os.getenv("SUPER_ADMIN_NAME", "Peter Mwaura")
SUPER_ADMIN_ORG = os.getenv("SUPER_ADMIN_ORG", "Jafari Credit")
SUPER_ADMIN_ORG_REG = os.getenv("SUPER_ADMIN_ORG_REG", "REG-JAFARI-001")

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = JWT_SECRET
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=7)
app.config["MAIL_SERVER"] = os.getenv("MAIL_SERVER", "")
app.config["MAIL_PORT"] = int(os.getenv("MAIL_PORT", 587))
app.config["MAIL_USE_TLS"] = os.getenv("MAIL_USE_TLS", "true").lower() == "true"
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME", "")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD", "")
app.config["MAIL_DEFAULT_SENDER"] = os.getenv(
    "MAIL_DEFAULT_SENDER", "noreply@loanregistry.local"
)

CORS(
    app,
    resources={r"/api/*": {
        "origins": "*",
        "methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
    }},
)

jwt = JWTManager(app)
mail = Mail(app)
connect(host=MONGODB_URI)


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


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
            "createdAt": self.created_at.isoformat() if self.created_at else None,
            "updatedAt": self.updated_at.isoformat() if self.updated_at else None,
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
        default="admin_agent",
    )
    organization = ReferenceField(Organization, required=True, reverse_delete_rule=CASCADE)
    assigned_branches = ListField(ReferenceField(Branch))
    is_active = BooleanField(default=True)
    last_login = DateTimeField()
    created_at = DateTimeField(default=utcnow)

    meta = {"collection": "users"}

    def set_password(self, raw):
        self.password_hash = bcrypt.hashpw(raw.strip().encode(), bcrypt.gensalt()).decode()

    def check_password(self, raw):
        if not self.password_hash:
            return False
        try:
            return bcrypt.checkpw(raw.strip().encode(), self.password_hash.encode())
        except Exception:
            return False

    def to_dict(self):
        return {
            "id": str(self.id),
            "_id": str(self.id),
            "name": self.name,
            "email": self.email,
            "role": self.role,
            "organization": self.organization.to_dict() if self.organization else None,
            "assignedBranches": [str(b.id) for b in self.assigned_branches],
            "isActive": self.is_active,
            "hasPassword": bool(self.password_hash),
            "password_set": bool(self.password_hash),
            "status": "active" if self.is_active else "inactive",
            "lastLogin": self.last_login.isoformat() if self.last_login else None,
            "createdAt": self.created_at.isoformat() if self.created_at else None,
        }


class Invitation(Document):
    email = EmailField(required=True)
    token = StringField(required=True, unique=True)
    role = StringField(
        choices=["super_admin", "admin_agent", "branch_manager", "auditor"],
        default="admin_agent",
    )
    organization = ReferenceField(Organization, required=True, reverse_delete_rule=CASCADE)
    invited_by = ReferenceField(User, reverse_delete_rule=NULLIFY)
    assigned_branches = ListField(ReferenceField(Branch))
    status = StringField(
        choices=["pending", "accepted", "revoked", "expired"],
        default="pending",
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
        if exp.tzinfo is not None:
            exp = exp.astimezone(timezone.utc).replace(tzinfo=None)
        return exp > utcnow()

    def to_dict(self):
        return {
            "_id": str(self.id),
            "email": self.email,
            "role": self.role,
            "status": self.status,
            "expiresAt": self.expires_at.isoformat() if self.expires_at else None,
            "acceptedAt": self.accepted_at.isoformat() if self.accepted_at else None,
            "createdAt": self.created_at.isoformat() if self.created_at else None,
            "invitedBy": self.invited_by.name if self.invited_by else None,
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
    currency = StringField(default="USD")
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
            "nextPaymentDate": self.next_payment_date.isoformat() if self.next_payment_date else None,
            "createdAt": self.created_at.isoformat() if self.created_at else None,
            "updatedAt": self.updated_at.isoformat() if self.updated_at else None,
        }


class AuditLog(Document):
    organization = ReferenceField(Organization, required=True, reverse_delete_rule=CASCADE)
    user = ReferenceField(User, reverse_delete_rule=NULLIFY)
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
            "userEmail": self.user.email if self.user else None,
            "ipAddress": self.ip_address,
            "createdAt": self.created_at.isoformat() if self.created_at else None,
            "timestamp": self.created_at.isoformat() if self.created_at else None,
        }


def log_action(user, action, entity_type=None, entity_id=None, details=None):
    try:
        AuditLog(
            organization=user.organization,
            user=user,
            action=action,
            entity_type=entity_type,
            entity_id=str(entity_id) if entity_id else None,
            details=details,
            ip_address=request.remote_addr if request else None,
        ).save()
    except Exception as e:
        print(f"[audit] failed: {e}")


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
        @jwt_required()
        def wrapper(*args, **kwargs):
            user = current_user()
            if not user or not user.is_active:
                return jsonify({"success": False, "message": "User not found or inactive"}), 401
            if user.role not in roles:
                return jsonify({"success": False, "message": "Insufficient permissions"}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def auth_required(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user or not user.is_active:
            return jsonify({"success": False, "message": "User not found or inactive"}), 401
        return fn(*args, **kwargs)
    return wrapper


def parse_date(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


def _send_invite_email(org_name, inviter_name, email, role, accept_url):
    try:
        if not (app.config["MAIL_USERNAME"] and app.config["MAIL_PASSWORD"] and app.config["MAIL_SERVER"]):
            print("[invite] mail not configured; skipping send")
            return False
        msg = Message(
            subject=f"You're invited to {org_name} on Jafari",
            recipients=[email],
            html=f"""
                <p>Hello,</p>
                <p><strong>{inviter_name}</strong> has invited you to join
                <strong>{org_name}</strong> as a
                <strong>{role.replace('_',' ')}</strong>.</p>
                <p><a href="{accept_url}">Accept Invitation</a></p>
                <p>Or paste this link into your browser:<br>{accept_url}</p>
                <p>This invitation expires in 7 days.</p>
            """,
        )
        mail.send(msg)
        return True
    except Exception as e:
        print(f"[invite] mail failed: {e}")
        return False


def _new_invitation_token():
    for _ in range(5):
        t = secrets.token_urlsafe(32)
        if not Invitation.objects(token=t).first():
            return t
    raise RuntimeError("Could not generate unique token")


def _scope_user_query(actor):
    """Return the User queryset appropriate for the actor's role."""
    if actor.role == "super_admin":
        return User.objects
    return User.objects(organization=actor.organization)


# ------------------------------------------------------------------
# HEALTH
# ------------------------------------------------------------------
@app.route("/api/health", methods=["GET", "OPTIONS"])
def health():
    if request.method == "OPTIONS":
        return "", 204
    return jsonify({
        "status": "OK",
        "timestamp": utcnow().isoformat(),
        "frontend_url": FRONTEND_URL,
        "users": User.objects.count(),
        "orgs": Organization.objects.count(),
    })


# ------------------------------------------------------------------
# AUTH
# ------------------------------------------------------------------
@app.route("/api/auth/register", methods=["POST", "OPTIONS"])
def register():
    if request.method == "OPTIONS":
        return "", 204
    data = request.get_json() or {}
    for r in ["name", "email", "password", "organizationId"]:
        if not data.get(r):
            return jsonify({"success": False, "message": f"{r} is required"}), 400
    if User.objects(email=data["email"]).first():
        return jsonify({"success": False, "message": "Email already registered"}), 400
    try:
        org = Organization.objects.get(id=data["organizationId"])
    except Organization.DoesNotExist:
        return jsonify({"success": False, "message": "Organization not found"}), 400
    user = User(
        name=data["name"], email=data["email"],
        role=data.get("role", "admin_agent"), organization=org,
    )
    user.set_password(data["password"])
    user.save()
    token = create_access_token(identity=str(user.id))
    return jsonify({"success": True, "token": token, "user": user.to_dict()}), 201


@app.route("/api/auth/login", methods=["POST", "OPTIONS"])
def login():
    if request.method == "OPTIONS":
        return "", 204
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    password = (data.get("password") or "").strip()
    if not email or not password:
        return jsonify({"success": False, "message": "Email and password required"}), 400
    user = User.objects(email=email).first()
    if not user or not user.check_password(password):
        return jsonify({"success": False, "message": "Invalid credentials"}), 401
    if not user.is_active:
        return jsonify({"success": False, "message": "Account deactivated"}), 403
    user.last_login = utcnow()
    user.save()
    log_action(user, "user.login", "user", user.id)
    token = create_access_token(identity=str(user.id))
    return jsonify({"success": True, "token": token, "user": user.to_dict()})


@app.route("/api/auth/me", methods=["GET", "OPTIONS"])
@auth_required
def me():
    if request.method == "OPTIONS":
        return "", 204
    return jsonify({"success": True, "user": current_user().to_dict()})


# ------------------------------------------------------------------
# INVITATION FLOW
# ------------------------------------------------------------------
@app.route("/api/auth/validate-invitation/<token>", methods=["GET", "OPTIONS"])
def auth_validate_invitation(token):
    if request.method == "OPTIONS":
        return "", 204
    invite = Invitation.objects(token=token).first()
    if not invite:
        return jsonify({"success": False, "error": "Invitation not found"}), 404
    if not invite.is_valid():
        return jsonify({"success": False, "error": "Invitation expired or already used"}), 400
    return jsonify({
        "success": True,
        "email": invite.email,
        "role": invite.role,
        "organization": invite.organization.name if invite.organization else "",
    })


@app.route("/api/auth/setup-password", methods=["POST", "OPTIONS"])
def auth_setup_password():
    if request.method == "OPTIONS":
        return "", 204
    data = request.get_json() or {}
    token = (data.get("token") or "").strip()
    password = (data.get("password") or "").strip()
    confirm = (data.get("confirm_password") or "").strip()
    if not token:
        return jsonify({"success": False, "error": "Missing invitation token"}), 400
    if len(password) < 6:
        return jsonify({"success": False, "error": "Password must be at least 6 characters"}), 400
    if confirm and password != confirm:
        return jsonify({"success": False, "error": "Passwords do not match"}), 400
    invite = Invitation.objects(token=token).first()
    if not invite:
        return jsonify({"success": False, "error": "Invitation not found"}), 404
    if not invite.is_valid():
        return jsonify({"success": False, "error": "Invitation expired or already used"}), 400
    if User.objects(email=invite.email).first():
        return jsonify({"success": False, "error": "A user with this email already exists"}), 400
    default_name = invite.email.split("@")[0].replace(".", " ").replace("_", " ").title()
    user = User(
        name=default_name,
        email=invite.email,
        role=invite.role,
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


@app.route("/api/invitations", methods=["GET", "OPTIONS"])
@role_required("super_admin", "admin_agent")
def list_invitations():
    if request.method == "OPTIONS":
        return "", 204
    user = current_user()
    invites = Invitation.objects(organization=user.organization).order_by("-created_at")
    return jsonify({"success": True, "invitations": [i.to_dict() for i in invites]})


@app.route("/api/invitations", methods=["POST", "OPTIONS"])
@role_required("super_admin", "admin_agent")
def create_invitation():
    if request.method == "OPTIONS":
        return "", 204
    user = current_user()
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    role = data.get("role", "admin_agent")
    if not email:
        return jsonify({"success": False, "message": "Email is required"}), 400
    if role not in ["super_admin", "admin_agent", "branch_manager", "auditor"]:
        return jsonify({"success": False, "message": "Invalid role"}), 400
    if User.objects(email=email).first():
        return jsonify({"success": False, "message": "A user with this email already exists"}), 400
    if Invitation.objects(organization=user.organization, email=email, status="pending").first():
        return jsonify({"success": False, "message": "Pending invitation already exists"}), 400
    token = _new_invitation_token()
    invite = Invitation(
        email=email, token=token, role=role,
        organization=user.organization, invited_by=user,
        expires_at=utcnow() + timedelta(days=7),
    ).save()
    accept_url = f"{FRONTEND_URL}/?invite={token}"
    emailed = _send_invite_email(user.organization.name, user.name, email, role, accept_url)
    log_action(user, "invitation.create", "invitation", invite.id, f"email={email}, role={role}")
    return jsonify({
        "success": True,
        "invitation": invite.to_dict(),
        "acceptUrl": accept_url,
        "invitation_link": accept_url,
        "emailed": emailed,
    }), 201


@app.route("/api/invitations/<invite_id>", methods=["DELETE", "OPTIONS"])
@role_required("super_admin", "admin_agent")
def revoke_invitation(invite_id):
    if request.method == "OPTIONS":
        return "", 204
    user = current_user()
    try:
        invite = Invitation.objects.get(id=invite_id, organization=user.organization)
    except Invitation.DoesNotExist:
        return jsonify({"success": False, "message": "Invitation not found"}), 404
    invite.status = "revoked"
    invite.save()
    log_action(user, "invitation.revoke", "invitation", invite.id)
    return jsonify({"success": True, "message": "Invitation revoked"})


@app.route("/api/auth/resend-invitation", methods=["POST", "OPTIONS"])
@role_required("super_admin", "admin_agent")
def resend_invitation():
    if request.method == "OPTIONS":
        return "", 204
    actor = current_user()
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    if not email:
        return jsonify({"success": False, "error": "Email required"}), 400
    Invitation.objects(organization=actor.organization, email=email, status="pending").update(set__status="revoked")
    token = _new_invitation_token()
    invite = Invitation(
        email=email, token=token, role="admin_agent",
        organization=actor.organization, invited_by=actor,
        expires_at=utcnow() + timedelta(days=7),
    ).save()
    link = f"{FRONTEND_URL}/?invite={token}"
    _send_invite_email(actor.organization.name, actor.name, email, "admin_agent", link)
    return jsonify({"success": True, "invitation_link": link})


# ------------------------------------------------------------------
# ADMIN USER MANAGEMENT
# ------------------------------------------------------------------
@app.route("/api/admin/users", methods=["GET", "OPTIONS"])
@role_required("super_admin", "admin_agent", "auditor")
def admin_list_users():
    if request.method == "OPTIONS":
        return "", 204
    user = current_user()
    if not user:
        return jsonify({"success": False, "error": "Not authenticated"}), 401

    if user.role == "super_admin":
        users = list(User.objects.order_by("name"))
    else:
        users = list(User.objects(organization=user.organization).order_by("name"))

    data = []
    for u in users:
        try:
            data.append(u.to_dict())
        except Exception as e:
            print(f"[admin_list_users] to_dict failed for {u.email}: {e}")

    print(f"[admin_list_users] {user.email} (role={user.role}) -> {len(data)} users")
    return jsonify({"success": True, "data": data, "users": data})


@app.route("/api/admin/users", methods=["POST", "OPTIONS"])
@role_required("super_admin", "admin_agent")
def admin_create_user():
    if request.method == "OPTIONS":
        return "", 204
    actor = current_user()
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    role = data.get("role", "admin_agent")
    name = (data.get("name") or "").strip()
    if not email:
        return jsonify({"success": False, "error": "Email required"}), 400
    if role not in ["super_admin", "admin_agent", "branch_manager", "auditor"]:
        return jsonify({"success": False, "error": "Invalid role"}), 400
    if User.objects(email=email).first():
        return jsonify({"success": False, "error": "User already exists"}), 400
    Invitation.objects(organization=actor.organization, email=email, status="pending").update(set__status="revoked")
    token = _new_invitation_token()
    invite = Invitation(
        email=email, token=token, role=role,
        organization=actor.organization, invited_by=actor,
        expires_at=utcnow() + timedelta(days=7),
    ).save()
    link = f"{FRONTEND_URL}/?invite={token}"
    emailed = _send_invite_email(actor.organization.name, name or actor.name, email, role, link)
    log_action(actor, "invitation.create", "invitation", invite.id, f"email={email}")
    return jsonify({
        "success": True,
        "message": "Invitation created",
        "invitation_link": link,
        "emailed": emailed,
    }), 201


@app.route("/api/admin/users/<path:email>", methods=["DELETE", "OPTIONS"])
@role_required("super_admin", "admin_agent")
def admin_delete_user(email):
    if request.method == "OPTIONS":
        return "", 204
    actor = current_user()
    try:
        if actor.role == "super_admin":
            target = User.objects.get(email=email)
        else:
            target = User.objects.get(email=email, organization=actor.organization)
    except User.DoesNotExist:
        return jsonify({"success": False, "error": "User not found"}), 404
    if target.id == actor.id:
        return jsonify({"success": False, "error": "Cannot delete yourself"}), 400
    target.delete()
    log_action(actor, "user.delete", "user", None, f"email={email}")
    return jsonify({"success": True, "message": "User removed"})


@app.route("/api/admin/users/<path:email>/toggle-status", methods=["POST", "OPTIONS"])
@role_required("super_admin", "admin_agent")
def admin_toggle_user(email):
    if request.method == "OPTIONS":
        return "", 204
    actor = current_user()
    try:
        if actor.role == "super_admin":
            target = User.objects.get(email=email)
        else:
            target = User.objects.get(email=email, organization=actor.organization)
    except User.DoesNotExist:
        return jsonify({"success": False, "error": "User not found"}), 404
    target.is_active = not target.is_active
    target.save()
    return jsonify({
        "success": True,
        "message": f"User {'activated' if target.is_active else 'deactivated'}",
    })


@app.route("/api/admin/users/<path:email>/reset-password", methods=["POST", "OPTIONS"])
@role_required("super_admin", "admin_agent")
def admin_reset_password(email):
    if request.method == "OPTIONS":
        return "", 204
    actor = current_user()
    Invitation.objects(organization=actor.organization, email=email, status="pending").update(set__status="revoked")
    token = _new_invitation_token()
    invite = Invitation(
        email=email, token=token, role="admin_agent",
        organization=actor.organization, invited_by=actor,
        expires_at=utcnow() + timedelta(days=7),
    ).save()
    link = f"{FRONTEND_URL}/?invite={token}"
    _send_invite_email(actor.organization.name, actor.name, email, "admin_agent", link)
    return jsonify({"success": True, "invitation_link": link})


# ------------------------------------------------------------------
# AUDIT LOG
# ------------------------------------------------------------------
@app.route("/api/audit", methods=["GET", "OPTIONS"])
@role_required("super_admin", "admin_agent", "auditor")
def list_audit():
    if request.method == "OPTIONS":
        return "", 204
    user = current_user()
    limit = int(request.args.get("limit", 100))
    logs = AuditLog.objects(organization=user.organization).order_by("-created_at").limit(limit)
    return jsonify({"success": True, "logs": [l.to_dict() for l in logs]})


@app.route("/api/admin/audit-log", methods=["GET", "OPTIONS"])
@role_required("super_admin", "admin_agent", "auditor")
def admin_audit_log():
    if request.method == "OPTIONS":
        return "", 204
    user = current_user()
    if user.role == "super_admin":
        qs = AuditLog.objects
    else:
        qs = AuditLog.objects(organization=user.organization)

    user_email = request.args.get("user_email")
    if user_email:
        u = User.objects(email=user_email).first()
        qs = qs.filter(user=u) if u else qs.filter(id=None)
    start_date = request.args.get("start_date")
    if start_date:
        d = parse_date(start_date)
        if d:
            qs = qs.filter(created_at__gte=d)
    end_date = request.args.get("end_date")
    if end_date:
        d = parse_date(end_date)
        if d:
            qs = qs.filter(created_at__lte=d)
    limit = int(request.args.get("limit", 500))
    logs = qs.order_by("-created_at").limit(limit)
    data = []
    for l in logs:
        d = l.to_dict()
        d.update({
            "generated_by_name": d.get("userName"),
            "generated_by_email": d.get("userEmail"),
            "verification_level": "unverified",
            "has_team_leader_sig": False,
            "has_agent_sig": False,
            "has_customer_sig": False,
            "has_selfie": False,
            "otp_verified": False,
        })
        data.append(d)
    return jsonify({"success": True, "data": data, "logs": data})


@app.route("/api/admin/audit-log/<log_id>", methods=["DELETE", "OPTIONS"])
@role_required("super_admin", "admin_agent")
def admin_delete_audit(log_id):
    if request.method == "OPTIONS":
        return "", 204
    user = current_user()
    try:
        log = AuditLog.objects.get(id=log_id)
    except AuditLog.DoesNotExist:
        return jsonify({"success": False, "error": "Not found"}), 404
    if user.role != "super_admin" and log.organization and log.organization.id != user.organization.id:
        return jsonify({"success": False, "error": "Forbidden"}), 403
    log.delete()
    return jsonify({"success": True})


@app.route("/api/admin/audit-log/export", methods=["GET", "OPTIONS"])
@role_required("super_admin", "admin_agent", "auditor")
def admin_export_audit():
    if request.method == "OPTIONS":
        return "", 204
    user = current_user()
    if user.role == "super_admin":
        logs = AuditLog.objects.order_by("-created_at")
    else:
        logs = AuditLog.objects(organization=user.organization).order_by("-created_at")
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Timestamp", "User", "Email", "Action", "Entity", "Entity ID", "Details"])
    count = 0
    for l in logs:
        w.writerow([
            l.created_at.isoformat() if l.created_at else "",
            l.user.name if l.user else "System",
            l.user.email if l.user else "",
            l.action, l.entity_type or "", l.entity_id or "", l.details or "",
        ])
        count += 1
    encoded = base64.b64encode(buf.getvalue().encode()).decode()
    filename = f"audit-log-{datetime.now().strftime('%Y%m%d-%H%M%S')}.csv"
    return jsonify({"success": True, "csv": encoded, "filename": filename, "count": count})


# ------------------------------------------------------------------
# OTP
# ------------------------------------------------------------------
_otp_store = {}


@app.route("/api/otp/send", methods=["POST", "OPTIONS"])
@auth_required
def otp_send():
    if request.method == "OPTIONS":
        return "", 204
    data = request.get_json() or {}
    phone = (data.get("phone") or "").strip()
    if not phone:
        return jsonify({"success": False, "error": "Phone required"}), 400
    code = f"{random.randint(0, 999999):06d}"
    _otp_store[phone] = {
        "code": code,
        "expires": utcnow() + timedelta(minutes=10),
        "verified": False,
        "token": None,
    }
    print(f"[OTP] {phone} -> {code}")
    is_admin = current_user().role in ("super_admin", "admin_agent")
    resp = {"success": True, "message": f"Code sent to {phone}", "expiresInMinutes": 10}
    if is_admin:
        resp["devCode"] = code
    return jsonify(resp)


@app.route("/api/otp/verify", methods=["POST", "OPTIONS"])
@auth_required
def otp_verify():
    if request.method == "OPTIONS":
        return "", 204
    data = request.get_json() or {}
    phone = (data.get("phone") or "").strip()
    code = (data.get("code") or "").strip()
    rec = _otp_store.get(phone)
    if not rec:
        return jsonify({"success": False, "error": "No code sent to this number"}), 400
    if utcnow() > rec["expires"]:
        return jsonify({"success": False, "error": "Code expired"}), 400
    if rec["code"] != code:
        return jsonify({"success": False, "error": "Invalid code"}), 400
    rec["verified"] = True
    rec["token"] = secrets.token_urlsafe(24)
    return jsonify({
        "success": True,
        "phone": phone,
        "verificationToken": rec["token"],
        "verifiedAt": utcnow().isoformat() + "Z",
    })


# ------------------------------------------------------------------
# REPORT GENERATION
# ------------------------------------------------------------------
def _build_meeting_report_pdf(data):
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=LETTER, leftMargin=40, rightMargin=40, topMargin=40, bottomMargin=40)
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("H1", parent=styles["Heading1"], fontSize=18, textColor=colors.HexColor("#123b72"))
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=11, textColor=colors.HexColor("#334155"))
    body = styles["BodyText"]
    el = []
    el.append(Paragraph("Customer Meeting Report", h1))
    el.append(Paragraph(f"Report ID: <b>{data.get('report_id','-')}</b>", body))
    el.append(Spacer(1, 10))

    def section(title, pairs):
        el.append(Paragraph(title, h2))
        rows = [[k, str(v) if v else "-"] for k, v in pairs]
        t = Table(rows, colWidths=[160, 340])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
        ]))
        el.append(t)
        el.append(Spacer(1, 10))

    section("Officer", [
        ("Name", data.get("created_by")),
        ("Role", data.get("user_role")),
        ("Agent Code", data.get("agent_code")),
        ("Branch", data.get("branch")),
        ("Meeting", data.get("meeting_datetime")),
    ])
    section("Customer", [
        ("Name", data.get("customer_name")),
        ("Customer No", data.get("customer_id")),
        ("ID No", data.get("customer_id_no")),
        ("Phone", data.get("customer_phone")),
        ("Email", data.get("customer_email")),
    ])
    section("Loan", [
        ("Product", data.get("loan_product")),
        ("Amount (KES)", data.get("loan_amount")),
        ("KYC Status", data.get("kyc_status")),
    ])
    section("Verification", [
        ("OTP Verified", "Yes" if data.get("otp_verified") else "No"),
        ("Selfie", "Yes" if data.get("selfie_image") else "No"),
        ("GPS", data.get("gps_locator") or "-"),
        ("Unverified reason", data.get("unverified_reason") or "-"),
    ])
    section("Discussion", [("Summary", data.get("discussion_summary") or "-")])
    doc.build(el)
    buf.seek(0)
    return buf.read()


def _compute_verification_level(data):
    if data.get("otp_verified") and data.get("selfie_image") and data.get("customer_signature_image"):
        return "full"
    if data.get("otp_verified") or data.get("selfie_image") or data.get("customer_signature_image"):
        return "partial"
    return "unverified"


def _compute_payload_hash(data):
    import hashlib, json as _json
    raw = _json.dumps(data, sort_keys=True, default=str).encode()
    return hashlib.sha256(raw).hexdigest()


@app.route("/api/generate", methods=["POST", "OPTIONS"])
@auth_required
def generate_report():
    if request.method == "OPTIONS":
        return "", 204
    data = request.get_json() or {}
    try:
        pdf_bytes = _build_meeting_report_pdf(data)
    except Exception as e:
        return jsonify({"success": False, "error": f"PDF build failed: {e}"}), 500
    b64 = base64.b64encode(pdf_bytes).decode()
    return jsonify({
        "success": True,
        "pdf": b64,
        "filename": f"report-{data.get('report_id', 'draft')}.pdf",
        "verification_level": _compute_verification_level(data),
        "payload_hash": _compute_payload_hash(data),
    })


@app.route("/api/generate-batch", methods=["POST", "OPTIONS"])
@auth_required
def generate_batch():
    if request.method == "OPTIONS":
        return "", 204
    data = request.get_json() or {}
    reports = data.get("reports", [])
    if not reports:
        return jsonify({"success": False, "error": "No reports"}), 400
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for r in reports:
            pdf_bytes = _build_meeting_report_pdf(r)
            zf.writestr(f"report-{r.get('report_id', 'draft')}.pdf", pdf_bytes)
    buf.seek(0)
    b64 = base64.b64encode(buf.read()).decode()
    return jsonify({
        "success": True,
        "zip": b64,
        "filename": f"reports-{datetime.now().strftime('%Y%m%d-%H%M%S')}.zip",
        "count": len(reports),
    })


# ------------------------------------------------------------------
# BRANCHES
# ------------------------------------------------------------------
@app.route("/api/branches", methods=["GET", "OPTIONS"])
@auth_required
def list_branches():
    if request.method == "OPTIONS":
        return "", 204
    user = current_user()
    if user.role == "super_admin":
        branches = Branch.objects(is_active=True).order_by("name")
    else:
        branches = Branch.objects(organization=user.organization, is_active=True).order_by("name")
    return jsonify({"success": True, "branches": [b.to_dict() for b in branches]})


# ------------------------------------------------------------------
# DASHBOARD (uses loans scoped to actor's org / all for super_admin)
# ------------------------------------------------------------------
@app.route("/api/dashboard/stats", methods=["GET", "OPTIONS"])
@auth_required
def dashboard_stats():
    if request.method == "OPTIONS":
        return "", 204
    user = current_user()
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


@app.route("/api/dashboard/recent-loans", methods=["GET", "OPTIONS"])
@auth_required
def recent_loans():
    if request.method == "OPTIONS":
        return "", 204
    user = current_user()
    qs = Loan.objects() if user.role == "super_admin" else Loan.objects(organization=user.organization)
    loans = qs.order_by("-created_at").limit(10)
    return jsonify({"success": True, "loans": [l.to_dict() for l in loans]})


# ------------------------------------------------------------------
# ERROR HANDLERS
# ------------------------------------------------------------------
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
# AUTO-BOOTSTRAP (runs on import — covers gunicorn, uwsgi, etc.)
# ------------------------------------------------------------------
def ensure_super_admin():
    """
    Idempotent:
      - Ensures the Jafari Credit org exists
      - Ensures SUPER_ADMIN_EMAIL exists as super_admin with SUPER_ADMIN_PASSWORD
      - Refreshes password on every boot so we're never locked out
    """
    org = Organization.objects(registration_number=SUPER_ADMIN_ORG_REG).first()
    if not org:
        org = Organization(
            name=SUPER_ADMIN_ORG,
            registration_number=SUPER_ADMIN_ORG_REG,
            license_number="LIC-JAFARI-001",
            address="Nairobi, Kenya",
            contact_email=SUPER_ADMIN_EMAIL,
            is_active=True,
        ).save()
        print(f"[BOOT] Created organization: {org.name}")

    existing = User.objects(email=SUPER_ADMIN_EMAIL).first()
    if existing:
        existing.set_password(SUPER_ADMIN_PASSWORD)
        existing.role = "super_admin"
        existing.is_active = True
        existing.organization = org
        existing.save()
        print(f"[BOOT] Super admin refreshed: {existing.email}")
    else:
        user = User(
            name=SUPER_ADMIN_NAME,
            email=SUPER_ADMIN_EMAIL,
            role="super_admin",
            organization=org,
            is_active=True,
        )
        user.set_password(SUPER_ADMIN_PASSWORD)
        user.save()
        print(f"[BOOT] Super admin created: {user.email}")


try:
    ensure_super_admin()
except Exception as e:
    print(f"[BOOT] ensure_super_admin failed: {e}")


# ------------------------------------------------------------------
# MAIN
# ------------------------------------------------------------------
if __name__ == "__main__":
    print("[BOOT] MongoDB connected")
    print(f"[BOOT] FRONTEND_URL = {FRONTEND_URL}")
    print(f"[RUN] Server on http://0.0.0.0:{PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False)