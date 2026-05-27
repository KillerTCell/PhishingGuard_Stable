"""Demo seed data for PhishGuard capstone demonstration (Section 9 Phase 3G).

Run via:
    cd backend && python app/seed.py
    # or
    make seed

Creates:
    - 1 Organisation (Demo University)
    - 2 Users (admin + analyst)
    - 5 Emails (2 phishing/quarantined, 2 safe/delivered, 1 suspicious/flagged)
    - 5 AnalysisResult rows with realistic features
    - 5 × 7 EmailFeature rows (one per feature extractor per email)
    - 2 Feedback records (confirm phishing + safe release)
    - 3 AuditLog entries (login_success × 2, threshold_changed × 1)

Idempotent: skips insertion if Demo University already exists.
"""
from __future__ import annotations

import asyncio
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Ensure backend/ is on sys.path so `app` imports resolve when run as a script.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import bcrypt
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from app.core.config import settings
from app.models.analysis_result import AnalysisResult
from app.models.audit_log import AuditLog
from app.models.email import Email
from app.models.email_feature import EmailFeature
from app.models.feedback import Feedback
from app.models.organisation import Organisation
from app.models.user import User

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_PASSWORD = "PhishGuard2026!"
_MODEL_VERSION = "rf_v1.0.0"

_NOW = datetime.now(timezone.utc)


def _ago(**kwargs: int) -> datetime:
    return _NOW - timedelta(**kwargs)


def _hash(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()


# ---------------------------------------------------------------------------
# Feature helpers
# ---------------------------------------------------------------------------

def _features(
    email_id: uuid.UUID,
    *,
    urgency: float = 0.0,
    credential: float = 0.0,
    link_mismatch: float = 0.0,
    impersonation: float = 0.0,
    auth_failure: float = 0.0,
    grammar: float = 0.0,
    known_bad_url: float = 0.0,
) -> list[EmailFeature]:
    """Build the 7 standardised EmailFeature rows for one email."""
    specs = [
        ("urgency_language", urgency, urgency > 0),
        ("credential_request", credential, credential > 0),
        ("link_mismatch", link_mismatch, {"displayed": "paypal.com", "actual": "paypa1-secure.ru"} if link_mismatch else False),
        ("impersonation_language", impersonation, impersonation > 0),
        ("auth_failure", auth_failure, auth_failure > 0),
        ("grammar_quality", grammar, grammar if grammar else 1.0),
        ("known_bad_url", known_bad_url, known_bad_url > 0),
    ]
    rows = []
    for name, score, value in specs:
        fv: object
        if isinstance(value, dict):
            fv = value
        elif isinstance(value, bool) and value:
            fv = 1
        elif isinstance(value, bool):
            fv = 0
        else:
            fv = value
        rows.append(
            EmailFeature(
                email_id=email_id,
                feature_name=name,
                feature_value=fv,
                score_contribution=round(score, 4),
            )
        )
    return rows


# ---------------------------------------------------------------------------
# Main seeder
# ---------------------------------------------------------------------------

async def seed() -> None:
    engine = create_async_engine(settings.DATABASE_URL, echo=False)
    async with AsyncSession(engine) as db:
        # ── Idempotency guard ─────────────────────────────────────────────
        existing = await db.scalar(
            select(Organisation).where(Organisation.name == "Demo University")
        )
        if existing is not None:
            print("Seed data already present (Demo University exists) — skipping.")
            await engine.dispose()
            return

        print("Seeding demo data …")

        # ── Organisation ─────────────────────────────────────────────────
        org_id = uuid.uuid4()
        org = Organisation(
            id=org_id,
            name="Demo University",
            suspicious_threshold=30,
            phishing_threshold=60,
            auto_quarantine_high_risk=True,
            prepend_subject_warning=True,
            connector_status="unconfigured",
            data_retention_days=90,
        )
        db.add(org)
        await db.flush()

        # ── Users ────────────────────────────────────────────────────────
        admin_id = uuid.uuid4()
        admin = User(
            id=admin_id,
            org_id=org_id,
            full_name="Admin User",
            email="admin@demo.edu",
            password_hash=_hash(_PASSWORD),
            role="admin",
            is_active=True,
            last_active_at=_ago(minutes=5),
        )
        db.add(admin)

        analyst_id = uuid.uuid4()
        analyst = User(
            id=analyst_id,
            org_id=org_id,
            full_name="Analyst User",
            email="analyst@demo.edu",
            password_hash=_hash(_PASSWORD),
            role="analyst",
            is_active=True,
            last_active_at=_ago(hours=1),
        )
        db.add(analyst)
        await db.flush()

        # ── Emails ───────────────────────────────────────────────────────
        # 1. Phishing — credential harvest (quarantined, high confidence)
        e1_id = uuid.uuid4()
        e1 = Email(
            id=e1_id,
            org_id=org_id,
            sender="security-noreply@paypa1-secure.ru",
            reply_to="harvest@paypa1-secure.ru",
            recipient_address="staff@demo.edu",
            subject="URGENT: Your PayPal account has been suspended — verify now",
            body_text=(
                "Dear Valued Customer,\n\n"
                "Your PayPal account has been SUSPENDED due to suspicious activity. "
                "Click the link below IMMEDIATELY to restore access or your account "
                "will be permanently closed within 24 hours.\n\n"
                "Verify Account: http://paypa1-secure.ru/login?token=a9f3c2\n\n"
                "PayPal Security Team"
            ),
            html_sanitised=(
                "<p>Dear Valued Customer,</p>"
                "<p>Your PayPal account has been <strong>SUSPENDED</strong> due to "
                "suspicious activity.</p>"
                "<p><a href='http://paypa1-secure.ru/login?token=a9f3c2'>Verify Account</a></p>"
            ),
            links=[
                {
                    "displayed_text": "Verify Account",
                    "actual_href": "http://paypa1-secure.ru/login?token=a9f3c2",
                    "is_mismatch": True,
                }
            ],
            attachment_metadata=[],
            spf="fail",
            dkim="fail",
            dmarc="fail",
            received_at=_ago(hours=3),
            status="quarantined",
            ingestion_source="upload",
            added_to_training=False,
        )
        db.add(e1)

        # 2. Phishing — executive impersonation (quarantined)
        e2_id = uuid.uuid4()
        e2 = Email(
            id=e2_id,
            org_id=org_id,
            sender="ceo-office@demo-edu.net",
            reply_to="cfo-urgent@gmail.com",
            recipient_address="finance@demo.edu",
            subject="Urgent wire transfer request — confidential",
            body_text=(
                "Hi,\n\n"
                "I'm in a board meeting and need you to process an urgent wire transfer "
                "of $45,000 to our new vendor before close of business today. "
                "This is time-sensitive — please action immediately and confirm by reply.\n\n"
                "Do not discuss this with anyone else until it is processed.\n\n"
                "Thanks,\nDr. James Harrison\nVice-Chancellor, Demo University"
            ),
            html_sanitised=(
                "<p>Hi,</p><p>I&#x27;m in a board meeting and need you to process "
                "an urgent wire transfer of $45,000 to our new vendor before close "
                "of business today.</p><p>Thanks,<br>Dr. James Harrison<br>"
                "Vice-Chancellor, Demo University</p>"
            ),
            links=[],
            attachment_metadata=[],
            spf="fail",
            dkim="none",
            dmarc="fail",
            received_at=_ago(hours=6),
            status="quarantined",
            ingestion_source="imap",
            added_to_training=True,
        )
        db.add(e2)

        # 3. Safe — internal IT newsletter (delivered)
        e3_id = uuid.uuid4()
        e3 = Email(
            id=e3_id,
            org_id=org_id,
            sender="it-helpdesk@demo.edu",
            reply_to=None,
            recipient_address="all-staff@demo.edu",
            subject="IT Newsletter — May 2026: New VPN client available",
            body_text=(
                "Dear Staff,\n\n"
                "We are pleased to announce that the new GlobalProtect VPN client "
                "(version 6.2) is now available via the Software Centre. Please update "
                "at your convenience over the next two weeks.\n\n"
                "If you have any questions, contact the IT Help Desk at ext. 4400.\n\n"
                "Kind regards,\nIT Services, Demo University"
            ),
            html_sanitised=(
                "<p>Dear Staff,</p><p>We are pleased to announce that the new "
                "GlobalProtect VPN client is now available via the Software Centre.</p>"
                "<p>Kind regards,<br>IT Services, Demo University</p>"
            ),
            links=[
                {
                    "displayed_text": "Software Centre",
                    "actual_href": "https://software.demo.edu/vpn",
                    "is_mismatch": False,
                }
            ],
            attachment_metadata=[],
            spf="pass",
            dkim="pass",
            dmarc="pass",
            received_at=_ago(days=1),
            status="delivered",
            ingestion_source="imap",
            added_to_training=False,
        )
        db.add(e3)

        # 4. Safe — conference registration confirmation (delivered)
        e4_id = uuid.uuid4()
        e4 = Email(
            id=e4_id,
            org_id=org_id,
            sender="noreply@acm.org",
            reply_to=None,
            recipient_address="researcher@demo.edu",
            subject="Your registration for ACM CCS 2026 is confirmed",
            body_text=(
                "Dear Researcher,\n\n"
                "Thank you for registering for ACM CCS 2026 (November 14-18, Dallas TX). "
                "Your registration ID is REG-20261109-4872.\n\n"
                "Please retain this email as your booking confirmation. "
                "Hotel and travel information will be sent separately.\n\n"
                "ACM Conference Services"
            ),
            html_sanitised=(
                "<p>Dear Researcher,</p><p>Thank you for registering for ACM CCS 2026. "
                "Your registration ID is <strong>REG-20261109-4872</strong>.</p>"
                "<p>ACM Conference Services</p>"
            ),
            links=[],
            attachment_metadata=[{"filename": "registration_confirmation.pdf", "size": 87432, "mime_type": "application/pdf"}],
            spf="pass",
            dkim="pass",
            dmarc="pass",
            received_at=_ago(days=2),
            status="delivered",
            ingestion_source="imap",
            added_to_training=False,
        )
        db.add(e4)

        # 5. Suspicious — ambiguous marketing (flagged)
        e5_id = uuid.uuid4()
        e5 = Email(
            id=e5_id,
            org_id=org_id,
            sender="offers@edu-software-deals.com",
            reply_to="sales@edu-software-deals.com",
            recipient_address="procurement@demo.edu",
            subject="Exclusive offer: 70% off Microsoft 365 licenses — limited time",
            body_text=(
                "Hello,\n\n"
                "We have secured an exclusive batch of Microsoft 365 Education licenses "
                "at 70% below RRP for a limited window. Act now — only 50 seats remaining!\n\n"
                "To claim your discount, click the link below and enter your institutional "
                "email address to verify eligibility.\n\n"
                "Claim offer: https://edu-software-deals.com/ms365-claim?ref=DU2026\n\n"
                "Best,\nEdu Software Deals"
            ),
            html_sanitised=(
                "<p>Hello,</p><p>We have secured an exclusive batch of Microsoft 365 "
                "Education licenses at 70% below RRP for a limited window.</p>"
                "<p><a href='https://edu-software-deals.com/ms365-claim?ref=DU2026'>"
                "Claim offer</a></p>"
            ),
            links=[
                {
                    "displayed_text": "Claim offer",
                    "actual_href": "https://edu-software-deals.com/ms365-claim?ref=DU2026",
                    "is_mismatch": False,
                }
            ],
            attachment_metadata=[],
            spf="pass",
            dkim="fail",
            dmarc="none",
            received_at=_ago(hours=12),
            status="flagged",
            ingestion_source="upload",
            added_to_training=False,
        )
        db.add(e5)
        await db.flush()

        # ── AnalysisResult rows ───────────────────────────────────────────
        top_phishing_features = [
            {"name": "auth_failure", "value": 1, "score_contribution": 0.45},
            {"name": "link_mismatch", "value": {"displayed": "paypal.com", "actual": "paypa1-secure.ru"}, "score_contribution": 0.35},
            {"name": "urgency_language", "value": 1, "score_contribution": 0.20},
        ]
        top_exec_features = [
            {"name": "impersonation_language", "value": 1, "score_contribution": 0.50},
            {"name": "urgency_language", "value": 1, "score_contribution": 0.30},
            {"name": "auth_failure", "value": 1, "score_contribution": 0.20},
        ]
        top_safe_features = [
            {"name": "grammar_quality", "value": 0.98, "score_contribution": 0.0},
            {"name": "auth_failure", "value": 0, "score_contribution": 0.0},
            {"name": "urgency_language", "value": 0, "score_contribution": 0.0},
        ]
        top_suspicious_features = [
            {"name": "urgency_language", "value": 1, "score_contribution": 0.35},
            {"name": "credential_request", "value": 1, "score_contribution": 0.25},
            {"name": "auth_failure", "value": 1, "score_contribution": 0.20},
        ]

        ar1 = AnalysisResult(
            id=uuid.uuid4(),
            email_id=e1_id,
            classification="phishing",
            risk_score=94,
            model_version=_MODEL_VERSION,
            threshold_applied_suspicious=30,
            threshold_applied_phishing=60,
            explanation=(
                "This email exhibits multiple high-confidence phishing indicators: "
                "the sender domain (paypa1-secure.ru) impersonates PayPal using a "
                "lookalike spelling, SPF/DKIM/DMARC all fail, and the embedded link "
                "redirects to a known credential-harvesting domain. The urgency "
                "language ('IMMEDIATELY', '24 hours') is a classic social engineering tactic."
            ),
            top_features=top_phishing_features,
            quarantined=True,
        )
        db.add(ar1)

        ar2 = AnalysisResult(
            id=uuid.uuid4(),
            email_id=e2_id,
            classification="phishing",
            risk_score=88,
            model_version=_MODEL_VERSION,
            threshold_applied_suspicious=30,
            threshold_applied_phishing=60,
            explanation=(
                "This is a business email compromise (BEC) attempt impersonating the "
                "Vice-Chancellor. The sender domain (demo-edu.net) differs from the "
                "legitimate organisational domain (demo.edu), and the reply-to address "
                "routes to a free Gmail account. The request for an urgent, confidential "
                "wire transfer is a hallmark of executive impersonation fraud."
            ),
            top_features=top_exec_features,
            quarantined=True,
        )
        db.add(ar2)

        ar3 = AnalysisResult(
            id=uuid.uuid4(),
            email_id=e3_id,
            classification="safe",
            risk_score=4,
            model_version=_MODEL_VERSION,
            threshold_applied_suspicious=30,
            threshold_applied_phishing=60,
            explanation=(
                "This email originates from an authenticated internal domain with "
                "passing SPF, DKIM, and DMARC records. The content is a routine IT "
                "newsletter containing no credential requests, urgency language, or "
                "suspicious links. Classified as safe with high confidence."
            ),
            top_features=top_safe_features,
            quarantined=False,
        )
        db.add(ar3)

        ar4 = AnalysisResult(
            id=uuid.uuid4(),
            email_id=e4_id,
            classification="safe",
            risk_score=2,
            model_version=_MODEL_VERSION,
            threshold_applied_suspicious=30,
            threshold_applied_phishing=60,
            explanation=(
                "Transactional confirmation email from a known academic conference "
                "body (acm.org) with full email authentication passing. No phishing "
                "indicators detected. The attached PDF is a standard booking confirmation."
            ),
            top_features=top_safe_features,
            quarantined=False,
        )
        db.add(ar4)

        ar5 = AnalysisResult(
            id=uuid.uuid4(),
            email_id=e5_id,
            classification="suspicious",
            risk_score=52,
            model_version=_MODEL_VERSION,
            threshold_applied_suspicious=30,
            threshold_applied_phishing=60,
            explanation=(
                "This email uses urgency language ('limited time', 'act now') and "
                "requests the recipient to enter their institutional email address on "
                "an external site. DKIM fails on a domain with no prior send history. "
                "While it may be a legitimate vendor, the combination of factors "
                "warrants human review before delivery."
            ),
            top_features=top_suspicious_features,
            quarantined=False,
        )
        db.add(ar5)
        await db.flush()

        # ── EmailFeature rows (7 per email × 5 emails = 35 rows) ─────────
        for feature in _features(
            e1_id,
            urgency=0.20, credential=0.15, link_mismatch=0.35,
            impersonation=0.10, auth_failure=0.45, grammar=0.05, known_bad_url=0.30,
        ):
            db.add(feature)

        for feature in _features(
            e2_id,
            urgency=0.30, credential=0.10, link_mismatch=0.0,
            impersonation=0.50, auth_failure=0.20, grammar=0.02, known_bad_url=0.0,
        ):
            db.add(feature)

        for feature in _features(
            e3_id,
            urgency=0.0, credential=0.0, link_mismatch=0.0,
            impersonation=0.0, auth_failure=0.0, grammar=0.0, known_bad_url=0.0,
        ):
            db.add(feature)

        for feature in _features(
            e4_id,
            urgency=0.0, credential=0.0, link_mismatch=0.0,
            impersonation=0.0, auth_failure=0.0, grammar=0.0, known_bad_url=0.0,
        ):
            db.add(feature)

        for feature in _features(
            e5_id,
            urgency=0.35, credential=0.25, link_mismatch=0.0,
            impersonation=0.05, auth_failure=0.20, grammar=0.08, known_bad_url=0.0,
        ):
            db.add(feature)

        await db.flush()

        # ── Feedback records ─────────────────────────────────────────────
        # 1. Analyst confirms e1 (PayPal) as phishing
        db.add(
            Feedback(
                id=uuid.uuid4(),
                email_id=e1_id,
                user_id=analyst_id,
                label="phishing",
                source="dashboard",
            )
        )
        # 2. Analyst marks e3 (IT newsletter) as safe
        db.add(
            Feedback(
                id=uuid.uuid4(),
                email_id=e3_id,
                user_id=analyst_id,
                label="safe",
                source="dashboard",
            )
        )
        await db.flush()

        # ── Audit log entries ─────────────────────────────────────────────
        # 1. Admin login
        db.add(
            AuditLog(
                org_id=org_id,
                user_id=admin_id,
                action="login_success",
                target_type="user",
                target_id=admin_id,
                detail={"email": "admin@demo.edu"},
                ip_address="192.168.1.10",
            )
        )
        # 2. Analyst login
        db.add(
            AuditLog(
                org_id=org_id,
                user_id=analyst_id,
                action="login_success",
                target_type="user",
                target_id=analyst_id,
                detail={"email": "analyst@demo.edu"},
                ip_address="192.168.1.22",
            )
        )
        # 3. Admin changes phishing threshold (UC-04)
        db.add(
            AuditLog(
                org_id=org_id,
                user_id=admin_id,
                action="threshold_changed",
                target_type="settings",
                target_id=None,
                detail={
                    "before": {"phishing_threshold": 85},
                    "after": {"phishing_threshold": 80},
                },
                ip_address="192.168.1.10",
            )
        )

        await db.commit()

    await engine.dispose()

    print("✓  Organisation:    Demo University")
    print("✓  Users:           admin@demo.edu, analyst@demo.edu  (password: PhishGuard2026!)")
    print("✓  Emails:          5 (2 quarantined, 1 flagged, 2 delivered)")
    print("✓  AnalysisResults: 5")
    print("✓  EmailFeatures:   35 (7 per email)")
    print("✓  Feedback:        2")
    print("✓  AuditLog:        3")
    print("\nSeed complete. Visit /api/docs to explore the API.")


if __name__ == "__main__":
    asyncio.run(seed())
