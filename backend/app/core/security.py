"""
PhishGuard security primitives.

Covers all cryptographic operations used across the application:
  - JWT access and refresh token creation / decoding
  - bcrypt password hashing (cost factor 12, NFR-2)
  - HMAC-SHA256 digest action token signing and verification
  - Fernet symmetric encryption for IMAP passwords at rest
  - Redis JTI blacklist for invalidated refresh tokens
"""
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import bcrypt
from cryptography.fernet import Fernet
from jose import jwt
from redis.asyncio import Redis

from app.core.config import settings

# ---------------------------------------------------------------------------
# Internal Fernet singleton — initialised once on first use
# ---------------------------------------------------------------------------
_fernet: Fernet | None = None


def _get_fernet() -> Fernet:
    """Return the cached Fernet instance, constructing it on first call."""
    global _fernet
    if _fernet is None:
        _fernet = Fernet(settings.FERNET_KEY.encode())
    return _fernet


# ---------------------------------------------------------------------------
# JWT
# ---------------------------------------------------------------------------

def create_access_token(
    user_id: int,
    org_id: int,
    role: str,
    hours: int = 8,
) -> str:
    """Create a signed HS256 JWT access token.

    Claims::

        sub      — str(user_id), primary identifier
        org_id   — str(org_id), multi-tenant isolation
        role     — 'admin' | 'analyst'
        jti      — random 16-byte URL-safe token (not blacklisted for access tokens)
        iat      — issued-at timestamp
        exp      — expiry (default 8 hours per NFR-2)

    Args:
        user_id: Primary key of the authenticated user.
        org_id:  Primary key of the user's organisation.
        role:    RBAC role string — 'admin' or 'analyst'.
        hours:   Token lifetime in hours (default 8).

    Returns:
        Encoded JWT string.
    """
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": str(user_id),
        "org_id": str(org_id),
        "role": role,
        "jti": secrets.token_urlsafe(16),
        "iat": now,
        "exp": now + timedelta(hours=hours),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm="HS256")


def decode_access_token(token: str) -> dict[str, Any]:
    """Decode and verify a JWT, returning the full claims payload.

    Raises:
        jose.JWTError: If the token is expired, tampered with, or malformed.

    Args:
        token: Encoded JWT string (access or refresh).

    Returns:
        Decoded claims dict with keys ``sub``, ``org_id``, ``role``, ``jti``,
        ``iat``, ``exp`` (and ``type`` for refresh tokens).
    """
    return jwt.decode(  # type: ignore[no-any-return]
        token,
        settings.JWT_SECRET,
        algorithms=["HS256"],
    )


def create_refresh_token(user_id: int) -> str:
    """Create a 7-day HS256 refresh token with a unique JTI.

    The JTI embedded in the token is extracted via ``decode_access_token``
    at logout time and stored in the Redis blacklist.

    Claims::

        sub   — str(user_id)
        type  — 'refresh'  (distinguishes from access tokens)
        jti   — random 32-byte URL-safe string (blacklisted on logout)
        iat   — issued-at timestamp
        exp   — 7 days from now

    Args:
        user_id: Primary key of the user receiving the refresh token.

    Returns:
        Encoded JWT refresh token string.
    """
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": str(user_id),
        "type": "refresh",
        "jti": secrets.token_urlsafe(32),
        "iat": now,
        "exp": now + timedelta(days=7),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm="HS256")


# ---------------------------------------------------------------------------
# bcrypt — cost factor 12 (NFR-2 mandate)
# ---------------------------------------------------------------------------

def hash_password(plain: str) -> str:
    """Return a bcrypt hash of *plain* using cost factor 12.

    Args:
        plain: Cleartext password string.

    Returns:
        bcrypt hash string (60 characters, includes salt and cost factor).
    """
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt(rounds=12)).decode()


def verify_password(plain: str, hashed: str) -> bool:
    """Return True if *plain* matches the stored bcrypt *hashed* value.

    Args:
        plain:  Cleartext password to verify.
        hashed: Previously computed bcrypt hash (from ``hash_password``).

    Returns:
        True on match, False otherwise.
    """
    return bcrypt.checkpw(plain.encode(), hashed.encode())  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# HMAC digest action tokens
# ---------------------------------------------------------------------------

def sign_digest_token(email_id: int, jti: str) -> str:
    """Return an HMAC-SHA256 hex digest for a quarantine digest action link.

    The token binds the *email_id* and a random *jti* together so that the
    signed URL cannot be reused for a different email or replayed after the
    JTI is consumed.

    Algorithm (from plan §5.2)::

        HMAC-SHA256(DIGEST_HMAC_SECRET, f"{email_id}:{jti}").hexdigest()

    Args:
        email_id: Primary key of the quarantined email.
        jti:      Random URL-safe string generated at send time
                  (``secrets.token_urlsafe(32)``).

    Returns:
        64-character lowercase hex string.
    """
    msg = f"{email_id}:{jti}".encode()
    return hmac.new(
        settings.DIGEST_HMAC_SECRET.encode(),
        msg,
        hashlib.sha256,
    ).hexdigest()


def verify_digest_token(token: str, email_id: int, jti: str) -> bool:
    """Verify a digest action token using constant-time comparison.

    Constant-time comparison prevents timing-based token forgery.

    Args:
        token:    Hex digest received from the signed email link.
        email_id: Email ID from the URL path.
        jti:      JTI from the URL query string.

    Returns:
        True if the token is authentic, False otherwise.
    """
    expected = sign_digest_token(email_id, jti)
    return hmac.compare_digest(token, expected)


# ---------------------------------------------------------------------------
# Fernet symmetric encryption (IMAP passwords at rest)
# ---------------------------------------------------------------------------

def fernet_encrypt(plain: str) -> str:
    """Encrypt *plain* with Fernet and return the URL-safe base64 ciphertext.

    The returned string is safe to store in the ``imap_password_encrypted``
    database column.  The plaintext is never written to disk.

    Args:
        plain: Cleartext string to encrypt (e.g. an IMAP password).

    Returns:
        URL-safe base64-encoded Fernet token string.
    """
    return _get_fernet().encrypt(plain.encode()).decode()


def fernet_decrypt(ciphertext: str) -> str:
    """Decrypt a Fernet *ciphertext* and return the original plaintext.

    Args:
        ciphertext: URL-safe base64 Fernet token (from ``fernet_encrypt``).

    Returns:
        Decrypted plaintext string.

    Raises:
        cryptography.fernet.InvalidToken: If the ciphertext is tampered with
        or the key does not match.
    """
    return _get_fernet().decrypt(ciphertext.encode()).decode()


# ---------------------------------------------------------------------------
# Redis JTI blacklist — refresh token invalidation
# ---------------------------------------------------------------------------

async def blacklist_jti(redis: Redis, jti: str, ttl_seconds: int) -> None:  # type: ignore[type-arg]
    """Add a refresh token JTI to the Redis blacklist with a TTL.

    Called at logout.  The TTL is set to the token's remaining lifetime so
    the key expires naturally when the token would have anyway.

    Redis key: ``blacklist:{jti}``

    Args:
        redis:       Async Redis client instance.
        jti:         JWT ID claim from the refresh token being invalidated.
        ttl_seconds: Seconds until the blacklist entry expires.
    """
    await redis.setex(f"blacklist:{jti}", ttl_seconds, "1")


async def is_jti_blacklisted(redis: Redis, jti: str) -> bool:  # type: ignore[type-arg]
    """Return True if the JTI is present in the Redis blacklist.

    Args:
        redis: Async Redis client instance.
        jti:   JWT ID claim to check.

    Returns:
        True if blacklisted (token revoked), False if the key is absent.
    """
    result = await redis.get(f"blacklist:{jti}")
    return result is not None
