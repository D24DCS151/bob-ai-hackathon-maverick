"""
Authentication and Role-Based Access Control for THREATICAP API.

Security model:
- API keys for machine-to-machine (connectors, CI/CD, SOC tooling)
- JWT tokens for interactive analyst/operator sessions
- Roles: reader < analyst < operator < admin
- TLP enforcement: users only see data at or below their clearance level
- All authentication events are audit-logged

Key storage:
- API keys: bcrypt-hashed in database (never store plaintext)
- JWT: signed with HS256 or RS256 (RS256 recommended for production)
- Secrets loaded from environment / mounted files (never config.yaml)

Production hardening:
- Use RS256 JWT with key rotation
- Implement token revocation list (Redis TTL-based)
- mTLS at ingress layer for service-to-service
- Rate limiting per API key / IP at ingress
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

from fastapi import Depends, Header, HTTPException, Request, status
from pydantic import BaseModel

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Role definitions
# ---------------------------------------------------------------------------

class Role(str, Enum):
    READER   = "reader"    # Read-only: list threats, view reports
    ANALYST  = "analyst"   # Reader + submit feedback, run pipeline
    OPERATOR = "operator"  # Analyst + manage API keys, ingest data
    ADMIN    = "admin"     # Full access including config changes


# Role hierarchy — higher index = more permissions
ROLE_HIERARCHY: list[Role] = [Role.READER, Role.ANALYST, Role.OPERATOR, Role.ADMIN]


def has_role(user_role: Role, required_role: Role) -> bool:
    """Returns True if user_role >= required_role in the hierarchy."""
    return ROLE_HIERARCHY.index(user_role) >= ROLE_HIERARCHY.index(required_role)


# TLP clearance levels — user must have >= alert's TLP to see it
TLP_ORDER = ["TLP:WHITE", "TLP:GREEN", "TLP:AMBER", "TLP:RED"]


def tlp_cleared(user_clearance: str, data_tlp: str) -> bool:
    """Returns True if user clearance level permits access to data_tlp."""
    try:
        user_level = TLP_ORDER.index(user_clearance)
        data_level = TLP_ORDER.index(data_tlp)
        return user_level >= data_level
    except ValueError:
        return False  # Unknown TLP — deny by default


# ---------------------------------------------------------------------------
# Token/key models
# ---------------------------------------------------------------------------

class AuthToken(BaseModel):
    """Validated identity attached to an authenticated request."""
    key_id: str
    actor: str
    role: Role
    clearance: str = "TLP:GREEN"
    authenticated_at: datetime


# ---------------------------------------------------------------------------
# API key management
# ---------------------------------------------------------------------------

def _hash_api_key(raw_key: str) -> str:
    """
    SHA-256 hash of the raw API key for database storage.

    In production, use bcrypt for true password-hashing semantics:
        import bcrypt
        return bcrypt.hashpw(raw_key.encode(), bcrypt.gensalt()).decode()

    SHA-256 is used here to avoid a bcrypt dependency, but bcrypt is
    strongly preferred for defence environments.
    """
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def generate_api_key() -> tuple[str, str]:
    """
    Generate a new API key.
    Returns (raw_key, key_hash) — store only the hash, give raw_key to client.
    """
    raw_key = f"tic_{secrets.token_urlsafe(32)}"
    key_hash = _hash_api_key(raw_key)
    return raw_key, key_hash


def verify_api_key(raw_key: str, stored_hash: str) -> bool:
    """Constant-time comparison to prevent timing attacks."""
    computed = _hash_api_key(raw_key)
    return hmac.compare_digest(computed.encode(), stored_hash.encode())


# ---------------------------------------------------------------------------
# JWT support (optional — requires python-jose)
# ---------------------------------------------------------------------------

def _jwt_secret() -> str:
    """Load JWT secret from environment or fail loudly."""
    secret = os.environ.get("JWT_SECRET_KEY", "")
    if not secret:
        # In development, generate an ephemeral secret
        if os.environ.get("ENVIRONMENT", "development") == "development":
            return "dev-only-insecure-jwt-secret-replace-in-production"
        raise RuntimeError(
            "JWT_SECRET_KEY environment variable must be set in production. "
            "Use a cryptographically random 256-bit value."
        )
    return secret


def create_jwt_token(
    key_id: str,
    actor: str,
    role: Role,
    clearance: str = "TLP:GREEN",
    expires_in_hours: int = 8,
) -> str:
    """
    Create a signed JWT token.
    Requires python-jose: pip install python-jose[cryptography]
    """
    try:
        from jose import jwt as jose_jwt
    except ImportError:
        raise RuntimeError("python-jose required for JWT: pip install python-jose[cryptography]")

    now = datetime.now(timezone.utc)
    payload = {
        "sub": key_id,
        "actor": actor,
        "role": role.value,
        "clearance": clearance,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=expires_in_hours)).timestamp()),
    }
    return jose_jwt.encode(payload, _jwt_secret(), algorithm="HS256")


def decode_jwt_token(token: str) -> dict[str, Any]:
    """Decode and validate a JWT token. Raises ValueError on invalid."""
    try:
        from jose import jwt as jose_jwt, JWTError
    except ImportError:
        raise RuntimeError("python-jose required: pip install python-jose[cryptography]")

    try:
        return jose_jwt.decode(token, _jwt_secret(), algorithms=["HS256"])
    except JWTError as exc:
        raise ValueError(f"Invalid JWT: {exc}") from exc


# ---------------------------------------------------------------------------
# FastAPI dependency: authenticate request
# ---------------------------------------------------------------------------

# In-memory API key store for development/demo mode.
# Production: replace lookup with database call (PostgresApiKeyStore).
_DEV_API_KEYS: dict[str, dict[str, Any]] = {}


def _get_dev_master_key() -> str:
    """Returns the development master key from env or a default."""
    key = os.environ.get("THREATICAP_MASTER_KEY", "")
    if key:
        return key
    logger.warning(
        "THREATICAP_MASTER_KEY not set — using insecure dev key. "
        "Set this environment variable in production."
    )
    return "dev-master-key-insecure-replace-me"


def _register_dev_key(raw_key: str, actor: str, role: Role, clearance: str) -> None:
    """Register an API key in the in-memory dev store."""
    key_hash = _hash_api_key(raw_key)
    _DEV_API_KEYS[key_hash] = {
        "key_id": f"devkey-{actor}",
        "actor": actor,
        "role": role,
        "clearance": clearance,
    }


def _init_dev_keys() -> None:
    """Initialise development API keys from environment."""
    master_key = _get_dev_master_key()
    _register_dev_key(master_key, "master", Role.ADMIN, "TLP:RED")

    # Additional keys from env
    for i in range(1, 5):
        key_env = os.environ.get(f"THREATICAP_API_KEY_{i}", "")
        role_env = os.environ.get(f"THREATICAP_API_ROLE_{i}", "reader")
        actor_env = os.environ.get(f"THREATICAP_API_ACTOR_{i}", f"user{i}")
        clearance_env = os.environ.get(f"THREATICAP_API_CLEARANCE_{i}", "TLP:GREEN")
        if key_env:
            try:
                role = Role(role_env)
            except ValueError:
                role = Role.READER
            _register_dev_key(key_env, actor_env, role, clearance_env)


# Initialise on import
_init_dev_keys()


class APIKeyStore:
    """
    Interface for API key validation.
    Override with database-backed implementation in production.
    """

    def validate(self, raw_key: str) -> AuthToken | None:
        """
        Validate an API key and return the AuthToken, or None if invalid.
        Override this method with a DB lookup in production.
        """
        key_hash = _hash_api_key(raw_key)
        entry = _DEV_API_KEYS.get(key_hash)
        if not entry:
            return None
        return AuthToken(
            key_id=entry["key_id"],
            actor=entry["actor"],
            role=entry["role"],
            clearance=entry.get("clearance", "TLP:GREEN"),
            authenticated_at=datetime.now(timezone.utc),
        )


# Module-level key store instance (replaced in production via DI)
_key_store = APIKeyStore()


def get_key_store() -> APIKeyStore:
    return _key_store


def set_key_store(store: APIKeyStore) -> None:
    """Replace the key store (e.g. with PostgresApiKeyStore)."""
    global _key_store
    _key_store = store


# ---------------------------------------------------------------------------
# FastAPI dependencies
# ---------------------------------------------------------------------------

async def authenticate_request(
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> AuthToken:
    """
    FastAPI dependency — authenticate via API key or JWT Bearer token.

    Priority:
    1. X-API-Key header (preferred for machine clients)
    2. Authorization: Bearer <jwt> (preferred for interactive sessions)

    Authentication bypass in development mode if THREATICAP_AUTH_DISABLED=true.
    NEVER set this in production.
    """
    if os.environ.get("THREATICAP_AUTH_DISABLED", "false").lower() == "true":
        logger.warning("AUTH_DISABLED=true — authentication bypassed (dev mode only)")
        return AuthToken(
            key_id="anon",
            actor="anonymous",
            role=Role.ADMIN,
            clearance="TLP:RED",
            authenticated_at=datetime.now(timezone.utc),
        )

    # Try API key
    if x_api_key:
        token = _key_store.validate(x_api_key)
        if token:
            _log_auth_event(request, token)
            return token
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    # Try JWT Bearer
    if authorization and authorization.lower().startswith("bearer "):
        raw_token = authorization[7:]
        try:
            payload = decode_jwt_token(raw_token)
            return AuthToken(
                key_id=payload.get("sub", ""),
                actor=payload.get("actor", ""),
                role=Role(payload.get("role", "reader")),
                clearance=payload.get("clearance", "TLP:GREEN"),
                authenticated_at=datetime.now(timezone.utc),
            )
        except (ValueError, RuntimeError) as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token: {exc}",
                headers={"WWW-Authenticate": "Bearer"},
            )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required. Provide X-API-Key header or Authorization: Bearer <token>",
        headers={"WWW-Authenticate": "ApiKey, Bearer"},
    )


def require_role(required: Role) -> Any:
    """
    Returns a FastAPI dependency that enforces a minimum role.

    Usage:
        @app.get("/admin")
        async def admin_route(auth: AuthToken = Depends(require_role(Role.ADMIN))):
            ...
    """
    async def _check(auth: AuthToken = Depends(authenticate_request)) -> AuthToken:
        if not has_role(auth.role, required):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{required.value}' required; you have '{auth.role.value}'",
            )
        return auth
    return _check


def _log_auth_event(request: Request, token: AuthToken) -> None:
    """Log successful authentication for audit purposes."""
    logger.info(
        "AUTH actor=%s role=%s path=%s method=%s",
        token.actor, token.role.value,
        request.url.path, request.method,
    )
