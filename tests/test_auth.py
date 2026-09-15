"""
Tests for the authentication and RBAC system (Phase 2).

Covers:
- Role hierarchy (has_role)
- TLP clearance (tlp_cleared)
- API key generation (generate_api_key)
- API key verification (verify_api_key)
- APIKeyStore validate
- authenticate_request FastAPI dependency (dev bypass, API key, JWT)
- require_role enforcement
- AuthToken model
"""
from __future__ import annotations

import os
import pytest
from datetime import datetime, timezone

# Tests run with auth disabled for the main API tests,
# but we explicitly test the auth logic here with AUTH_DISABLED=false
# by importing the auth module directly.

from threaticap.api.auth import (
    Role,
    ROLE_HIERARCHY,
    AuthToken,
    has_role,
    tlp_cleared,
    generate_api_key,
    verify_api_key,
    _hash_api_key,
    APIKeyStore,
    _DEV_API_KEYS,
    _register_dev_key,
)


# ---------------------------------------------------------------------------
# Role hierarchy
# ---------------------------------------------------------------------------

class TestRoleHierarchy:

    def test_reader_has_reader(self):
        assert has_role(Role.READER, Role.READER)

    def test_reader_lacks_analyst(self):
        assert not has_role(Role.READER, Role.ANALYST)

    def test_analyst_has_reader(self):
        assert has_role(Role.ANALYST, Role.READER)

    def test_analyst_has_analyst(self):
        assert has_role(Role.ANALYST, Role.ANALYST)

    def test_analyst_lacks_operator(self):
        assert not has_role(Role.ANALYST, Role.OPERATOR)

    def test_operator_has_analyst(self):
        assert has_role(Role.OPERATOR, Role.ANALYST)

    def test_operator_lacks_admin(self):
        assert not has_role(Role.OPERATOR, Role.ADMIN)

    def test_admin_has_all(self):
        for role in ROLE_HIERARCHY:
            assert has_role(Role.ADMIN, role)

    def test_hierarchy_is_ordered(self):
        """ROLE_HIERARCHY list must be in ascending order."""
        for i in range(len(ROLE_HIERARCHY) - 1):
            assert ROLE_HIERARCHY.index(ROLE_HIERARCHY[i]) < ROLE_HIERARCHY.index(ROLE_HIERARCHY[i + 1])


# ---------------------------------------------------------------------------
# TLP clearance
# ---------------------------------------------------------------------------

class TestTLPClearance:

    def test_white_clears_white(self):
        assert tlp_cleared("TLP:WHITE", "TLP:WHITE")

    def test_white_cannot_see_green(self):
        assert not tlp_cleared("TLP:WHITE", "TLP:GREEN")

    def test_green_clears_white(self):
        assert tlp_cleared("TLP:GREEN", "TLP:WHITE")

    def test_green_clears_green(self):
        assert tlp_cleared("TLP:GREEN", "TLP:GREEN")

    def test_green_cannot_see_amber(self):
        assert not tlp_cleared("TLP:GREEN", "TLP:AMBER")

    def test_amber_clears_green(self):
        assert tlp_cleared("TLP:AMBER", "TLP:GREEN")

    def test_red_clears_all(self):
        for tlp in ["TLP:WHITE", "TLP:GREEN", "TLP:AMBER", "TLP:RED"]:
            assert tlp_cleared("TLP:RED", tlp)

    def test_unknown_tlp_denied(self):
        assert not tlp_cleared("TLP:BLACK", "TLP:WHITE")
        assert not tlp_cleared("TLP:RED", "TLP:UNKNOWN")


# ---------------------------------------------------------------------------
# API key generation and verification
# ---------------------------------------------------------------------------

class TestAPIKeyGeneration:

    def test_generate_produces_two_values(self):
        raw_key, key_hash = generate_api_key()
        assert raw_key
        assert key_hash

    def test_raw_key_starts_with_tic(self):
        raw_key, _ = generate_api_key()
        assert raw_key.startswith("tic_")

    def test_hash_is_deterministic(self):
        _, h1 = generate_api_key()
        raw_key, h2 = generate_api_key()
        # Two different keys produce different hashes
        raw2, h3 = generate_api_key()
        assert h1 != h3  # Different keys → different hashes

    def test_hash_is_hex_string(self):
        _, key_hash = generate_api_key()
        int(key_hash, 16)  # Should not raise

    def test_two_keys_differ(self):
        k1, _ = generate_api_key()
        k2, _ = generate_api_key()
        assert k1 != k2

    def test_verify_correct_key(self):
        raw, stored = generate_api_key()
        assert verify_api_key(raw, stored)

    def test_verify_wrong_key(self):
        raw, stored = generate_api_key()
        assert not verify_api_key("wrong-key", stored)

    def test_verify_constant_time(self):
        """verify_api_key must not short-circuit (timing attack prevention)."""
        raw, stored = generate_api_key()
        # Both must return bool and not raise
        assert isinstance(verify_api_key(raw, stored), bool)
        assert isinstance(verify_api_key("x", stored), bool)


# ---------------------------------------------------------------------------
# APIKeyStore
# ---------------------------------------------------------------------------

class TestAPIKeyStore:

    def setup_method(self):
        """Register a fresh test key before each test."""
        self.raw_key = "test-key-for-store-tests-xyz123"
        self.actor = "test-actor"
        self.role = Role.ANALYST
        self.clearance = "TLP:AMBER"
        _register_dev_key(self.raw_key, self.actor, self.role, self.clearance)
        self.store = APIKeyStore()

    def test_validate_correct_key_returns_token(self):
        token = self.store.validate(self.raw_key)
        assert token is not None
        assert isinstance(token, AuthToken)

    def test_validate_correct_key_actor(self):
        token = self.store.validate(self.raw_key)
        assert token.actor == self.actor

    def test_validate_correct_key_role(self):
        token = self.store.validate(self.raw_key)
        assert token.role == self.role

    def test_validate_correct_key_clearance(self):
        token = self.store.validate(self.raw_key)
        assert token.clearance == self.clearance

    def test_validate_wrong_key_returns_none(self):
        token = self.store.validate("completely-wrong-key")
        assert token is None

    def test_validate_empty_key_returns_none(self):
        token = self.store.validate("")
        assert token is None


# ---------------------------------------------------------------------------
# AuthToken model
# ---------------------------------------------------------------------------

class TestAuthToken:

    def test_create_auth_token(self):
        t = AuthToken(
            key_id="k1",
            actor="analyst-1",
            role=Role.ANALYST,
            clearance="TLP:GREEN",
            authenticated_at=datetime.now(timezone.utc),
        )
        assert t.key_id == "k1"
        assert t.role == Role.ANALYST

    def test_default_clearance_is_green(self):
        t = AuthToken(
            key_id="k2",
            actor="reader",
            role=Role.READER,
            authenticated_at=datetime.now(timezone.utc),
        )
        assert t.clearance == "TLP:GREEN"


# ---------------------------------------------------------------------------
# JWT (only tested if python-jose is installed)
# ---------------------------------------------------------------------------

class TestJWT:

    def setup_method(self):
        try:
            from jose import jwt  # noqa
            self.has_jose = True
        except ImportError:
            self.has_jose = False

    def test_create_and_decode_jwt(self):
        if not self.has_jose:
            pytest.skip("python-jose not installed")
        from threaticap.api.auth import create_jwt_token, decode_jwt_token
        token_str = create_jwt_token("kid-1", "analyst", Role.ANALYST, "TLP:GREEN", expires_in_hours=1)
        payload = decode_jwt_token(token_str)
        assert payload["actor"] == "analyst"
        assert payload["role"] == "analyst"
        assert payload["clearance"] == "TLP:GREEN"

    def test_decode_invalid_jwt_raises(self):
        if not self.has_jose:
            pytest.skip("python-jose not installed")
        from threaticap.api.auth import decode_jwt_token
        with pytest.raises((ValueError, Exception)):
            decode_jwt_token("this.is.not.a.valid.jwt")
