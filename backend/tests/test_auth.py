from __future__ import annotations

import base64
import json as jsonlib
from collections.abc import Generator
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.main import app
from app.models.auth_session import AuthSession
from app.models.user import User
from app.services.auth import create_access_token
from app.services.rate_limit import limiter


@pytest.fixture()
def auth_client(db: Session) -> Generator[TestClient, None, None]:
    """TestClient exercising the real get_current_user/auth flow against the
    in-memory test database (only the session is overridden)."""

    def _override_get_db() -> Generator[Session, None, None]:
        yield db

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


ADMIN_EMAIL = "admin@sentinelai.local"
ADMIN_PASSWORD = "adminpassword123"


def _login(client, *, email=ADMIN_EMAIL, password=ADMIN_PASSWORD):
    return client.post(
        "/api/auth/login",
        json={"email": email, "password": password},
        headers=_client_headers(),
    )


def _client_headers() -> dict[str, str]:
    return {settings.client_header_name: settings.client_header_value}


def _forgot(client, email):
    return client.post(
        "/api/auth/forgot-password",
        json={"email": email},
        headers=_client_headers(),
    )


def _get_set_cookie_tokens(response) -> dict[str, str]:
    tokens = {}
    for header in response.headers.get_list("set-cookie"):
        name, rest = header.split("=", 1)
        value = rest.split(";", 1)[0]
        tokens[name] = value
    return tokens


def _refresh_with_token(client, raw_refresh: str):
    return client.post(
        "/api/auth/refresh",
        headers={"Cookie": f"{settings.cookie_refresh_name}={raw_refresh}", **_client_headers()},
    )


class TestLogin:
    def test_login_succeeds_and_sets_http_only_cookies(self, client, admin_user):
        resp = _login(client)
        assert resp.status_code == 200
        body = resp.json()
        assert set(body.keys()) == {"user", "message"}
        assert body["user"]["email"] == ADMIN_EMAIL
        assert "token" not in body
        assert "refresh" not in body

        cookies = _get_set_cookie_tokens(resp)
        assert settings.cookie_access_name in cookies
        assert settings.cookie_refresh_name in cookies

        access_header = next(
            h for h in resp.headers.get_list("set-cookie") if h.startswith(settings.cookie_access_name)
        )
        refresh_header = next(
            h for h in resp.headers.get_list("set-cookie") if h.startswith(settings.cookie_refresh_name)
        )
        for header in (access_header, refresh_header):
            parts = [p.strip() for p in header.split(";")[1:]]
            names = {p.split("=", 1)[0].lower() for p in parts}
            assert "httponly" in names
            values = {
                p.split("=", 1)[0].lower(): p.split("=", 1)[1].lower()
                for p in parts
                if "=" in p
            }
            assert values.get("samesite") == "lax"
        access_values = {
            p.strip().split("=", 1)[0].lower(): p.strip().split("=", 1)[1].lower()
            for p in access_header.split(";")[1:]
            if "=" in p
        }
        refresh_values = {
            p.strip().split("=", 1)[0].lower(): p.strip().split("=", 1)[1].lower()
            for p in refresh_header.split(";")[1:]
            if "=" in p
        }
        assert access_values["path"] == "/api"
        assert refresh_values["path"] == "/api/auth"
        assert access_values["max-age"] == str(settings.access_token_expire_minutes * 60)

    def test_login_rejects_bad_credentials_generically(self, client, admin_user):
        resp = _login(client, password="wrong-password")
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Invalid email or password."

    def test_login_nonexistent_email_generic(self, client):
        resp = client.post(
            "/api/auth/login",
            json={"email": "ghost@absent.local", "password": "whatever123"},
        )
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Invalid email or password."

    def test_login_rejects_deactivated_account(self, client, db, admin_user):
        admin_user.is_active = False
        db.commit()
        resp = _login(client)
        assert resp.status_code == 403

    def test_me_requires_session(self, auth_client):
        resp = auth_client.get("/api/auth/me")
        assert resp.status_code == 401

    def test_me_with_session(self, auth_client, admin_user):
        _login(auth_client)
        resp = auth_client.get("/api/auth/me")
        assert resp.status_code == 200
        assert resp.json()["email"] == ADMIN_EMAIL

    def test_me_rejects_revoked_session(self, auth_client, admin_user, db):
        _login(auth_client)
        session = db.query(AuthSession).first()
        session.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        db.commit()
        resp = auth_client.get("/api/auth/me")
        assert resp.status_code == 401


class TestRefresh:
    def test_refresh_rotates_token(self, auth_client, admin_user):
        login = _login(auth_client)
        tokens = _get_set_cookie_tokens(login)
        old_refresh = tokens[settings.cookie_refresh_name]

        resp = _refresh_with_token(auth_client, old_refresh)
        assert resp.status_code == 200
        new_tokens = _get_set_cookie_tokens(resp)
        assert settings.cookie_refresh_name in new_tokens
        assert new_tokens[settings.cookie_refresh_name] != old_refresh

    def test_old_refresh_reused_after_rotation_fails(self, auth_client, admin_user):
        login = _login(auth_client)
        old_refresh = _get_set_cookie_tokens(login)[settings.cookie_refresh_name]
        first = _refresh_with_token(auth_client, old_refresh)
        assert first.status_code == 200
        assert first.json()["message"] == "Session refreshed."

        reused = _refresh_with_token(auth_client, old_refresh)
        assert reused.status_code == 401

    def test_replay_revokes_entire_family(self, auth_client, admin_user):
        login = _login(auth_client)
        tokens = _get_set_cookie_tokens(login)
        old_refresh = tokens[settings.cookie_refresh_name]

        r1 = _refresh_with_token(auth_client, old_refresh)
        assert r1.status_code == 200
        new_refresh = _get_set_cookie_tokens(r1)[settings.cookie_refresh_name]

        # Replay of the rotated credential burns the family: both the old and the
        # newly minted refresh tokens must now be dead.
        assert _refresh_with_token(auth_client, old_refresh).status_code == 401
        assert _refresh_with_token(auth_client, new_refresh).status_code == 401

    def test_access_token_not_accepted_as_refresh(self, auth_client, admin_user):
        _login(auth_client)
        access = _get_set_cookie_tokens(_login(auth_client))[settings.cookie_access_name]
        resp = _refresh_with_token(auth_client, access)
        assert resp.status_code == 401

    def test_refresh_requires_client_header(self, auth_client, admin_user):
        login = _login(auth_client)
        old_refresh = _get_set_cookie_tokens(login)[settings.cookie_refresh_name]
        resp = auth_client.post(
            "/api/auth/refresh",
            headers={"Cookie": f"{settings.cookie_refresh_name}={old_refresh}"},
        )
        assert resp.status_code == 403

    def test_session_row_count_after_rotation(self, auth_client, admin_user, db):
        login = _login(auth_client)
        old_refresh = _get_set_cookie_tokens(login)[settings.cookie_refresh_name]
        before = db.query(AuthSession).count()
        _refresh_with_token(auth_client, old_refresh)
        after = db.query(AuthSession).count()
        assert after == before + 1
        assert db.query(AuthSession).filter(AuthSession.revoked_at.isnot(None)).count() == before


class TestLogout:
    def test_logout_revokes_session(self, auth_client, admin_user):
        login = _login(auth_client)
        refresh = _get_set_cookie_tokens(login)[settings.cookie_refresh_name]

        logout = auth_client.post("/api/auth/logout", headers=_client_headers())
        assert logout.status_code == 200
        assert logout.json()["message"] == "Logged out successfully."

        refreshed = _refresh_with_token(auth_client, refresh)
        assert refreshed.status_code == 401

    def test_logout_requires_client_header(self, auth_client, admin_user):
        _login(auth_client)
        resp = auth_client.post("/api/auth/logout")
        assert resp.status_code == 403


class TestRegister:
    def test_register_returns_user_and_message_only(self, client):
        resp = client.post(
            "/api/auth/register",
            json={"name": "Fresh", "email": "fresh@test.local", "password": "strongpass123"},
        )
        assert resp.status_code == 201
        body = resp.json()
        assert set(body.keys()) == {"user", "message"}
        assert "token" not in body

    def test_register_duplicate_conflicts(self, client, admin_user):
        resp = client.post(
            "/api/auth/register",
            json={"name": "Dup", "email": ADMIN_EMAIL, "password": "strongpass123"},
        )
        assert resp.status_code == 409


class TestForgotReset:
    def test_forgot_unknown_email_generic_without_token(self, client):
        resp = _forgot(client, "nobody@absent.local")
        assert resp.status_code == 200
        assert resp.json()["debug_reset_token"] is None
        assert "If an account exists" in resp.json()["message"]

    def test_forgot_existing_email_returns_debug_token_in_test_env(self, client, admin_user):
        resp = _forgot(client, ADMIN_EMAIL)
        assert resp.status_code == 200
        assert resp.json()["debug_reset_token"]
        assert "If an account exists" in resp.json()["message"]

    def test_reset_changes_password_and_revokes_sessions(self, auth_client, admin_user, db):
        _login(auth_client)
        old_refresh = _get_set_cookie_tokens(_login(auth_client))[settings.cookie_refresh_name]

        token = _forgot(auth_client, ADMIN_EMAIL).json()["debug_reset_token"]
        resp = auth_client.post(
            "/api/auth/reset-password",
            json={"token": token, "new_password": "brandnewpass456"},
            headers=_client_headers(),
        )
        assert resp.status_code == 200

        assert _login(auth_client, password=ADMIN_PASSWORD).status_code == 401
        assert _login(auth_client, password="brandnewpass456").status_code == 200

        # All prior sessions were revoked server-side.
        assert _refresh_with_token(auth_client, old_refresh).status_code == 401

    def test_reset_token_single_use(self, auth_client, admin_user, db):
        token = _forgot(auth_client, ADMIN_EMAIL).json()["debug_reset_token"]
        first = auth_client.post(
            "/api/auth/reset-password",
            json={"token": token, "new_password": "onceonlypass123"},
            headers=_client_headers(),
        )
        assert first.status_code == 200

        second = auth_client.post(
            "/api/auth/reset-password",
            json={"token": token, "new_password": "regenerated456"},
            headers=_client_headers(),
        )
        assert second.status_code == 400
        assert second.json()["detail"] == "The reset link is invalid or has expired."
        assert _login(auth_client, password="onceonlypass123").status_code == 200
        assert _login(auth_client, password="regenerated456").status_code == 401

    def test_reset_rejects_access_jwt(self, auth_client, admin_user):
        access_token = create_access_token(admin_user.id)
        resp = auth_client.post(
            "/api/auth/reset-password",
            json={"token": access_token, "new_password": "shouldnotwork1"},
            headers=_client_headers(),
        )
        assert resp.status_code in (400, 422)

    def test_reset_requires_client_header(self, auth_client, admin_user):
        _login(auth_client)
        resp = auth_client.post(
            "/api/auth/reset-password",
            json={"token": "any-token", "new_password": "headerless345"},
        )
        assert resp.status_code == 403


class TestClientHeaderGuard:
    def test_mutating_request_with_session_cookie_requires_header(self, auth_client, admin_user):
        _login(auth_client)
        resp = auth_client.patch(
            "/api/system/settings",
            json={"max_upload_mb": 60, "analysis_history_limit": 120},
        )
        assert resp.status_code == 403
        assert resp.json()["detail"] == "Missing or invalid client header."

    def test_mutating_request_with_header_succeeds(self, auth_client, admin_user):
        _login(auth_client)
        resp = auth_client.patch(
            "/api/system/settings",
            json={"max_upload_mb": 60, "analysis_history_limit": 120},
            headers=_client_headers(),
        )
        assert resp.status_code == 200


class TestRateLimiting:
    def test_login_rate_limited(self, client, admin_user):
        responses = [client.post("/api/auth/login", json={"email": ADMIN_EMAIL, "password": "bad"}) for _ in range(5)]
        assert all(r.status_code == 401 for r in responses)
        blocked = client.post("/api/auth/login", json={"email": ADMIN_EMAIL, "password": "bad"})
        assert blocked.status_code == 429

    def test_register_rate_limited(self, client):
        for i in range(5):
            client.post(
                "/api/auth/register",
                json={"name": f"Spam {i}", "email": f"spam{i}@test.local", "password": "strongpass123"},
            )
        blocked = client.post(
            "/api/auth/register",
            json={"name": "Spam 6", "email": "spam6@test.local", "password": "strongpass123"},
        )
        assert blocked.status_code == 429

    def test_limiter_reset(self):
        limiter.reset()
        from app.services.rate_limit import LOGIN_IP, limiter as shared_limiter

        assert shared_limiter.allow("probe", LOGIN_IP) is True


class TestJwtValidation:
    def _b64(self, payload: bytes) -> str:
        return base64.urlsafe_b64encode(payload).rstrip(b"=").decode()

    def test_alg_none_rejected(self, admin_user):
        header = {"alg": "none", "typ": "JWT"}
        now = datetime.now(timezone.utc)
        payload = {
            "sub": admin_user.id,
            "jti": "forged",
            "iss": settings.jwt_issuer,
            "aud": settings.jwt_audience,
            "iat": now,
            "exp": now + timedelta(minutes=15),
            "typ": "access",
        }
        token_parts = [
            self._b64(jsonlib.dumps(header).encode()),
            self._b64(jsonlib.dumps(payload, default=str).encode()),
            "",
        ]
        forged = ".".join(token_parts)

        from app.services.auth import decode_access_token

        assert decode_access_token(forged) is None

    def test_wrong_audience_rejected(self, admin_user):
        import jwt

        now = datetime.now(timezone.utc)
        token = jwt.encode(
            {
                "sub": admin_user.id,
                "jti": "x",
                "iss": settings.jwt_issuer,
                "aud": "someone-else",
                "iat": now,
                "exp": now + timedelta(minutes=15),
                "typ": "access",
            },
            settings.jwt_secret_key,
            algorithm="HS256",
        )
        from app.services.auth import decode_access_token

        assert decode_access_token(token) is None

    def test_wrong_issuer_rejected(self, admin_user):
        import jwt

        now = datetime.now(timezone.utc)
        token = jwt.encode(
            {
                "sub": admin_user.id,
                "jti": "x",
                "iss": "attacker",
                "aud": settings.jwt_audience,
                "iat": now,
                "exp": now + timedelta(minutes=15),
                "typ": "access",
            },
            settings.jwt_secret_key,
            algorithm="HS256",
        )
        from app.services.auth import decode_access_token

        assert decode_access_token(token) is None

    def test_expired_token_rejected(self, admin_user):
        import jwt

        now = datetime.now(timezone.utc)
        token = jwt.encode(
            {
                "sub": admin_user.id,
                "jti": "x",
                "iss": settings.jwt_issuer,
                "aud": settings.jwt_audience,
                "iat": now - timedelta(hours=1),
                "exp": now - timedelta(minutes=1),
                "typ": "access",
            },
            settings.jwt_secret_key,
            algorithm="HS256",
        )
        from app.services.auth import decode_access_token

        assert decode_access_token(token) is None


class TestAuditEventsForSecurity:
    def test_refresh_reuse_audited(self, client, admin_user, db):
        login = _login(client)
        old_refresh = _get_set_cookie_tokens(login)[settings.cookie_refresh_name]
        _refresh_with_token(client, old_refresh)
        _refresh_with_token(client, old_refresh)

        from app.models.audit_log import AuditLog

        events = db.query(AuditLog).filter(AuditLog.action == "REFRESH_TOKEN_REUSED").all()
        assert len(events) == 1
        assert events[0].result == "FAILURE"

    def test_login_success_audited_with_session(self, client, admin_user, db):
        _login(client)
        from app.models.audit_log import AuditLog

        event = (
            db.query(AuditLog)
            .filter(AuditLog.action == "LOGIN_SUCCESS")
            .order_by(AuditLog.timestamp.desc())
            .first()
        )
        assert event is not None
        assert event.metadata_json.get("session_id")


class TestConfigFailFast:
    def test_production_rejects_default_secret(self, monkeypatch):
        from app.core import config

        monkeypatch.setenv("SENTINEL_ENV", "production")
        monkeypatch.setenv("JWT_SECRET_KEY", "dev-secret-change-in-production")
        monkeypatch.setenv("AUTH_COOKIE_SECURE", "true")
        with pytest.raises(RuntimeError, match="JWT_SECRET_KEY"):
            config.get_settings()

    def test_production_rejects_missing_secret(self, monkeypatch):
        from app.core import config

        monkeypatch.setenv("SENTINEL_ENV", "production")
        monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
        monkeypatch.setenv("AUTH_COOKIE_SECURE", "true")
        with pytest.raises(RuntimeError, match="Missing JWT_SECRET_KEY"):
            config.get_settings()

    def test_production_rejects_insecure_cookie(self, monkeypatch):
        from app.core import config

        monkeypatch.setenv("SENTINEL_ENV", "production")
        monkeypatch.setenv("JWT_SECRET_KEY", "z" * 48)
        monkeypatch.setenv("AUTH_COOKIE_SECURE", "false")
        monkeypatch.setenv("DEBUG_RESET_RETURNS_TOKEN", "false")
        with pytest.raises(RuntimeError, match="AUTH_COOKIE_SECURE"):
            config.get_settings()

    def test_production_accepts_strong_config(self, monkeypatch):
        from app.core import config

        monkeypatch.setenv("SENTINEL_ENV", "production")
        monkeypatch.setenv("JWT_SECRET_KEY", "k" * 48)
        monkeypatch.setenv("AUTH_COOKIE_SECURE", "true")
        monkeypatch.setenv("DEBUG_RESET_RETURNS_TOKEN", "false")
        monkeypatch.setenv("FRONTEND_ORIGIN", "https://sentinel.example.com")
        s = config.get_settings()
        assert s.cookie_secure is True
        assert s.env == "production"

    def test_dev_generates_ephemeral_secret_when_unset(self, monkeypatch):
        from app.core import config

        monkeypatch.setenv("SENTINEL_ENV", "development")
        monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
        s = config.get_settings()
        assert s.jwt_secret_key != "dev-secret-change-in-production"
        assert len(s.jwt_secret_key) >= 32