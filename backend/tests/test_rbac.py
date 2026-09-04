from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from app.models.user import User


def _get_users(client) -> list[dict]:
    return client.get("/api/users").json()["items"]


class TestAdminAccess:
    def test_admin_lists_users(self, client):
        response = client.get("/api/users")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] >= 1
        assert all("hashed_password" not in u for u in data["items"])

    def test_admin_gets_user_by_id(self, client, db):
        user = db.query(User).first()
        response = client.get(f"/api/users/{user.id}")
        assert response.status_code == 200
        assert response.json()["email"] == user.email
        assert "hashed_password" not in response.json()

    def test_admin_changes_role(self, client, analyst_user):
        response = client.patch(
            f"/api/users/{analyst_user.id}",
            json={"role": "admin"},
        )
        assert response.status_code == 200
        assert response.json()["role"] == "admin"

    def test_admin_activates_deactivates_user(self, client, analyst_user):
        response = client.patch(
            f"/api/users/{analyst_user.id}",
            json={"is_active": False},
        )
        assert response.status_code == 200
        assert response.json()["is_active"] is False

        response = client.patch(
            f"/api/users/{analyst_user.id}",
            json={"is_active": True},
        )
        assert response.status_code == 200
        assert response.json()["is_active"] is True


class TestAnalystForbidden:
    def test_analyst_cannot_list_users(self, analyst_client):
        response = analyst_client.get("/api/users")
        assert response.status_code == 403

    def test_analyst_cannot_get_user(self, analyst_client, admin_user):
        response = analyst_client.get(f"/api/users/{admin_user.id}")
        assert response.status_code == 403

    def test_analyst_cannot_change_role(self, analyst_client, admin_user):
        response = analyst_client.patch(
            f"/api/users/{admin_user.id}",
            json={"role": "viewer"},
        )
        assert response.status_code == 403

    def test_analyst_cannot_deactivate_user(self, analyst_client, admin_user):
        response = analyst_client.patch(
            f"/api/users/{admin_user.id}",
            json={"is_active": False},
        )
        assert response.status_code == 403

    def test_analyst_cannot_modify_settings(self, analyst_client):
        response = analyst_client.patch(
            "/api/system/settings",
            json={"max_upload_mb": 50, "analysis_history_limit": 100},
        )
        assert response.status_code == 403

    def test_analyst_can_view_settings(self, analyst_client):
        response = analyst_client.get("/api/system/settings")
        assert response.status_code == 200


class TestUnauthenticatedForbidden:
    def test_unauth_cannot_list_users(self, unauth_client):
        response = unauth_client.get("/api/users")
        assert response.status_code == 401

    def test_unauth_cannot_get_user(self, unauth_client, admin_user):
        response = unauth_client.get(f"/api/users/{admin_user.id}")
        assert response.status_code == 401


class TestPasswordHashNotExposed:
    def test_password_hash_never_in_list(self, client):
        response = client.get("/api/users")
        for user in response.json()["items"]:
            assert "hashed_password" not in user
            assert "password" not in user

    def test_password_hash_never_in_detail(self, client, admin_user):
        response = client.get(f"/api/users/{admin_user.id}")
        assert "hashed_password" not in response.json()
        assert "password" not in response.json()


class TestLastAdminProtection:
    def test_cannot_deactivate_last_admin(self, client, admin_user):
        response = client.patch(
            f"/api/users/{admin_user.id}",
            json={"is_active": False},
        )
        assert response.status_code == 409
        assert "last active admin" in response.json()["detail"].lower()

    def test_can_deactivate_admin_when_other_admins_exist(self, client, db, admin_user):
        second_admin = User(
            email="admin2@sentinelai.local",
            hashed_password="pass123",
            name="Second Admin",
            role="admin",
        )
        db.add(second_admin)
        db.commit()
        db.refresh(second_admin)

        response = client.patch(
            f"/api/users/{admin_user.id}",
            json={"is_active": False},
        )
        assert response.status_code == 200
        assert response.json()["is_active"] is False


class TestUserCreation:
    def test_admin_creates_user(self, client):
        response = client.post(
            "/api/users",
            json={
                "name": "New Analyst",
                "email": "newanalyst@test.local",
                "password": "securepass123",
                "role": "analyst",
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["email"] == "newanalyst@test.local"
        assert data["role"] == "analyst"
        assert data["is_active"] is True
        assert "hashed_password" not in data
        assert "password" not in data

    def test_admin_can_create_admin(self, client):
        response = client.post(
            "/api/users",
            json={
                "name": "New Admin",
                "email": "newadmin@test.local",
                "password": "securepass123",
                "role": "admin",
            },
        )
        assert response.status_code == 201
        assert response.json()["role"] == "admin"

    def test_duplicate_email_conflict(self, client, analyst_user):
        response = client.post(
            "/api/users",
            json={
                "name": "Dupe",
                "email": analyst_user.email,
                "password": "securepass123",
                "role": "analyst",
            },
        )
        assert response.status_code == 409

    def test_create_user_emits_audit_event(self, client, db):
        from app.models.audit_log import AuditLog

        before = db.query(AuditLog).count()
        client.post(
            "/api/users",
            json={
                "name": "Audited",
                "email": "audited@test.local",
                "password": "securepass123",
                "role": "analyst",
            },
        )
        after = db.query(AuditLog).count()
        assert after > before

    def test_short_password_rejected(self, client):
        response = client.post(
            "/api/users",
            json={
                "name": "Short",
                "email": "short@test.local",
                "password": "short",
                "role": "analyst",
            },
        )
        assert response.status_code == 422

    def test_analyst_cannot_create_user(self, analyst_client):
        response = analyst_client.post(
            "/api/users",
            json={
                "name": "Nope",
                "email": "nope@test.local",
                "password": "securepass123",
                "role": "analyst",
            },
        )
        assert response.status_code == 403

    def test_unauth_cannot_create_user(self, unauth_client):
        response = unauth_client.post(
            "/api/users",
            json={
                "name": "Nope",
                "email": "nope@test.local",
                "password": "securepass123",
                "role": "analyst",
            },
        )
        assert response.status_code == 401


class TestPaginationFiltering:
    def test_pagination(self, client, db):
        for i in range(5):
            db.add(User(
                email=f"user{i}@test.local",
                hashed_password="pass",
                name=f"User {i}",
                role="analyst",
            ))
        db.commit()

        response = client.get("/api/users?page=1&page_size=2")
        data = response.json()
        assert data["total"] >= 6
        assert len(data["items"]) == 2
        assert data["total_pages"] >= 3

    def test_filter_by_role(self, client, admin_user, analyst_user):
        response = client.get("/api/users?role=admin")
        data = response.json()
        assert all(u["role"] == "admin" for u in data["items"])

    def test_filter_by_active(self, client, admin_user, analyst_user):
        response = client.get("/api/users?is_active=true")
        data = response.json()
        assert all(u["is_active"] is True for u in data["items"])

    def test_search(self, client, admin_user):
        response = client.get("/api/users?search=admin")
        data = response.json()
        assert data["total"] >= 1
        assert any("admin" in u["email"] for u in data["items"])
