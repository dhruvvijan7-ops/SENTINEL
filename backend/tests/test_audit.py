from __future__ import annotations

from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import pytest
from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog
from app.models.alert import Alert
from app.models.analysis_run import AnalysisRun
from app.models.detection import Detection
from app.models.user import User
from app.services.audit_enums import AuditAction, AuditCategory, AuditResult


def _make_trace(calls: list[str]) -> dict:
    return {"sequences": [{"system_calls": calls}]}


class TestAuthEventsLogged:
    def test_login_success(self, client, analyst_user):
        client.post(
            "/api/auth/login",
            json={"email": "analyst@sentinelai.local", "password": "analystpassword123"},
        )
        logs = _query_logs(client)
        assert any(l["action"] == "LOGIN_SUCCESS" and l["result"] == "SUCCESS" for l in logs)

    def test_login_failed(self, client):
        client.post(
            "/api/auth/login",
            json={"email": "admin@sentinelai.local", "password": "wrongpassword"},
        )
        logs = _query_logs(client)
        assert any(l["action"] == "LOGIN_FAILED" and l["result"] == "FAILURE" for l in logs)

    def test_registration(self, client):
        client.post(
            "/api/auth/register",
            json={"name": "New User", "email": "new@test.local", "password": "testpass123"},
        )
        logs = _query_logs(client)
        assert any(l["action"] == "REGISTRATION" and l["result"] == "SUCCESS" for l in logs)

    def test_password_reset_request(self, client, admin_user):
        client.post(
            "/api/auth/forgot-password",
            json={"email": admin_user.email},
        )
        logs = _query_logs(client)
        assert any(l["action"] == "PASSWORD_RESET_REQUESTED" for l in logs)

    def test_password_reset(self, client, admin_user, db):
        from app.services.auth import create_access_token
        token = create_access_token(admin_user.id)
        client.post(
            "/api/auth/reset-password",
            json={"token": token, "new_password": "newpass12345"},
        )
        logs = _query_logs(client)
        assert any(l["action"] == "PASSWORD_RESET_COMPLETED" for l in logs)

    def test_logout(self, client, admin_user):
        resp = client.post("/api/auth/logout")
        assert resp.status_code == 200
        logs = _query_logs(client)
        assert any(l["action"] == "LOGOUT" and l["result"] == "SUCCESS" for l in logs)

    def test_login_captures_user_agent(self, client, analyst_user):
        client.post(
            "/api/auth/login",
            json={"email": "analyst@sentinelai.local", "password": "analystpassword123"},
            headers={"User-Agent": "TestAgent/1.0"},
        )
        logs = _query_logs(client)
        login_log = next((l for l in logs if l["action"] == "LOGIN_SUCCESS"), None)
        assert login_log is not None
        assert login_log.get("user_agent") == "TestAgent/1.0"

    def test_login_captures_actor_type(self, client, analyst_user):
        client.post(
            "/api/auth/login",
            json={"email": "analyst@sentinelai.local", "password": "analystpassword123"},
        )
        logs = _query_logs(client)
        login_log = next((l for l in logs if l["action"] == "LOGIN_SUCCESS"), None)
        assert login_log is not None
        assert login_log.get("actor_type") == "user"


class TestAnalysisEventsLogged:
    def test_file_uploaded_and_analysis_completed(self, client, db):
        trace = _make_trace(["read", "write", "open", "close"])
        client.post(
            "/api/analysis-runs/host-traces",
            files={"file": ("test.json", __import__("json").dumps(trace).encode(), "application/json")},
        )
        logs = _query_logs(client)
        actions = [l["action"] for l in logs]
        assert "JSON_UPLOAD" in actions
        assert "VALIDATION_STARTED" in actions
        assert "VALIDATION_COMPLETED" in actions
        assert "ANALYSIS_STARTED" in actions
        assert "ANALYSIS_COMPLETED" in actions

    def test_csv_upload_detected(self, client, db):
        csv_content = (
            "trace_id,timestamp,syscall_id,syscall_name,pid,ppid,uid,success,info,attack,confidence\n"
            "t1,2024-01-01T00:00:00Z,1,read,1,1,0,true,,,\n"
        )
        resp = client.post(
            "/api/analysis-runs/host-traces",
            files={"file": ("test.csv", csv_content.encode(), "text/csv")},
        )
        if resp.status_code in (200, 201):
            logs = _query_logs(client)
            actions = [l["action"] for l in logs]
            assert "CSV_UPLOAD" in actions

    def test_file_rejected(self, client, db):
        from app.api.routes import analysis as analysis_route
        original = analysis_route.summarize_host_trace

        def reject(*a, **kw):
            from fastapi import HTTPException
            raise HTTPException(status_code=413, detail="File too large")

        analysis_route.summarize_host_trace = reject
        try:
            resp = client.post(
                "/api/analysis-runs/host-traces",
                files={"file": ("big.json", b'{"sequences":[]}', "application/json")},
            )
            assert resp.status_code == 413
            logs = _query_logs(client)
            actions = [l["action"] for l in logs]
            assert "UPLOAD_REJECTED" in actions
            assert "VALIDATION_FAILED" in actions
        finally:
            analysis_route.summarize_host_trace = original

    def test_detection_created(self, client, db):
        trace = _make_trace([
            "socket", "connect", "bind", "listen", "accept",
            "setuid", "setgid",
            "openat", "unlink", "rename",
            "read", "write",
            "sendto", "recvfrom", "sendmsg", "recvmsg",
        ])
        client.post(
            "/api/analysis-runs/host-traces",
            files={"file": ("audit_test.json", __import__("json").dumps(trace).encode(), "application/json")},
        )
        logs = _query_logs(client)
        assert any(l["action"] == "DETECTION_CREATED" for l in logs)


class TestAlertEventsLogged:
    def test_alert_created(self, client, db):
        trace = _make_trace([f"call_{i}" for i in range(600)])
        client.post(
            "/api/analysis-runs/host-traces",
            files={"file": ("alert_test.json", __import__("json").dumps(trace).encode(), "application/json")},
        )
        logs = _query_logs(client)
        assert any(l["action"] == "ALERT_CREATED" for l in logs)

    def test_alert_status_changed(self, client, db):
        alert = Alert(
            id="test-alert-1", severity="high", status="new",
            title="Test Alert", description="test", source="test",
        )
        db.add(alert)
        db.commit()

        client.patch(
            f"/api/alerts/{alert.id}",
            json={"status": "investigating"},
        )
        logs = _query_logs(client)
        assert any(
            l["action"] == "ALERT_STATUS_CHANGED"
            and l["metadata_json"] is not None
            and l["metadata_json"].get("new_status") == "investigating"
            for l in logs
        )

    def test_alert_resolved(self, client, db):
        alert = Alert(
            id="test-alert-2", severity="high", status="investigating",
            title="Test Alert Res", description="test", source="test",
        )
        db.add(alert)
        db.commit()

        client.patch(
            f"/api/alerts/{alert.id}",
            json={"status": "resolved"},
        )
        logs = _query_logs(client)
        assert any(
            l["action"] == "ALERT_RESOLVED"
            and l["metadata_json"] is not None
            and l["metadata_json"].get("new_status") == "resolved"
            for l in logs
        )

    def test_alert_reopened(self, client, db):
        alert = Alert(
            id="test-alert-3", severity="high", status="resolved",
            title="Test Alert Reopen", description="test", source="test",
        )
        db.add(alert)
        db.commit()

        client.patch(
            f"/api/alerts/{alert.id}",
            json={"status": "new"},
        )
        logs = _query_logs(client)
        assert any(l["action"] == "ALERT_REOPENED" for l in logs)


class TestDetectionEventsLogged:
    def test_detection_status_changed(self, client, db):
        det = Detection(
            id="test-det-1", detection_type="test", title="Test",
            description="test", severity="medium", status="new",
        )
        db.add(det)
        db.commit()

        client.patch(
            f"/api/detections/{det.id}",
            json={"status": "investigating"},
        )
        logs = _query_logs(client)
        assert any(
            l["action"] == "DETECTION_STATUS_CHANGED"
            and l["metadata_json"] is not None
            and l["metadata_json"].get("old_status") == "new"
            and l["metadata_json"].get("new_status") == "investigating"
            for l in logs
        )

    def test_detection_viewed(self, client, db):
        det = Detection(
            id="test-det-view", detection_type="test", title="Test View",
            description="test view", severity="low", status="new",
        )
        db.add(det)
        db.commit()

        client.get(f"/api/detections/{det.id}")
        logs = _query_logs(client)
        assert any(l["action"] == "DETECTION_VIEWED" for l in logs)


class TestAdministrationEventsLogged:
    def test_role_changed(self, client, analyst_user):
        client.patch(
            f"/api/users/{analyst_user.id}",
            json={"role": "admin"},
        )
        logs = _query_logs(client)
        assert any(
            l["action"] == "USER_ROLE_CHANGED"
            and l["metadata_json"] is not None
            and l["metadata_json"].get("old_role") == "analyst"
            and l["metadata_json"].get("new_role") == "admin"
            for l in logs
        )
        client.patch(
            f"/api/users/{analyst_user.id}",
            json={"role": "analyst"},
        )

    def test_deactivation(self, client, analyst_user):
        client.patch(
            f"/api/users/{analyst_user.id}",
            json={"is_active": False},
        )
        logs = _query_logs(client)
        assert any(l["action"] == "USER_DEACTIVATED" for l in logs)

    def test_activation(self, client, db, admin_user):
        second = User(
            email="act@test.local", hashed_password="x", name="Act", role="analyst", is_active=False,
        )
        db.add(second)
        db.commit()
        db.refresh(second)

        client.patch(
            f"/api/users/{second.id}",
            json={"is_active": True},
        )
        logs = _query_logs(client)
        assert any(l["action"] == "USER_ACTIVATED" for l in logs)


class TestSystemEventsLogged:
    def test_settings_changed(self, client, db):
        client.patch(
            "/api/system/settings",
            json={"max_upload_mb": 25, "analysis_history_limit": 100},
        )
        logs = _query_logs(client)
        assert any(l["action"] == "SYSTEM_SETTING_CHANGED" for l in logs)
        client.patch(
            "/api/system/settings",
            json={"max_upload_mb": 10, "analysis_history_limit": 50},
        )


class TestQueryAuthorization:
    def test_admin_can_query(self, client):
        resp = client.get("/api/audit-logs")
        assert resp.status_code == 200

    def test_analyst_can_query_read_only(self, analyst_client):
        resp = analyst_client.get("/api/audit-logs")
        assert resp.status_code == 200

    def test_unauthenticated_forbidden(self, unauth_client):
        resp = unauth_client.get("/api/audit-logs")
        assert resp.status_code == 401

    def test_get_log_by_id(self, client, analyst_user):
        client.patch(f"/api/users/{analyst_user.id}", json={"role": "admin"})
        logs = _query_logs(client)
        log_id = logs[0]["id"]
        resp = client.get(f"/api/audit-logs/{log_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == log_id
        assert "user_agent" in data
        assert "request_id" in data
        assert "actor_type" in data
        assert "created_at" in data

    def test_get_log_by_id_not_found(self, client):
        resp = client.get("/api/audit-logs/nonexistent-id")
        assert resp.status_code == 404

    def test_analyst_can_get_log_by_id_read_only(self, analyst_client, db):
        log = AuditLog(
            actor_user_id="analyst_x",
            actor_email="analyst_x@test.local",
            category="AUTHENTICATION",
            action="LOGIN_SUCCESS",
            result="SUCCESS",
            severity="info",
        )
        db.add(log)
        db.commit()
        resp = analyst_client.get(f"/api/audit-logs/{log.id}")
        assert resp.status_code == 200
        assert resp.json()["action"] == "LOGIN_SUCCESS"


class TestFiltering:
    def test_category_filter(self, client, admin_user, analyst_user):
        client.patch(f"/api/users/{analyst_user.id}", json={"role": "admin"})
        client.patch(f"/api/users/{analyst_user.id}", json={"role": "analyst"})
        resp = client.get("/api/audit-logs?category=USER_MANAGEMENT")
        data = resp.json()
        assert all(l["category"] == "USER_MANAGEMENT" for l in data["items"])

    def test_action_filter(self, client, analyst_user):
        client.patch(f"/api/users/{analyst_user.id}", json={"role": "viewer"})
        client.patch(f"/api/users/{analyst_user.id}", json={"role": "analyst"})
        resp = client.get("/api/audit-logs?action=USER_ROLE_CHANGED")
        data = resp.json()
        assert all(l["action"] == "USER_ROLE_CHANGED" for l in data["items"])

    def test_result_filter(self, client):
        client.post(
            "/api/auth/login",
            json={"email": "nonexistent@test.local", "password": "bad"},
        )
        resp = client.get("/api/audit-logs?result=FAILURE")
        data = resp.json()
        assert all(l["result"] == "FAILURE" for l in data["items"])

    def test_actor_filter(self, client, admin_user):
        resp = client.get(f"/api/audit-logs?actor_user_id={admin_user.id}")
        data = resp.json()
        assert all(l["actor_user_id"] == admin_user.id for l in data["items"])

    def test_resource_filter(self, client, analyst_user):
        client.patch(f"/api/users/{analyst_user.id}", json={"role": "admin"})
        client.patch(f"/api/users/{analyst_user.id}", json={"role": "analyst"})
        resp = client.get("/api/audit-logs?resource_type=USER")
        data = resp.json()
        assert all(l["resource_type"] == "USER" for l in data["items"])

    def test_date_filter(self, client, analyst_user):
        now = datetime.now(timezone.utc)
        client.patch(f"/api/users/{analyst_user.id}", json={"role": "admin"})
        from_ts = quote((now - timedelta(minutes=1)).isoformat())
        to_ts = quote((now + timedelta(minutes=1)).isoformat())
        resp = client.get(f"/api/audit-logs?from_timestamp={from_ts}&to_timestamp={to_ts}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1

    def test_second_precision(self, client, analyst_user):
        now = datetime.now(timezone.utc)
        client.patch(f"/api/users/{analyst_user.id}", json={"role": "admin"})
        from_ts = quote(now.isoformat())
        resp = client.get(f"/api/audit-logs?from_timestamp={from_ts}")
        assert resp.status_code == 200

    def test_combined_filters(self, client, analyst_user):
        now = datetime.now(timezone.utc)
        client.patch(f"/api/users/{analyst_user.id}", json={"role": "admin"})
        client.patch(f"/api/users/{analyst_user.id}", json={"role": "analyst"})
        from_ts = quote((now - timedelta(hours=1)).isoformat())
        resp = client.get(f"/api/audit-logs?category=USER_MANAGEMENT&action=USER_ROLE_CHANGED&from_timestamp={from_ts}")
        data = resp.json()
        assert all(
            l["category"] == "USER_MANAGEMENT" and l["action"] == "USER_ROLE_CHANGED"
            for l in data["items"]
        )

    def test_search(self, client, analyst_user, admin_user):
        client.patch(f"/api/users/{analyst_user.id}", json={"role": "admin"})
        resp = client.get(f"/api/audit-logs?search={admin_user.email}")
        data = resp.json()
        assert data["total"] >= 1

    def test_resource_id_filter(self, client, analyst_user):
        client.patch(f"/api/users/{analyst_user.id}", json={"role": "admin"})
        resp = client.get(f"/api/audit-logs?resource_type=USER&resource_id={analyst_user.id}")
        data = resp.json()
        assert all(
            l["resource_type"] == "USER" and l["resource_id"] == analyst_user.id
            for l in data["items"]
        )

    def test_user_agent_filter(self, client, analyst_user):
        client.post(
            "/api/auth/login",
            json={"email": "analyst@sentinelai.local", "password": "analystpassword123"},
            headers={"User-Agent": "UniqueAgent/9.9"},
        )
        resp = client.get("/api/audit-logs?user_agent=UniqueAgent")
        data = resp.json()
        assert data["total"] >= 1
        assert all("UniqueAgent" in (l.get("user_agent") or "") for l in data["items"])


class TestPagination:
    def test_page_size(self, client, analyst_user):
        for _ in range(5):
            client.patch(f"/api/users/{analyst_user.id}", json={"role": "admin"})
            client.patch(f"/api/users/{analyst_user.id}", json={"role": "analyst"})
        resp = client.get("/api/audit-logs?page=1&page_size=2")
        data = resp.json()
        assert len(data["items"]) == 2
        assert data["total"] >= 10
        assert data["page_size"] == 2

    def test_newest_first(self, client, analyst_user):
        client.patch(f"/api/users/{analyst_user.id}", json={"role": "admin"})
        client.patch(f"/api/users/{analyst_user.id}", json={"role": "analyst"})
        resp = client.get("/api/audit-logs?page_size=5")
        data = resp.json()
        timestamps = [l["timestamp"] for l in data["items"]]
        assert timestamps == sorted(timestamps, reverse=True)

    def test_total_pages(self, client, analyst_user):
        for _ in range(5):
            client.patch(f"/api/users/{analyst_user.id}", json={"role": "admin"})
            client.patch(f"/api/users/{analyst_user.id}", json={"role": "analyst"})
        resp = client.get("/api/audit-logs?page_size=3")
        data = resp.json()
        assert data["total_pages"] >= 4


class TestSecurity:
    def test_no_passwords_in_metadata(self, client, analyst_user):
        client.patch(f"/api/users/{analyst_user.id}", json={"role": "admin"})
        client.patch(f"/api/users/{analyst_user.id}", json={"role": "analyst"})
        resp = client.get("/api/audit-logs?page_size=100")
        data = resp.json()
        for log in data["items"]:
            meta = log.get("metadata_json") or {}
            meta_str = str(meta).lower()
            assert "hashed_password" not in meta_str
            assert "secret" not in meta_str

    def test_no_update_delete_endpoints(self, client):
        assert client.patch("/api/audit-logs/fake-id", json={}).status_code in (404, 405)
        assert client.delete("/api/audit-logs/fake-id").status_code in (404, 405)

    def test_actor_email_in_events(self, client, admin_user):
        client.patch(f"/api/users/{admin_user.id}", json={"role": "admin"})
        logs = _query_logs(client)
        admin_logs = [l for l in logs if l["actor_user_id"] == admin_user.id]
        assert all(l["actor_email"] == admin_user.email for l in admin_logs)

    def test_new_fields_present_in_response(self, client, analyst_user):
        client.patch(f"/api/users/{analyst_user.id}", json={"role": "admin"})
        client.patch(f"/api/users/{analyst_user.id}", json={"role": "analyst"})
        logs = _query_logs(client)
        for log in logs:
            assert "user_agent" in log
            assert "request_id" in log
            assert "actor_type" in log
            assert "created_at" in log


def _query_logs(client) -> list[dict]:
    resp = client.get("/api/audit-logs?page_size=100")
    return resp.json()["items"]


class TestAnalystAuditAccess:
    def test_analyst_can_list_audit_logs(self, analyst_client):
        resp = analyst_client.get("/api/audit-logs")
        assert resp.status_code == 200
        assert "items" in resp.json()

    def test_analyst_can_get_audit_log(self, analyst_client, db):
        log = AuditLog(
            actor_user_id="analyst_x",
            actor_email="analyst_x@test.local",
            category="AUTHENTICATION",
            action="LOGIN_SUCCESS",
            result="SUCCESS",
            severity="info",
        )
        db.add(log)
        db.commit()
        resp = analyst_client.get(f"/api/audit-logs/{log.id}")
        assert resp.status_code == 200
        assert resp.json()["action"] == "LOGIN_SUCCESS"


class TestAuditSeverity:
    def test_severity_field_present(self, client, analyst_user):
        client.patch(f"/api/users/{analyst_user.id}", json={"role": "admin"})
        logs = _query_logs(client)
        for log in logs:
            assert "severity" in log
            assert log["severity"] in ("info", "medium", "high")

    def test_severity_classification_failure_events(self, client):
        client.post(
            "/api/auth/login",
            json={"email": "admin@sentinelai.local", "password": "wrong"},
        )
        logs = _query_logs(client)
        failed = [l for l in logs if l["action"] == "LOGIN_FAILED"]
        assert failed
        assert all(l["severity"] == "high" for l in failed)

    def test_filter_by_severity(self, client, db):
        for action, severity in (
            ("LOGIN_SUCCESS", "info"),
            ("SYSTEM_SETTING_CHANGED", "medium"),
            ("LOGIN_FAILED", "high"),
        ):
            db.add(AuditLog(
                actor_user_id="x",
                actor_email="x@test.local",
                category="AUTHENTICATION",
                action=action,
                result="SUCCESS" if severity != "high" else "FAILURE",
                severity=severity,
            ))
        db.commit()

        resp = client.get("/api/audit-logs?severity=high&page_size=100")
        items = resp.json()["items"]
        assert items
        assert all(i["severity"] == "high" for i in items)


class TestAuditIpFilter:
    def test_filter_by_ip_address(self, client, db):
        db.add(AuditLog(
            actor_user_id="a", actor_email="a@test.local",
            category="AUTHENTICATION", action="LOGIN_SUCCESS",
            result="SUCCESS", severity="info", ip_address="203.0.113.7",
        ))
        db.add(AuditLog(
            actor_user_id="b", actor_email="b@test.local",
            category="AUTHENTICATION", action="LOGIN_SUCCESS",
            result="SUCCESS", severity="info", ip_address="198.51.100.9",
        ))
        db.commit()

        resp = client.get("/api/audit-logs?ip_address=203.0.113.7&page_size=100")
        items = resp.json()["items"]
        assert items
        assert all(i["ip_address"] == "203.0.113.7" for i in items)


class TestAuditExport:
    def test_export_csv_returns_csv(self, client, db):
        db.add(AuditLog(
            actor_user_id="a", actor_email="a@test.local",
            category="AUTHENTICATION", action="LOGIN_SUCCESS",
            result="SUCCESS", severity="info",
        ))
        db.commit()

        resp = client.get("/api/audit-logs/export")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/csv")
        text = resp.text
        assert text.startswith("id,timestamp,created_at,actor_user_id,actor_email,actor_type")
        assert "LOGIN_SUCCESS" in text

    def test_export_csv_respects_filters(self, client, db):
        db.add(AuditLog(
            actor_user_id="a", actor_email="a@test.local",
            category="AUTHENTICATION", action="LOGIN_SUCCESS",
            result="SUCCESS", severity="info",
        ))
        db.add(AuditLog(
            actor_user_id="b", actor_email="b@test.local",
            category="AUTHENTICATION", action="LOGIN_FAILED",
            result="FAILURE", severity="high",
        ))
        db.commit()

        resp = client.get("/api/audit-logs/export?action=LOGIN_SUCCESS")
        text = resp.text
        assert "LOGIN_SUCCESS" in text
        assert "LOGIN_FAILED" not in text

    def test_analyst_can_export_csv(self, analyst_client):
        resp = analyst_client.get("/api/audit-logs/export")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/csv")


class TestAnalysisFailedLogged:
    def test_analysis_failed_event(self, client, db):
        from app.api.routes import analysis as analysis_route
        from fastapi import HTTPException

        original = analysis_route.analyse_trace

        def boom(*a, **kw):
            raise RuntimeError("engine exploded")

        analysis_route.analyse_trace = boom
        try:
            trace = _make_trace(["read", "write"])
            resp = client.post(
                "/api/analysis-runs/host-traces",
                files={"file": ("fail.json", __import__("json").dumps(trace).encode(), "application/json")},
            )
            assert resp.status_code == 500
            logs = _query_logs(client)
            failed = [l for l in logs if l["action"] == "ANALYSIS_FAILED"]
            assert failed
            assert all(l["result"] == "FAILURE" for l in failed)
            assert failed[-1]["severity"] == "high"
            assert failed[-1]["resource_type"] == "ANALYSIS_RUN"
        finally:
            analysis_route.analyse_trace = original

    def test_analysis_failed_marks_run_failed(self, client, db):
        from app.api.routes import analysis as analysis_route

        original = analysis_route.analyse_trace

        def boom(*a, **kw):
            raise RuntimeError("engine exploded")

        analysis_route.analyse_trace = boom
        try:
            trace = _make_trace(["read", "write"])
            client.post(
                "/api/analysis-runs/host-traces",
                files={"file": ("fail.json", __import__("json").dumps(trace).encode(), "application/json")},
            )
            run = db.query(AnalysisRun).order_by(AnalysisRun.submitted_at.desc()).first()
            assert run is not None
            assert run.status == "failed"
        finally:
            analysis_route.analyse_trace = original


class TestSystemConfigurationChangedLogged:
    def test_settings_update_emits_configuration_changed(self, client):
        client.patch(
            "/api/system/settings",
            json={"max_upload_mb": 60, "analysis_history_limit": 120},
        )
        logs = _query_logs(client)
        actions = [l["action"] for l in logs]
        assert "SYSTEM_SETTING_CHANGED" in actions
        assert "SYSTEM_CONFIGURATION_CHANGED" in actions

    def test_no_configuration_changed_on_failed_update(self, client):
        client.patch(
            "/api/system/settings",
            json={"max_upload_mb": -5},
        )
        logs = _query_logs(client)
        actions = [l["action"] for l in logs]
        assert "SYSTEM_CONFIGURATION_CHANGED" not in actions
