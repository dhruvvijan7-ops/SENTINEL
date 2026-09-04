from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.detection import Detection


def _make_detection(
    db: Session,
    *,
    title: str = "Test detection",
    severity: str = "high",
    status: str = "new",
    analysis_run_id: str | None = None,
    detection_type: str = "test_rule",
) -> Detection:
    detection = Detection(
        id=str(uuid4()),
        analysis_run_id=analysis_run_id,
        detection_type=detection_type,
        title=title,
        description="Test description",
        severity=severity,
        status=status,
        confidence=75,
        source_ip="10.0.0.1",
        destination_ip="192.168.1.1",
        protocol="tcp",
        evidence={"rule": "test_rule"},
    )
    db.add(detection)
    db.commit()
    db.refresh(detection)
    return detection


def _make_alert(
    db: Session,
    detection_id: str,
    *,
    severity: str = "high",
    status: str = "new",
) -> Alert:
    alert = Alert(
        id=str(uuid4()),
        detection_id=detection_id,
        severity=severity,
        status=status,
        title="Test alert",
        description="Alert description",
        source="detection-engine",
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert


# ─── GET /api/detections ───────────────────────────────────────────


class TestListDetections:
    def test_list_empty(self, client):
        response = client.get("/api/detections")
        assert response.status_code == 200
        data = response.json()
        assert data["items"] == []
        assert data["total"] == 0

    def test_list_returns_detections(self, client, db):
        _make_detection(db, title="Alpha")
        _make_detection(db, title="Beta", severity="critical")
        response = client.get("/api/detections")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 2
        assert len(data["items"]) == 2

    def test_list_filter_severity(self, client, db):
        _make_detection(db, severity="high")
        _make_detection(db, severity="critical")
        _make_detection(db, severity="low")
        response = client.get("/api/detections?severity=critical")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert data["items"][0]["severity"] == "critical"

    def test_list_search(self, client, db):
        _make_detection(db, title="Privilege escalation attempt")
        _make_detection(db, title="Network anomaly")
        response = client.get("/api/detections?search=privilege")
        assert response.status_code == 200
        assert response.json()["total"] == 1

    def test_list_pagination(self, client, db):
        for i in range(5):
            _make_detection(db, title=f"Detection {i}")
        response = client.get("/api/detections?page=1&page_size=2")
        data = response.json()
        assert data["total"] == 5
        assert len(data["items"]) == 2
        assert data["total_pages"] == 3

    def test_list_unauthenticated(self, unauth_client):
        response = unauth_client.get("/api/detections")
        assert response.status_code == 401


# ─── GET /api/detections/{detection_id} ────────────────────────────


class TestGetDetection:
    def test_get_detail(self, client, db):
        detection = _make_detection(db)
        _make_alert(db, detection.id)
        response = client.get(f"/api/detections/{detection.id}")
        assert response.status_code == 200
        data = response.json()
        assert data["detection"]["id"] == detection.id
        assert data["detection"]["title"] == "Test detection"
        assert len(data["alerts"]) == 1
        assert data["alerts"][0]["detection_id"] == detection.id

    def test_get_detail_no_alerts(self, client, db):
        detection = _make_detection(db)
        response = client.get(f"/api/detections/{detection.id}")
        assert response.status_code == 200
        data = response.json()
        assert data["alerts"] == []

    def test_get_detail_with_analysis_run(self, client, db):
        from app.models.analysis_run import AnalysisRun

        run = AnalysisRun(
            id=str(uuid4()),
            source_type="host_trace",
            file_name="test.csv",
            status="completed",
            event_count=100,
            sequence_count=10,
            details={"unique_system_calls": 25},
        )
        db.add(run)
        db.commit()

        detection = _make_detection(db, analysis_run_id=run.id)
        response = client.get(f"/api/detections/{detection.id}")
        assert response.status_code == 200
        data = response.json()
        assert data["analysis_run"]["id"] == run.id
        assert data["analysis_run"]["event_count"] == 100
        assert data["other_detections_in_run"] == 0

    def test_get_detail_other_detections_counted(self, client, db):
        from app.models.analysis_run import AnalysisRun

        run = AnalysisRun(
            id=str(uuid4()),
            source_type="host_trace",
            file_name="test.csv",
            status="completed",
            event_count=50,
            sequence_count=5,
            details={},
        )
        db.add(run)
        db.commit()

        primary = _make_detection(db, analysis_run_id=run.id)
        _make_detection(db, analysis_run_id=run.id, title="Sibling 1")
        _make_detection(db, analysis_run_id=run.id, title="Sibling 2")

        response = client.get(f"/api/detections/{primary.id}")
        assert response.status_code == 200
        assert response.json()["other_detections_in_run"] == 2

    def test_get_detail_not_found(self, client):
        response = client.get("/api/detections/nonexistent-id")
        assert response.status_code == 404

    def test_get_detail_unauthenticated(self, unauth_client, db):
        detection = _make_detection(db)
        response = unauth_client.get(f"/api/detections/{detection.id}")
        assert response.status_code == 401


# ─── PATCH /api/detections/{detection_id} ──────────────────────────


class TestUpdateDetection:
    def test_update_status_investigating(self, client, db):
        detection = _make_detection(db, status="new")
        response = client.patch(
            f"/api/detections/{detection.id}",
            json={"status": "investigating"},
        )
        assert response.status_code == 200
        assert response.json()["status"] == "investigating"

    def test_update_status_resolved(self, client, db):
        detection = _make_detection(db, status="investigating")
        response = client.patch(
            f"/api/detections/{detection.id}",
            json={"status": "resolved"},
        )
        assert response.status_code == 200
        assert response.json()["status"] == "resolved"

    def test_update_status_reopen(self, client, db):
        detection = _make_detection(db, status="resolved")
        response = client.patch(
            f"/api/detections/{detection.id}",
            json={"status": "new"},
        )
        assert response.status_code == 200
        assert response.json()["status"] == "new"

    def test_update_invalid_status(self, client, db):
        detection = _make_detection(db)
        response = client.patch(
            f"/api/detections/{detection.id}",
            json={"status": "invalid_status"},
        )
        assert response.status_code == 422

    def test_update_not_found(self, client):
        response = client.patch(
            "/api/detections/nonexistent-id",
            json={"status": "resolved"},
        )
        assert response.status_code == 404

    def test_update_also_changes_alert_status_via_separate_call(self, client, db):
        detection = _make_detection(db, status="new")
        alert = _make_alert(db, detection.id, status="new")

        # Update detection
        response = client.patch(
            f"/api/detections/{detection.id}",
            json={"status": "investigating"},
        )
        assert response.status_code == 200

        # Alert status is independent (can be updated via alerts endpoint)
        alert_response = client.patch(
            f"/api/alerts/{alert.id}",
            json={"status": "investigating"},
        )
        assert alert_response.status_code == 200
        assert alert_response.json()["status"] == "investigating"


# ─── GET /api/detections/{detection_id}/alerts ─────────────────────


class TestDetectionAlerts:
    def test_get_alerts(self, client, db):
        detection = _make_detection(db)
        _make_alert(db, detection.id)
        _make_alert(db, detection.id, severity="low")
        response = client.get(f"/api/detections/{detection.id}/alerts")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2

    def test_get_alerts_empty(self, client, db):
        detection = _make_detection(db)
        response = client.get(f"/api/detections/{detection.id}/alerts")
        assert response.status_code == 200
        assert response.json() == []

    def test_get_alerts_not_found(self, client):
        response = client.get("/api/detections/nonexistent-id/alerts")
        assert response.status_code == 404

    def test_get_alerts_unauthenticated(self, unauth_client, db):
        detection = _make_detection(db)
        response = unauth_client.get(f"/api/detections/{detection.id}/alerts")
        assert response.status_code == 401
