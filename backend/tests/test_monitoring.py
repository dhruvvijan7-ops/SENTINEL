from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.analysis_run import AnalysisRun
from app.models.detection import Detection
from app.models.network_event import NetworkEvent


def _make_run(db: Session, **kwargs) -> AnalysisRun:
    kwargs.setdefault("file_name", "test.json")
    kwargs.setdefault("event_count", 0)
    kwargs.setdefault("sequence_count", 0)
    run = AnalysisRun(
        source_type="host_trace",
        status="completed",
        details={"unique_system_calls": 5},
        **kwargs,
    )
    db.add(run)
    db.flush()
    return run


def _make_detection(db: Session, run_id: str, **kwargs) -> Detection:
    det = Detection(
        analysis_run_id=run_id,
        detection_type=kwargs.pop("detection_type", "suspicious_call"),
        title=kwargs.pop("title", "Suspicious Activity"),
        description=kwargs.pop("description", "Detected suspicious system call"),
        severity=kwargs.pop("severity", "high"),
        confidence=kwargs.pop("confidence", 80),
        **kwargs,
    )
    db.add(det)
    db.flush()
    return det


def _make_alert(db: Session, detection_id: str, **kwargs) -> Alert:
    alert = Alert(
        detection_id=detection_id,
        severity=kwargs.pop("severity", "high"),
        status=kwargs.pop("status", "new"),
        title=kwargs.pop("title", "Alert Title"),
        description=kwargs.pop("description", "Alert description"),
        source="detection-engine",
        **kwargs,
    )
    db.add(alert)
    db.flush()
    return alert


def _make_network_event(db: Session, run_id: str, **kwargs) -> NetworkEvent:
    ne = NetworkEvent(
        analysis_run_id=run_id,
        source_ip=kwargs.pop("source_ip", "192.168.1.10"),
        destination_ip=kwargs.pop("destination_ip", "10.0.0.5"),
        protocol=kwargs.pop("protocol", "TCP"),
        syscall_name=kwargs.pop("syscall_name", "sendto"),
        description=kwargs.pop("description", "Network event"),
        **kwargs,
    )
    db.add(ne)
    db.flush()
    return ne


class TestMonitoringRunList:
    def test_returns_runs(self, client, db):
        run = _make_run(db, file_name="trace.json", event_count=100)
        _make_detection(db, run.id, severity="high")
        _make_detection(db, run.id, severity="low")
        db.commit()

        resp = client.get("/api/analysis-runs/monitoring")
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert len(data["items"]) >= 1
        item = data["items"][0]
        assert item["file_name"] == "trace.json"
        assert item["event_count"] == 100
        assert item["detection_count"] == 2
        assert item["severity_counts"]["high"] == 1
        assert item["severity_counts"]["low"] == 1

    def test_alert_count_in_monitoring_list(self, client, db):
        run = _make_run(db)
        det = _make_detection(db, run.id)
        _make_alert(db, det.id)
        _make_alert(db, det.id)
        db.commit()

        resp = client.get("/api/analysis-runs/monitoring")
        assert resp.status_code == 200
        item = resp.json()["items"][0]
        assert item["alert_count"] == 2


class TestRunDetail:
    def test_run_detail(self, client, db):
        run = _make_run(db, file_name="detail_test.json")
        _make_detection(db, run.id, severity="critical")
        _make_detection(db, run.id, severity="medium")
        det = _make_detection(db, run.id, severity="high")
        _make_alert(db, det.id)
        db.commit()

        resp = client.get(f"/api/analysis-runs/{run.id}/detail")
        assert resp.status_code == 200
        data = resp.json()
        assert data["file_name"] == "detail_test.json"
        assert data["detection_count"] == 3
        assert data["alert_count"] == 1
        assert data["severity_counts"]["critical"] == 1
        assert data["severity_counts"]["high"] == 1
        assert data["severity_counts"]["medium"] == 1

    def test_run_detail_not_found(self, client):
        resp = client.get("/api/analysis-runs/nonexistent-id/detail")
        assert resp.status_code == 404


class TestRunAlerts:
    def test_alerts_for_run(self, client, db):
        run = _make_run(db)
        det1 = _make_detection(db, run.id)
        det2 = _make_detection(db, run.id)
        _make_alert(db, det1.id, title="Alert 1")
        _make_alert(db, det2.id, title="Alert 2")
        other_run = _make_run(db, file_name="other.json")
        other_det = _make_detection(db, other_run.id)
        _make_alert(db, other_det.id, title="Other Alert")
        db.commit()

        resp = client.get(f"/api/analysis-runs/{run.id}/alerts")
        assert resp.status_code == 200
        alerts = resp.json()
        assert len(alerts) == 2
        titles = {a["title"] for a in alerts}
        assert titles == {"Alert 1", "Alert 2"}

    def test_alerts_not_found(self, client):
        resp = client.get("/api/analysis-runs/bad-id/alerts")
        assert resp.status_code == 404


class TestRunRecords:
    def test_records_returns_detections_and_events(self, client, db):
        run = _make_run(db)
        det = _make_detection(db, run.id, severity="critical", title="Crit Det")
        _make_network_event(
            db, run.id,
            source_ip="10.0.0.1", destination_ip="203.0.113.5",
            syscall_name="connect",
        )
        db.commit()

        resp = client.get(f"/api/analysis-runs/{run.id}/records")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        types = {r["record_type"] for r in data["items"]}
        assert "detection" in types
        assert "network_event" in types

        det_rec = next(r for r in data["items"] if r["record_type"] == "detection")
        assert det_rec["severity"] == "critical"
        assert det_rec["title"] == "Crit Det"

        ev_rec = next(r for r in data["items"] if r["record_type"] == "network_event")
        assert ev_rec["severity"] == "normal"

    def test_records_filter_by_severity(self, client, db):
        run = _make_run(db)
        _make_detection(db, run.id, severity="critical")
        _make_detection(db, run.id, severity="low")
        db.commit()

        resp = client.get(f"/api/analysis-runs/{run.id}/records?severity=critical")
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["severity"] == "critical"

    def test_records_filter_by_type(self, client, db):
        run = _make_run(db)
        _make_detection(db, run.id)
        _make_network_event(db, run.id)
        db.commit()

        resp = client.get(f"/api/analysis-runs/{run.id}/records?type=detection")
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["record_type"] == "detection"

    def test_records_filter_by_search(self, client, db):
        run = _make_run(db)
        _make_detection(db, run.id, title="Port Scan Detected")
        _make_network_event(db, run.id, description="Normal DNS query")
        db.commit()

        resp = client.get(f"/api/analysis-runs/{run.id}/records?search=Port")
        data = resp.json()
        assert data["total"] == 1
        assert "Port Scan" in data["items"][0]["title"]

    def test_records_pagination(self, client, db):
        run = _make_run(db)
        for i in range(5):
            _make_detection(db, run.id, title=f"Det {i}")
        db.commit()

        resp = client.get(f"/api/analysis-runs/{run.id}/records?page=1&page_size=2")
        data = resp.json()
        assert data["total"] == 5
        assert len(data["items"]) == 2
        assert data["total_pages"] == 3

        resp2 = client.get(f"/api/analysis-runs/{run.id}/records?page=3&page_size=2")
        data2 = resp2.json()
        assert len(data2["items"]) == 1

    def test_records_empty_run(self, client, db):
        run = _make_run(db)
        db.commit()

        resp = client.get(f"/api/analysis-runs/{run.id}/records")
        data = resp.json()
        assert data["total"] == 0
        assert data["items"] == []

    def test_records_not_found(self, client):
        resp = client.get("/api/analysis-runs/bad-id/records")
        assert resp.status_code == 404

    def test_records_only_own_run(self, client, db):
        run1 = _make_run(db, file_name="run1.json")
        _make_detection(db, run1.id, title="Run1 Det")
        run2 = _make_run(db, file_name="run2.json")
        _make_detection(db, run2.id, title="Run2 Det")
        db.commit()

        resp = client.get(f"/api/analysis-runs/{run1.id}/records")
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["title"] == "Run1 Det"


class TestMonitoringAuthorization:
    def test_analyst_can_access_monitoring_runs(self, analyst_client, db):
        _make_run(db)
        db.commit()
        resp = analyst_client.get("/api/analysis-runs/monitoring")
        assert resp.status_code == 200

    def test_analyst_can_access_run_detail(self, analyst_client, db):
        run = _make_run(db)
        db.commit()
        resp = analyst_client.get(f"/api/analysis-runs/{run.id}/detail")
        assert resp.status_code == 200

    def test_analyst_can_access_run_records(self, analyst_client, db):
        run = _make_run(db)
        db.commit()
        resp = analyst_client.get(f"/api/analysis-runs/{run.id}/records")
        assert resp.status_code == 200

    def test_analyst_can_access_run_alerts(self, analyst_client, db):
        run = _make_run(db)
        db.commit()
        resp = analyst_client.get(f"/api/analysis-runs/{run.id}/alerts")
        assert resp.status_code == 200

    def test_unauth_cannot_access_monitoring(self, unauth_client):
        resp = unauth_client.get("/api/analysis-runs/monitoring")
        assert resp.status_code == 401
