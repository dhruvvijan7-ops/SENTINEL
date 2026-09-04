from __future__ import annotations

import json
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.network_event import NetworkEvent
from app.services.host_trace import summarize_host_trace


def _seed_network_events(db: Session, analysis_run_id: str, count: int = 10) -> list[NetworkEvent]:
    events = []
    for i in range(count):
        ne = NetworkEvent(
            id=str(uuid4()),
            analysis_run_id=analysis_run_id,
            timestamp=datetime(2026, 8, 25, 10, i % 60, i % 60, tzinfo=timezone.utc),
            source_ip=f"10.0.0.{i % 5 + 1}",
            destination_ip=f"192.168.1.{(i * 7) % 100 + 1}",
            source_port=30000 + i,
            destination_port=443 if i % 3 == 0 else 80 if i % 3 == 1 else 22,
            protocol="TCP",
            connection_id=f"conn-{i}",
            syscall_name="connect" if i % 2 == 0 else "sendto",
            sequence_index=0,
            event_index=i,
        )
        db.add(ne)
        events.append(ne)
    db.commit()
    return events


class TestNetworkEventsAuth:
    def test_unauthenticated_events(self, unauth_client: TestClient):
        r = unauth_client.get("/api/network/events")
        assert r.status_code == 401

    def test_unauthenticated_summary(self, unauth_client: TestClient):
        r = unauth_client.get("/api/network/summary")
        assert r.status_code == 401

    def test_unauthenticated_ports(self, unauth_client: TestClient):
        r = unauth_client.get("/api/network/ports")
        assert r.status_code == 401

    def test_unauthenticated_protocols(self, unauth_client: TestClient):
        r = unauth_client.get("/api/network/protocols")
        assert r.status_code == 401

    def test_unauthenticated_top_talkers(self, unauth_client: TestClient):
        r = unauth_client.get("/api/network/top-talkers")
        assert r.status_code == 401

    def test_unauthenticated_timeline(self, unauth_client: TestClient):
        r = unauth_client.get("/api/network/timeline")
        assert r.status_code == 401

    def test_analyst_can_access_events(self, analyst_client: TestClient):
        r = analyst_client.get("/api/network/events")
        assert r.status_code == 200
        assert "items" in r.json()
        assert "total" in r.json()


class TestNetworkEventsList:
    def test_empty_events(self, client: TestClient):
        r = client.get("/api/network/events")
        assert r.status_code == 200
        data = r.json()
        assert data["items"] == []
        assert data["total"] == 0

    def test_events_returned(self, client: TestClient, db: Session):
        from app.models.analysis_run import AnalysisRun
        run = AnalysisRun(source_type="host_trace", file_name="test.json", status="completed", event_count=0, sequence_count=0)
        db.add(run)
        db.flush()
        _seed_network_events(db, run.id, 5)
        r = client.get("/api/network/events")
        assert r.status_code == 200
        assert r.json()["total"] == 5

    def test_pagination(self, client: TestClient, db: Session):
        from app.models.analysis_run import AnalysisRun
        run = AnalysisRun(source_type="host_trace", file_name="test.json", status="completed", event_count=0, sequence_count=0)
        db.add(run)
        db.flush()
        _seed_network_events(db, run.id, 15)
        r = client.get("/api/network/events?page=1&page_size=5")
        data = r.json()
        assert len(data["items"]) == 5
        assert data["total"] == 15
        assert data["total_pages"] == 3

    def test_source_ip_filter(self, client: TestClient, db: Session):
        from app.models.analysis_run import AnalysisRun
        run = AnalysisRun(source_type="host_trace", file_name="test.json", status="completed", event_count=0, sequence_count=0)
        db.add(run)
        db.flush()
        _seed_network_events(db, run.id, 10)
        r = client.get("/api/network/events?source_ip=10.0.0.1")
        assert r.status_code == 200
        for item in r.json()["items"]:
            assert item["source_ip"] == "10.0.0.1"

    def test_destination_ip_filter(self, client: TestClient, db: Session):
        from app.models.analysis_run import AnalysisRun
        run = AnalysisRun(source_type="host_trace", file_name="test.json", status="completed", event_count=0, sequence_count=0)
        db.add(run)
        db.flush()
        _seed_network_events(db, run.id, 10)
        r = client.get("/api/network/events?destination_ip=192.168.1.15")
        assert r.status_code == 200
        for item in r.json()["items"]:
            assert item["destination_ip"] == "192.168.1.15"

    def test_port_filter(self, client: TestClient, db: Session):
        from app.models.analysis_run import AnalysisRun
        run = AnalysisRun(source_type="host_trace", file_name="test.json", status="completed", event_count=0, sequence_count=0)
        db.add(run)
        db.flush()
        _seed_network_events(db, run.id, 10)
        r = client.get("/api/network/events?destination_port=443")
        assert r.status_code == 200
        for item in r.json()["items"]:
            assert item["destination_port"] == 443

    def test_protocol_filter(self, client: TestClient, db: Session):
        from app.models.analysis_run import AnalysisRun
        run = AnalysisRun(source_type="host_trace", file_name="test.json", status="completed", event_count=0, sequence_count=0)
        db.add(run)
        db.flush()
        _seed_network_events(db, run.id, 10)
        r = client.get("/api/network/events?protocol=TCP")
        assert r.status_code == 200
        assert r.json()["total"] == 10

    def test_search_filter(self, client: TestClient, db: Session):
        from app.models.analysis_run import AnalysisRun
        run = AnalysisRun(source_type="host_trace", file_name="test.json", status="completed", event_count=0, sequence_count=0)
        db.add(run)
        db.flush()
        _seed_network_events(db, run.id, 10)
        r = client.get("/api/network/events?search=10.0.0.1")
        assert r.status_code == 200
        assert r.json()["total"] > 0

    def test_combined_filters(self, client: TestClient, db: Session):
        from app.models.analysis_run import AnalysisRun
        run = AnalysisRun(source_type="host_trace", file_name="test.json", status="completed", event_count=0, sequence_count=0)
        db.add(run)
        db.flush()
        _seed_network_events(db, run.id, 10)
        r = client.get("/api/network/events?protocol=TCP&destination_port=443&source_ip=10.0.0.1")
        assert r.status_code == 200
        for item in r.json()["items"]:
            assert item["protocol"] == "TCP"
            assert item["destination_port"] == 443
            assert item["source_ip"] == "10.0.0.1"

    def test_time_filter(self, client: TestClient, db: Session):
        from app.models.analysis_run import AnalysisRun
        run = AnalysisRun(source_type="host_trace", file_name="test.json", status="completed", event_count=0, sequence_count=0)
        db.add(run)
        db.flush()
        _seed_network_events(db, run.id, 10)
        r = client.get("/api/network/events?from_timestamp=2026-08-25T10:00:00Z&to_timestamp=2026-08-25T10:05:00Z")
        assert r.status_code == 200
        for item in r.json()["items"]:
            ts = item["timestamp"]
            if ts:
                assert "2026-08-25" in ts

    def test_analysis_run_id_filter(self, client: TestClient, db: Session):
        from app.models.analysis_run import AnalysisRun
        run1 = AnalysisRun(source_type="host_trace", file_name="a.json", status="completed", event_count=0, sequence_count=0)
        run2 = AnalysisRun(source_type="host_trace", file_name="b.json", status="completed", event_count=0, sequence_count=0)
        db.add_all([run1, run2])
        db.flush()
        _seed_network_events(db, run1.id, 5)
        _seed_network_events(db, run2.id, 5)
        r = client.get(f"/api/network/events?analysis_run_id={run1.id}")
        assert r.json()["total"] == 5

    def test_invalid_timestamp_handled(self, client: TestClient):
        r = client.get("/api/network/events?from_timestamp=not-a-date")
        assert r.status_code == 200


class TestNetworkSummary:
    def test_empty_summary(self, client: TestClient):
        r = client.get("/api/network/summary")
        assert r.status_code == 200
        data = r.json()
        assert data["total_events"] == 0
        assert data["protocols_observed"] == []

    def test_summary_with_data(self, client: TestClient, db: Session):
        from app.models.analysis_run import AnalysisRun
        run = AnalysisRun(source_type="host_trace", file_name="test.json", status="completed", event_count=0, sequence_count=0)
        db.add(run)
        db.flush()
        _seed_network_events(db, run.id, 10)
        r = client.get("/api/network/summary")
        assert r.status_code == 200
        data = r.json()
        assert data["total_events"] == 10
        assert data["unique_source_ips"] > 0
        assert data["unique_destination_ips"] > 0
        assert "TCP" in data["protocols_observed"]

    def test_summary_with_analysis_run_filter(self, client: TestClient, db: Session):
        from app.models.analysis_run import AnalysisRun
        run1 = AnalysisRun(source_type="host_trace", file_name="a.json", status="completed", event_count=0, sequence_count=0)
        run2 = AnalysisRun(source_type="host_trace", file_name="b.json", status="completed", event_count=0, sequence_count=0)
        db.add_all([run1, run2])
        db.flush()
        _seed_network_events(db, run1.id, 5)
        r = client.get(f"/api/network/summary?analysis_run_id={run1.id}")
        assert r.json()["total_events"] == 5


class TestNetworkIPDetail:
    def test_nonexistent_ip(self, client: TestClient):
        r = client.get("/api/network/ips/10.99.99.99")
        assert r.status_code == 200
        data = r.json()
        assert data["total_events"] == 0
        assert data["ip_address"] == "10.99.99.99"

    def test_ip_detail(self, client: TestClient, db: Session):
        from app.models.analysis_run import AnalysisRun
        run = AnalysisRun(source_type="host_trace", file_name="test.json", status="completed", event_count=0, sequence_count=0)
        db.add(run)
        db.flush()
        _seed_network_events(db, run.id, 10)
        r = client.get("/api/network/ips/10.0.0.1")
        assert r.status_code == 200
        data = r.json()
        assert data["ip_address"] == "10.0.0.1"
        assert data["total_events"] > 0
        assert data["protocols"] != []


class TestNetworkPorts:
    def test_empty_ports(self, client: TestClient):
        r = client.get("/api/network/ports")
        assert r.status_code == 200
        assert r.json()["items"] == []

    def test_ports_with_data(self, client: TestClient, db: Session):
        from app.models.analysis_run import AnalysisRun
        run = AnalysisRun(source_type="host_trace", file_name="test.json", status="completed", event_count=0, sequence_count=0)
        db.add(run)
        db.flush()
        _seed_network_events(db, run.id, 10)
        r = client.get("/api/network/ports")
        assert r.status_code == 200
        data = r.json()
        assert len(data["items"]) > 0
        for port in data["items"]:
            assert "port" in port
            assert "event_count" in port
            assert port["event_count"] > 0


class TestNetworkProtocols:
    def test_empty_protocols(self, client: TestClient):
        r = client.get("/api/network/protocols")
        assert r.status_code == 200
        assert r.json()["items"] == []

    def test_protocols_with_data(self, client: TestClient, db: Session):
        from app.models.analysis_run import AnalysisRun
        run = AnalysisRun(source_type="host_trace", file_name="test.json", status="completed", event_count=0, sequence_count=0)
        db.add(run)
        db.flush()
        _seed_network_events(db, run.id, 10)
        r = client.get("/api/network/protocols")
        assert r.status_code == 200
        items = r.json()["items"]
        assert len(items) > 0
        total_pct = sum(i["percentage"] for i in items)
        assert abs(total_pct - 100.0) < 0.1 or total_pct == 100.0


class TestNetworkTopTalkers:
    def test_empty_top_talkers(self, client: TestClient):
        r = client.get("/api/network/top-talkers")
        assert r.status_code == 200
        assert r.json()["items"] == []

    def test_top_talkers_with_data(self, client: TestClient, db: Session):
        from app.models.analysis_run import AnalysisRun
        run = AnalysisRun(source_type="host_trace", file_name="test.json", status="completed", event_count=0, sequence_count=0)
        db.add(run)
        db.flush()
        _seed_network_events(db, run.id, 10)
        r = client.get("/api/network/top-talkers")
        assert r.status_code == 200
        items = r.json()["items"]
        assert len(items) > 0
        for item in items:
            assert "ip_address" in item
            assert "connection_count" in item
            assert item["connection_count"] > 0

    def test_top_talkers_limit(self, client: TestClient, db: Session):
        from app.models.analysis_run import AnalysisRun
        run = AnalysisRun(source_type="host_trace", file_name="test.json", status="completed", event_count=0, sequence_count=0)
        db.add(run)
        db.flush()
        _seed_network_events(db, run.id, 20)
        r = client.get("/api/network/top-talkers?limit=3")
        assert len(r.json()["items"]) <= 3


class TestNetworkTimeline:
    def test_empty_timeline(self, client: TestClient):
        r = client.get("/api/network/timeline")
        assert r.status_code == 200
        data = r.json()
        assert data["items"] == []
        assert data["interval"] == "none"

    def test_timeline_with_data(self, client: TestClient, db: Session):
        from app.models.analysis_run import AnalysisRun
        run = AnalysisRun(source_type="host_trace", file_name="test.json", status="completed", event_count=0, sequence_count=0)
        db.add(run)
        db.flush()
        _seed_network_events(db, run.id, 10)
        r = client.get("/api/network/timeline")
        assert r.status_code == 200
        data = r.json()
        assert len(data["items"]) > 0
        assert data["interval"] in ("minute", "hour", "day")


class TestNetworkEventDetail:
    def test_nonexistent_event(self, client: TestClient):
        r = client.get(f"/api/network/events/{uuid4()}")
        assert r.status_code == 404

    def test_event_detail(self, client: TestClient, db: Session):
        from app.models.analysis_run import AnalysisRun
        run = AnalysisRun(source_type="host_trace", file_name="test.json", status="completed", event_count=0, sequence_count=0)
        db.add(run)
        db.flush()
        events = _seed_network_events(db, run.id, 3)
        r = client.get(f"/api/network/events/{events[0].id}")
        assert r.status_code == 200
        data = r.json()
        assert data["event"]["id"] == events[0].id
        assert "related_detections" in data
        assert "related_alerts" in data


class TestSQLInjectionSafety:
    def test_source_ip_injection(self, client: TestClient):
        r = client.get("/api/network/events?source_ip='; DROP TABLE network_events; --")
        assert r.status_code == 200

    def test_protocol_injection(self, client: TestClient):
        r = client.get("/api/network/events?protocol=' OR 1=1 --")
        assert r.status_code == 200

    def test_search_injection(self, client: TestClient):
        r = client.get("/api/network/events?search=' UNION SELECT * FROM users --")
        assert r.status_code == 200


class TestUploadWithNetworkEvents:
    def test_json_upload_with_network_events(self, client: TestClient, db: Session):
        payload = {
            "sequences": [
                {
                    "system_calls": ["socket", "connect", "sendto"],
                    "network_events": [
                        {
                            "timestamp": "2026-08-25T10:00:00Z",
                            "source_ip": "10.0.0.1",
                            "destination_ip": "8.8.8.8",
                            "source_port": 44523,
                            "destination_port": 53,
                            "protocol": "UDP",
                            "connection_id": "conn-1",
                        },
                        {
                            "timestamp": "2026-08-25T10:00:01Z",
                            "source_ip": "10.0.0.1",
                            "destination_ip": "1.1.1.1",
                            "source_port": 44524,
                            "destination_port": 443,
                            "protocol": "TCP",
                            "connection_id": "conn-2",
                        },
                    ],
                }
            ]
        }
        content = json.dumps(payload).encode()
        r = client.post(
            "/api/analysis-runs/host-traces",
            files={"file": ("trace.json", content, "application/json")},
        )
        assert r.status_code == 201
        run_id = r.json()["id"]

        r2 = client.get(f"/api/network/events?analysis_run_id={run_id}")
        assert r2.status_code == 200
        assert r2.json()["total"] == 2

    def test_json_upload_without_network_events(self, client: TestClient, db: Session):
        payload = {
            "sequences": [
                {"system_calls": ["open", "read", "write", "close"]}
            ]
        }
        content = json.dumps(payload).encode()
        r = client.post(
            "/api/analysis-runs/host-traces",
            files={"file": ("trace.json", content, "application/json")},
        )
        assert r.status_code == 201
        run_id = r.json()["id"]

        r2 = client.get(f"/api/network/events?analysis_run_id={run_id}")
        assert r2.status_code == 200
        assert r2.json()["total"] == 0

    def test_csv_upload_with_network_columns(self, client: TestClient, db: Session):
        csv_content = (
            "trace_id,timestamp,syscall_name,source_ip,destination_ip,source_port,destination_port,protocol,connection_id\n"
            "0,2026-08-25T10:00:00Z,connect,10.0.0.1,8.8.8.8,44523,53,UDP,conn-1\n"
            "0,2026-08-25T10:00:01Z,sendto,10.0.0.1,1.1.1.1,44524,443,TCP,conn-2\n"
        ).encode()
        r = client.post(
            "/api/analysis-runs/host-traces",
            files={"file": ("trace.csv", csv_content, "text/csv")},
        )
        assert r.status_code == 201
        run_id = r.json()["id"]

        r2 = client.get(f"/api/network/events?analysis_run_id={run_id}")
        assert r2.status_code == 200
        assert r2.json()["total"] == 2


class TestNetworkDetectionEngine:
    def test_excessive_connections_detection(self, client: TestClient, db: Session):
        from app.models.analysis_run import AnalysisRun
        run = AnalysisRun(source_type="host_trace", file_name="test.json", status="completed", event_count=0, sequence_count=0)
        db.add(run)
        db.flush()

        events = []
        for i in range(12):
            ne = NetworkEvent(
                id=str(uuid4()),
                analysis_run_id=run.id,
                timestamp=datetime(2026, 8, 25, 10, 0, i, tzinfo=timezone.utc),
                source_ip="10.0.0.1",
                destination_ip=f"192.168.1.{i + 1}",
                source_port=30000 + i,
                destination_port=443,
                protocol="TCP",
                sequence_index=0,
                event_index=i,
            )
            db.add(ne)
            events.append(ne)
        db.flush()

        from app.detection.pipeline import analyse_network_events
        det, alert = analyse_network_events(network_events=events, analysis_run_id=run.id, db=db)

        types = [d.detection_type for d in det]
        assert "excessive_connection_attempts" in types
        assert len(alert) >= 1
