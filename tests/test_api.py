import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

BASE_CONFIG = {
    "database": {"sqlite_path": ":memory:"},
    "feeds": {
        "hibp": {"enabled": False, "api_key": ""},
        "dehashed": {"enabled": False, "email": "", "api_key": ""},
        "intelx": {"enabled": False, "api_key": ""},
        "pastebin": {"enabled": False},
        "github": {"enabled": False, "token": ""},
    },
    "monitor": {"max_concurrent_feeds": 5},
    "alerting": {"enabled": False},
    "logging": {"level": "ERROR", "file": "logs/test-api.log"},
}


@pytest.fixture
def client():
    import core.database as db_module
    db_module._engine = None
    db_module._SessionLocal = None

    from core.database import init_db
    init_db(BASE_CONFIG)

    import dashboard.backend.app as app_module
    app_module._config = BASE_CONFIG
    app_module.app.config["TESTING"] = True

    # Disable rate limiting in tests
    app_module.limiter.enabled = False

    with app_module.app.test_client() as c:
        yield c


@pytest.fixture
def seeded_client(client):
    """Client with sample data seeded."""
    from core.database import db_session, WatchTarget, ExposedCredential, Alert

    with db_session() as db:
        wt = WatchTarget(target="example.com", target_type="domain", active=True)
        db.add(wt)

        cred = ExposedCredential(
            target="example.com",
            source_feed="HIBP",
            exposure_type="domain_breach",
            value="admin@example.com",
            severity="HIGH",
            breach_name="TestBreach",
            hash="abc123test001",
        )
        db.add(cred)

        alert = Alert(
            target="example.com",
            source_feed="HIBP",
            severity="HIGH",
            message="[HIGH] Test alert",
            sent=False,
        )
        db.add(alert)
        db.commit()

    return client


class TestHealthEndpoint:
    def test_health_returns_ok(self, client):
        r = client.get("/api/v1/health")
        assert r.status_code == 200
        data = r.get_json()
        assert data["status"] == "ok"
        assert data["db"] == "ok"


class TestStatsEndpoint:
    def test_stats_returns_zero_counts(self, client):
        r = client.get("/api/v1/stats")
        assert r.status_code == 200
        data = r.get_json()
        assert "total_findings" in data
        assert "critical" in data
        assert "pending_alerts" in data
        assert data["total_findings"] == 0

    def test_stats_counts_seeded_data(self, seeded_client):
        r = seeded_client.get("/api/v1/stats")
        assert r.status_code == 200
        data = r.get_json()
        assert data["total_findings"] == 1
        assert data["high"] == 1
        assert data["active_targets"] == 1
        assert data["pending_alerts"] == 1


class TestFindingsEndpoint:
    def test_findings_empty(self, client):
        r = client.get("/api/v1/findings")
        assert r.status_code == 200
        data = r.get_json()
        assert data["total"] == 0
        assert data["results"] == []

    def test_findings_returns_seeded(self, seeded_client):
        r = seeded_client.get("/api/v1/findings")
        assert r.status_code == 200
        data = r.get_json()
        assert data["total"] == 1
        assert data["results"][0]["source_feed"] == "HIBP"

    def test_findings_filter_by_severity(self, seeded_client):
        r = seeded_client.get("/api/v1/findings?severity=CRITICAL")
        data = r.get_json()
        assert data["total"] == 0

        r = seeded_client.get("/api/v1/findings?severity=HIGH")
        data = r.get_json()
        assert data["total"] == 1

    def test_findings_invalid_severity_returns_400(self, client):
        r = client.get("/api/v1/findings?severity=UNKNOWN")
        assert r.status_code == 400

    def test_findings_search(self, seeded_client):
        r = seeded_client.get("/api/v1/findings?search=admin")
        data = r.get_json()
        assert data["total"] == 1

    def test_findings_pagination(self, seeded_client):
        r = seeded_client.get("/api/v1/findings?limit=1&offset=0")
        data = r.get_json()
        assert data["limit"] == 1
        assert data["offset"] == 0
        assert len(data["results"]) == 1

    def test_findings_limit_clamped(self, client):
        r = client.get("/api/v1/findings?limit=99999")
        assert r.status_code == 200
        data = r.get_json()
        assert data["limit"] == 500

    def test_finding_detail_not_found(self, client):
        r = client.get("/api/v1/findings/9999")
        assert r.status_code == 404

    def test_finding_detail_returns_data(self, seeded_client):
        findings = seeded_client.get("/api/v1/findings").get_json()
        fid = findings["results"][0]["id"]
        r = seeded_client.get(f"/api/v1/findings/{fid}")
        assert r.status_code == 200
        data = r.get_json()
        assert data["id"] == fid
        assert "notes" in data


class TestAlertsEndpoint:
    def test_alerts_empty(self, client):
        r = client.get("/api/v1/alerts")
        assert r.status_code == 200
        data = r.get_json()
        assert data["total"] == 0

    def test_alerts_returns_seeded(self, seeded_client):
        r = seeded_client.get("/api/v1/alerts")
        data = r.get_json()
        assert data["total"] == 1
        assert data["results"][0]["severity"] == "HIGH"


class TestTargetsEndpoint:
    def test_targets_empty(self, client):
        r = client.get("/api/v1/targets")
        assert r.status_code == 200
        assert r.get_json() == []

    def test_add_target(self, client):
        r = client.post("/api/v1/targets", json={"target": "newdomain.com"})
        assert r.status_code == 201
        data = r.get_json()
        assert data["status"] == "created"
        assert "id" in data

    def test_add_duplicate_target_returns_exists(self, seeded_client):
        r = seeded_client.post("/api/v1/targets", json={"target": "example.com"})
        data = r.get_json()
        assert data["status"] == "exists"

    def test_add_target_missing_body(self, client):
        r = client.post("/api/v1/targets", json={})
        assert r.status_code == 400

    def test_delete_target(self, seeded_client):
        targets = seeded_client.get("/api/v1/targets").get_json()
        tid = targets[0]["id"]
        r = seeded_client.delete(f"/api/v1/targets/{tid}")
        assert r.status_code == 200
        assert r.get_json()["status"] == "deactivated"

    def test_delete_nonexistent_target(self, client):
        r = client.delete("/api/v1/targets/9999")
        assert r.status_code == 404


class TestTimelineEndpoint:
    def test_timeline_returns_structure(self, client):
        r = client.get("/api/v1/timeline")
        assert r.status_code == 200
        data = r.get_json()
        assert "days" in data
        assert "data" in data
        assert isinstance(data["data"], list)

    def test_timeline_days_parameter(self, client):
        r = client.get("/api/v1/timeline?days=7")
        data = r.get_json()
        assert data["days"] == 7


class TestRiskEndpoint:
    def test_risk_empty(self, client):
        r = client.get("/api/v1/risk")
        assert r.status_code == 200
        assert r.get_json() == []

    def test_risk_scores_seeded_data(self, seeded_client):
        r = seeded_client.get("/api/v1/risk")
        data = r.get_json()
        assert len(data) == 1
        assert data[0]["target"] == "example.com"
        assert data[0]["score"] > 0
        assert data[0]["score"] <= 100


class TestNotesEndpoint:
    def _get_finding_id(self, seeded_client):
        return seeded_client.get("/api/v1/findings").get_json()["results"][0]["id"]

    def test_create_note(self, seeded_client):
        fid = self._get_finding_id(seeded_client)
        r = seeded_client.post("/api/v1/notes", json={
            "finding_id": fid,
            "target": "example.com",
            "content": "Test analyst note",
        })
        assert r.status_code == 201
        data = r.get_json()
        assert data["content"] == "Test analyst note"
        assert data["finding_id"] == fid

    def test_create_note_missing_content(self, seeded_client):
        r = seeded_client.post("/api/v1/notes", json={
            "target": "example.com",
            "content": "",
        })
        assert r.status_code == 400

    def test_list_notes_by_finding(self, seeded_client):
        fid = self._get_finding_id(seeded_client)
        seeded_client.post("/api/v1/notes", json={
            "finding_id": fid, "target": "example.com", "content": "Note A"
        })
        r = seeded_client.get(f"/api/v1/notes?finding_id={fid}")
        data = r.get_json()
        assert len(data) >= 1

    def test_delete_note(self, seeded_client):
        fid = self._get_finding_id(seeded_client)
        created = seeded_client.post("/api/v1/notes", json={
            "finding_id": fid, "target": "example.com", "content": "Delete me"
        }).get_json()
        r = seeded_client.delete(f"/api/v1/notes/{created['id']}")
        assert r.status_code == 200
        assert r.get_json()["status"] == "deleted"


class TestSavedSearchesEndpoint:
    def test_create_saved_search(self, client):
        r = client.post("/api/v1/searches", json={
            "name": "Critical HIBP",
            "filters": {"severity": "CRITICAL", "source": "HIBP", "search": ""},
        })
        assert r.status_code == 201
        data = r.get_json()
        assert data["name"] == "Critical HIBP"
        assert data["filters"]["severity"] == "CRITICAL"

    def test_list_saved_searches(self, client):
        client.post("/api/v1/searches", json={"name": "Test", "filters": {"severity": "HIGH"}})
        r = client.get("/api/v1/searches")
        data = r.get_json()
        assert len(data) >= 1

    def test_delete_saved_search(self, client):
        created = client.post("/api/v1/searches", json={
            "name": "ToDelete", "filters": {}
        }).get_json()
        r = client.delete(f"/api/v1/searches/{created['id']}")
        assert r.get_json()["status"] == "deleted"

    def test_create_invalid_filters_type(self, client):
        r = client.post("/api/v1/searches", json={"name": "Bad", "filters": "not-a-dict"})
        assert r.status_code == 400


class TestSecurityHeaders:
    def test_security_headers_present(self, client):
        r = client.get("/api/v1/health")
        assert r.headers.get("X-Content-Type-Options") == "nosniff"
        assert r.headers.get("X-Frame-Options") == "DENY"
        assert "Content-Security-Policy" in r.headers
        assert r.headers.get("Cache-Control") == "no-store"
