import argparse
import asyncio
import json
import logging
import os
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from flask import Flask, jsonify, request, send_file, g
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from core.config import load_config
from core.database import (
    init_db, get_db, db_session,
    ExposedCredential, Alert, WatchTarget, FeedStatus,
    InvestigationNote, SavedSearch,
)

app = Flask(__name__)

logger = logging.getLogger(__name__)

FRONTEND_PATH = Path(__file__).resolve().parent.parent / "frontend" / "index.html"

_config: dict = {}

# ---------------------------------------------------------------------------
# Security — CORS (restrict origins via config/env)
# ---------------------------------------------------------------------------
_allowed_origins = os.getenv("DASHBOARD_ALLOWED_ORIGINS", "http://localhost:5050").split(",")
CORS(app, resources={r"/api/*": {"origins": [o.strip() for o in _allowed_origins]}})

# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["300 per minute", "30 per second"],
    storage_uri="memory://",
)


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store"
    # CSP — allows inline scripts/styles needed by the single-file dashboard
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self';"
    )
    return response


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _parse_int(value, default: int, min_val: int = 0, max_val: int = 10000) -> int:
    try:
        return max(min_val, min(max_val, int(value)))
    except (TypeError, ValueError):
        return default


def _serialize_dt(dt) -> str | None:
    if dt is None:
        return None
    return str(dt)[:19]


VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
VALID_TARGET_TYPES = {"domain", "email"}
SEVERITY_WEIGHTS = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1}


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------
@app.errorhandler(404)
def not_found(_e):
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(429)
def rate_limited(_e):
    return jsonify({"error": "Rate limit exceeded"}), 429


@app.errorhandler(500)
def internal_error(e):
    logger.error("Internal server error: %s", e)
    return jsonify({"error": "Internal server error"}), 500


# ---------------------------------------------------------------------------
# Static
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return send_file(str(FRONTEND_PATH))


# ---------------------------------------------------------------------------
# Health / Readiness
# ---------------------------------------------------------------------------
@app.route("/api/v1/health")
@limiter.exempt
def health():
    try:
        with db_session() as db:
            db.execute(__import__("sqlalchemy").text("SELECT 1"))
        return jsonify({"status": "ok", "db": "ok"})
    except Exception as e:
        logger.error("Health check failed: %s", e)
        return jsonify({"status": "degraded", "db": "error", "detail": str(e)}), 503


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------
@app.route("/api/v1/stats")
def stats():
    with db_session() as db:
        total = db.query(ExposedCredential).count()
        critical = db.query(ExposedCredential).filter_by(severity="CRITICAL").count()
        high = db.query(ExposedCredential).filter_by(severity="HIGH").count()
        medium = db.query(ExposedCredential).filter_by(severity="MEDIUM").count()
        low = db.query(ExposedCredential).filter_by(severity="LOW").count()
        targets = db.query(WatchTarget).filter_by(active=True).count()
        unsent_alerts = db.query(Alert).filter_by(sent=False).count()
        return jsonify({
            "total_findings": total,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "active_targets": targets,
            "pending_alerts": unsent_alerts,
        })


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------
@app.route("/api/v1/findings")
def findings():
    target = request.args.get("target", "").strip() or None
    severity = request.args.get("severity", "").strip().upper() or None
    source = request.args.get("source", "").strip() or None
    search = request.args.get("search", "").strip() or None
    limit = _parse_int(request.args.get("limit"), 100, 1, 500)
    offset = _parse_int(request.args.get("offset"), 0, 0)

    if severity and severity not in VALID_SEVERITIES:
        return jsonify({"error": "Invalid severity"}), 400

    with db_session() as db:
        query = db.query(ExposedCredential)
        if target:
            query = query.filter(ExposedCredential.target == target)
        if severity:
            query = query.filter(ExposedCredential.severity == severity)
        if source:
            query = query.filter(ExposedCredential.source_feed == source)
        if search:
            pattern = f"%{search}%"
            query = query.filter(
                ExposedCredential.target.ilike(pattern)
                | ExposedCredential.value.ilike(pattern)
                | ExposedCredential.breach_name.ilike(pattern)
                | ExposedCredential.description.ilike(pattern)
            )

        total = query.count()
        rows = (
            query.order_by(ExposedCredential.first_seen_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

        results = [
            {
                "id": r.id,
                "target": r.target,
                "source_feed": r.source_feed,
                "exposure_type": r.exposure_type,
                "value": r.value,
                "severity": r.severity,
                "breach_name": r.breach_name,
                "breach_date": r.breach_date,
                "description": r.description,
                "first_seen_at": _serialize_dt(r.first_seen_at),
            }
            for r in rows
        ]
        return jsonify({"total": total, "offset": offset, "limit": limit, "results": results})


@app.route("/api/v1/findings/<int:finding_id>")
def finding_detail(finding_id: int):
    with db_session() as db:
        r = db.query(ExposedCredential).filter_by(id=finding_id).first()
        if not r:
            return jsonify({"error": "Not found"}), 404
        notes = db.query(InvestigationNote).filter_by(finding_id=finding_id).all()
        return jsonify({
            "id": r.id,
            "target": r.target,
            "source_feed": r.source_feed,
            "exposure_type": r.exposure_type,
            "value": r.value,
            "severity": r.severity,
            "breach_name": r.breach_name,
            "breach_date": r.breach_date,
            "description": r.description,
            "first_seen_at": _serialize_dt(r.first_seen_at),
            "notes": [
                {
                    "id": n.id,
                    "content": n.content,
                    "created_at": _serialize_dt(n.created_at),
                }
                for n in notes
            ],
        })


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------
@app.route("/api/v1/alerts")
def alerts():
    limit = _parse_int(request.args.get("limit"), 50, 1, 500)
    offset = _parse_int(request.args.get("offset"), 0, 0)
    with db_session() as db:
        query = db.query(Alert).order_by(Alert.created_at.desc())
        total = query.count()
        rows = query.offset(offset).limit(limit).all()
        return jsonify({
            "total": total,
            "results": [
                {
                    "id": a.id,
                    "target": a.target,
                    "source_feed": a.source_feed,
                    "severity": a.severity,
                    "message": a.message,
                    "sent": a.sent,
                    "created_at": _serialize_dt(a.created_at),
                }
                for a in rows
            ]
        })


# ---------------------------------------------------------------------------
# Watch Targets
# ---------------------------------------------------------------------------
@app.route("/api/v1/targets", methods=["GET"])
def targets_list():
    with db_session() as db:
        rows = db.query(WatchTarget).order_by(WatchTarget.created_at.desc()).all()
        return jsonify([
            {
                "id": t.id,
                "target": t.target,
                "target_type": t.target_type,
                "active": t.active,
                "created_at": _serialize_dt(t.created_at),
                "last_scanned_at": _serialize_dt(t.last_scanned_at),
            }
            for t in rows
        ])


@app.route("/api/v1/targets", methods=["POST"])
@limiter.limit("10 per minute")
def targets_add():
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()
    if not target or len(target) > 255:
        return jsonify({"error": "Invalid target"}), 400

    from core.aggregator import detect_target_type
    target_type = detect_target_type(target)

    with db_session() as db:
        existing = db.query(WatchTarget).filter_by(target=target).first()
        if existing:
            if not existing.active:
                existing.active = True
                db.commit()
                return jsonify({"status": "reactivated", "id": existing.id})
            return jsonify({"status": "exists", "id": existing.id})
        wt = WatchTarget(target=target, target_type=target_type, active=True)
        db.add(wt)
        db.commit()
        return jsonify({"status": "created", "id": wt.id}), 201


@app.route("/api/v1/targets/<int:target_id>", methods=["DELETE"])
@limiter.limit("10 per minute")
def targets_delete(target_id: int):
    with db_session() as db:
        wt = db.query(WatchTarget).filter_by(id=target_id).first()
        if not wt:
            return jsonify({"error": "Not found"}), 404
        wt.active = False
        db.commit()
        return jsonify({"status": "deactivated"})


# ---------------------------------------------------------------------------
# Feed Sources
# ---------------------------------------------------------------------------
@app.route("/api/v1/sources")
def sources():
    with db_session() as db:
        rows = db.query(FeedStatus).all()
        return jsonify([
            {
                "feed_name": f.feed_name,
                "last_run_at": _serialize_dt(f.last_run_at),
                "last_status": f.last_status,
                "last_error": f.last_error,
                "total_results": f.total_results,
            }
            for f in rows
        ])


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------
@app.route("/api/v1/timeline")
def timeline():
    days = _parse_int(request.args.get("days"), 30, 1, 365)
    target = request.args.get("target", "").strip() or None

    with db_session() as db:
        from sqlalchemy import func, text

        query = db.query(
            func.date(ExposedCredential.first_seen_at).label("date"),
            ExposedCredential.severity,
            func.count(ExposedCredential.id).label("count"),
        )
        if target:
            query = query.filter(ExposedCredential.target == target)

        query = query.filter(
            ExposedCredential.first_seen_at >= text(f"date('now', '-{days} days')")
        ).group_by("date", ExposedCredential.severity).order_by("date")

        rows = query.all()

    date_map: dict[str, dict] = {}
    for row in rows:
        d = str(row.date)[:10]
        if d not in date_map:
            date_map[d] = {"date": d, "total": 0, "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        date_map[d][row.severity] = row.count
        date_map[d]["total"] += row.count

    return jsonify({"days": days, "data": sorted(date_map.values(), key=lambda x: x["date"])})


# ---------------------------------------------------------------------------
# Risk Scores
# ---------------------------------------------------------------------------
@app.route("/api/v1/risk")
def risk():
    with db_session() as db:
        from sqlalchemy import func

        rows = (
            db.query(
                ExposedCredential.target,
                ExposedCredential.severity,
                func.count(ExposedCredential.id).label("count"),
            )
            .group_by(ExposedCredential.target, ExposedCredential.severity)
            .all()
        )

    target_scores: dict[str, dict] = {}
    for row in rows:
        t = row.target
        if t not in target_scores:
            target_scores[t] = {
                "target": t,
                "score": 0,
                "total": 0,
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
            }
        target_scores[t][row.severity] = row.count
        target_scores[t]["total"] += row.count
        target_scores[t]["score"] += SEVERITY_WEIGHTS.get(row.severity, 0) * row.count

    for entry in target_scores.values():
        entry["score"] = min(100, entry["score"])

    sorted_targets = sorted(target_scores.values(), key=lambda x: x["score"], reverse=True)
    return jsonify(sorted_targets)


# ---------------------------------------------------------------------------
# Investigation Notes
# ---------------------------------------------------------------------------
@app.route("/api/v1/notes", methods=["GET"])
def notes_list():
    finding_id = request.args.get("finding_id")
    target = request.args.get("target", "").strip() or None

    with db_session() as db:
        query = db.query(InvestigationNote)
        if finding_id is not None:
            fid = _parse_int(finding_id, -1, 1)
            if fid < 0:
                return jsonify({"error": "Invalid finding_id"}), 400
            query = query.filter_by(finding_id=fid)
        elif target:
            query = query.filter_by(target=target)
        rows = query.order_by(InvestigationNote.created_at.desc()).all()
        return jsonify([
            {
                "id": n.id,
                "finding_id": n.finding_id,
                "target": n.target,
                "content": n.content,
                "created_at": _serialize_dt(n.created_at),
                "updated_at": _serialize_dt(n.updated_at),
            }
            for n in rows
        ])


@app.route("/api/v1/notes", methods=["POST"])
@limiter.limit("30 per minute")
def notes_create():
    data = request.get_json(silent=True) or {}
    content = (data.get("content") or "").strip()
    target = (data.get("target") or "").strip()
    finding_id = data.get("finding_id")

    if not content or len(content) > 10000:
        return jsonify({"error": "content required (max 10000 chars)"}), 400
    if not target or len(target) > 255:
        return jsonify({"error": "target required"}), 400
    if finding_id is not None:
        finding_id = _parse_int(finding_id, -1, 1)
        if finding_id < 0:
            return jsonify({"error": "Invalid finding_id"}), 400

    with db_session() as db:
        note = InvestigationNote(
            finding_id=finding_id,
            target=target,
            content=content,
        )
        db.add(note)
        db.commit()
        return jsonify({
            "id": note.id,
            "finding_id": note.finding_id,
            "target": note.target,
            "content": note.content,
            "created_at": _serialize_dt(note.created_at),
        }), 201


@app.route("/api/v1/notes/<int:note_id>", methods=["DELETE"])
@limiter.limit("30 per minute")
def notes_delete(note_id: int):
    with db_session() as db:
        note = db.query(InvestigationNote).filter_by(id=note_id).first()
        if not note:
            return jsonify({"error": "Not found"}), 404
        db.delete(note)
        db.commit()
        return jsonify({"status": "deleted"})


# ---------------------------------------------------------------------------
# Saved Searches
# ---------------------------------------------------------------------------
@app.route("/api/v1/searches", methods=["GET"])
def searches_list():
    with db_session() as db:
        rows = db.query(SavedSearch).order_by(SavedSearch.created_at.desc()).all()
        return jsonify([
            {
                "id": s.id,
                "name": s.name,
                "filters": json.loads(s.filters),
                "created_at": _serialize_dt(s.created_at),
            }
            for s in rows
        ])


@app.route("/api/v1/searches", methods=["POST"])
@limiter.limit("20 per minute")
def searches_create():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    filters = data.get("filters")

    if not name or len(name) > 255:
        return jsonify({"error": "name required (max 255 chars)"}), 400
    if not isinstance(filters, dict):
        return jsonify({"error": "filters must be an object"}), 400

    with db_session() as db:
        search = SavedSearch(name=name, filters=json.dumps(filters))
        db.add(search)
        db.commit()
        return jsonify({
            "id": search.id,
            "name": search.name,
            "filters": filters,
            "created_at": _serialize_dt(search.created_at),
        }), 201


@app.route("/api/v1/searches/<int:search_id>", methods=["DELETE"])
@limiter.limit("20 per minute")
def searches_delete(search_id: int):
    with db_session() as db:
        s = db.query(SavedSearch).filter_by(id=search_id).first()
        if not s:
            return jsonify({"error": "Not found"}), 404
        db.delete(s)
        db.commit()
        return jsonify({"status": "deleted"})


# ---------------------------------------------------------------------------
# On-demand Scan Trigger
# ---------------------------------------------------------------------------
@app.route("/api/v1/scan", methods=["POST"])
@limiter.limit("5 per minute")
def trigger_scan():
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()
    if not target or len(target) > 255:
        return jsonify({"error": "target required"}), 400

    def _run():
        from core.aggregator import aggregate as agg
        try:
            asyncio.run(agg(target, _config))
        except Exception as exc:
            logger.error("Background scan failed for %s: %s", target, exc)

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    return jsonify({"status": "queued", "target": target})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=5050)
    parser.add_argument("--host", type=str, default="127.0.0.1")
    args = parser.parse_args()

    config_path = Path(__file__).resolve().parents[2] / "config.yaml"
    _config = load_config(str(config_path))
    init_db(_config)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    app.run(host=args.host, port=args.port, debug=False)
