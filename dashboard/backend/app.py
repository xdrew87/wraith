import argparse
import json
import logging
import sys
from datetime import datetime
from pathlib import Path

# Resolve src/ regardless of working directory
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from flask import Flask, jsonify, request, send_file
from flask_cors import CORS

from core.config import load_config
from core.database import (
    init_db, get_db, ExposedCredential, Alert, WatchTarget, FeedStatus
)

app = Flask(__name__)
CORS(app)

logger = logging.getLogger(__name__)

FRONTEND_PATH = Path(__file__).resolve().parent.parent / "frontend" / "index.html"


@app.route("/")
def index():
    return send_file(str(FRONTEND_PATH))


@app.route("/api/v1/stats")
def stats():
    db = get_db()
    try:
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
    finally:
        db.close()


@app.route("/api/v1/findings")
def findings():
    target = request.args.get("target")
    severity = request.args.get("severity")
    source = request.args.get("source")
    limit = int(request.args.get("limit", 100))
    offset = int(request.args.get("offset", 0))

    db = get_db()
    try:
        query = db.query(ExposedCredential)
        if target:
            query = query.filter(ExposedCredential.target == target)
        if severity:
            query = query.filter(ExposedCredential.severity == severity)
        if source:
            query = query.filter(ExposedCredential.source_feed == source)

        total = query.count()
        rows = query.order_by(ExposedCredential.first_seen_at.desc()).offset(offset).limit(limit).all()

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
                "first_seen_at": str(r.first_seen_at),
            }
            for r in rows
        ]
        return jsonify({"total": total, "results": results})
    finally:
        db.close()


@app.route("/api/v1/alerts")
def alerts():
    limit = int(request.args.get("limit", 50))
    db = get_db()
    try:
        rows = db.query(Alert).order_by(Alert.created_at.desc()).limit(limit).all()
        return jsonify([
            {
                "id": a.id,
                "target": a.target,
                "source_feed": a.source_feed,
                "severity": a.severity,
                "message": a.message,
                "sent": a.sent,
                "created_at": str(a.created_at),
            }
            for a in rows
        ])
    finally:
        db.close()


@app.route("/api/v1/targets")
def targets():
    db = get_db()
    try:
        rows = db.query(WatchTarget).order_by(WatchTarget.created_at.desc()).all()
        return jsonify([
            {
                "id": t.id,
                "target": t.target,
                "target_type": t.target_type,
                "active": t.active,
                "created_at": str(t.created_at),
                "last_scanned_at": str(t.last_scanned_at) if t.last_scanned_at else None,
            }
            for t in rows
        ])
    finally:
        db.close()


@app.route("/api/v1/sources")
def sources():
    db = get_db()
    try:
        rows = db.query(FeedStatus).all()
        return jsonify([
            {
                "feed_name": f.feed_name,
                "last_run_at": str(f.last_run_at) if f.last_run_at else None,
                "last_status": f.last_status,
                "last_error": f.last_error,
                "total_results": f.total_results,
            }
            for f in rows
        ])
    finally:
        db.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=5050)
    args = parser.parse_args()

    config_path = Path(__file__).resolve().parents[2] / "config.yaml"
    config = load_config(str(config_path))
    init_db(config)

    app.run(host="0.0.0.0", port=args.port, debug=False)
