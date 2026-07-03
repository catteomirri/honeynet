"""
dashboard/app.py
Dashboard web locale per il sistema di detection ransomware.
Espone API REST lette dal frontend via polling, più le route per il replay
degli incidenti storici.
"""
import os
import sys
from flask import Flask, jsonify, render_template, request

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from storage import db

app = Flask(__name__, static_folder="static", template_folder="templates")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/events")
def api_events():
    limit = int(request.args.get("limit", 100))
    return jsonify(db.get_recent_events(limit))


@app.route("/api/alerts")
def api_alerts():
    limit = int(request.args.get("limit", 50))
    return jsonify(db.get_alerts(limit))


@app.route("/api/incidents")
def api_incidents():
    return jsonify(db.get_incidents())


@app.route("/api/incidents/<int:incident_id>/replay")
def api_replay(incident_id):
    return jsonify(db.get_incident_timeline(incident_id))


@app.route("/api/stats")
def api_stats():
    events = db.get_recent_events(1000)
    alerts = db.get_alerts(1000)
    incidents = db.get_incidents()
    return jsonify({
        "total_events": len(events),
        "total_alerts": len(alerts),
        "active_incidents": len([i for i in incidents if i["status"] == "active"]),
        "contained_incidents": len([i for i in incidents if i["status"] == "contained"]),
        "decoy_hits": len([e for e in events if e["is_decoy"]]),
    })


if __name__ == "__main__":
    db.init_db()
    app.run(host="127.0.0.1", port=5050, debug=False)
