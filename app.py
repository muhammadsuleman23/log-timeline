from collections import Counter
from datetime import datetime
from flask import Flask, jsonify, render_template, request
from log_parser import get_events

app = Flask(__name__)

RANGES = {
    "1h": "1 hour ago",
    "6h": "6 hours ago",
    "24h": "24 hours ago",
    "7d": "7 days ago",
}

ALERT_WINDOW_SEC = 300   # 5 minute
ALERT_THRESHOLD = 3      # kam az kam itne failed logins


def detect_alerts(events):
    """Failed logins ke woh groups dhoondo jo 5 minute ke andar andar hon."""
    times = sorted(
        datetime.fromisoformat(e["time"])
        for e in events if e["type"] == "failed_login"
    )
    alerts, cluster = [], []

    def flush():
        if len(cluster) >= ALERT_THRESHOLD:
            alerts.append({
                "start": cluster[0].isoformat(timespec="seconds"),
                "end": cluster[-1].isoformat(timespec="seconds"),
                "count": len(cluster),
            })

    for t in times:
        if cluster and (t - cluster[-1]).total_seconds() > ALERT_WINDOW_SEC:
            flush()
            cluster = [t]
        else:
            cluster.append(t)
    flush()
    return alerts


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/events")
def events():
    key = request.args.get("range", "24h")
    since = RANGES.get(key, RANGES["24h"])
    data = get_events(since=since)
    counts = Counter(e["type"] for e in data)
    return jsonify({
        "range": key,
        "total": len(data),
        "counts": counts,
        "alerts": detect_alerts(data),
        "events": data,
    })


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)
