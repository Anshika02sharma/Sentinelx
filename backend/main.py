
from fastapi import FastAPI
from datetime import datetime, timezone

app = FastAPI(
    title="SENTINELX",
    description="Security Detection and Incident Investigation API",
    version="0.1.0",
)


@app.get("/")
def home():
    return {
        "project": "SENTINELX",
        "status": "online",
        "message": "Security detection engine is running.",
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/v1/detections/test")
def test_detection():
    failed_logins = 10
    threshold = 5

    alert = failed_logins >= threshold

    return {
        "rule_id": "AUTH-001",
        "rule_name": "Excessive Failed Logins",
        "severity": "high" if alert else "low",
        "failed_logins": failed_logins,
        "threshold": threshold,
        "alert_triggered": alert,
        "note": "Demonstration event; not a real security incident.",
    }
