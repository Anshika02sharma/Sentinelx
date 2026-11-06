"""Reusable, read-only SMB activity-window correlation logic."""
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

EXECUTION_TERMS = (
    "psexec", "psexesvc", "cmd.exe", "output.txt", "stdin", "stdout", "stderr",
)


def parse_smb_time(value: Any):
    try:
        parsed = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except (ValueError, TypeError):
        return None


def build_smb_activity_windows(rows: list[dict[str, Any]], window_seconds: int = 60):
    """Group timestamped SMB events by host/user and flag candidate windows."""
    if window_seconds < 0:
        raise ValueError("window_seconds must be non-negative")
    grouped = defaultdict(list)
    for row in rows:
        if (row.get("source_dataset") or "").strip() != "smb_security":
            continue
        timestamp = parse_smb_time(row.get("_time", ""))
        if timestamp is None:
            continue
        key = ((row.get("host") or "").strip(), (row.get("user") or "").strip())
        grouped[key].append((timestamp, row))

    candidates = []
    for (host, user), events in sorted(grouped.items()):
        events.sort(key=lambda item: item[0])
        clusters, current, previous_time = [], [], None
        for timestamp, row in events:
            if previous_time is not None and (timestamp - previous_time).total_seconds() > window_seconds:
                clusters.append(current)
                current = []
            current.append((timestamp, row))
            previous_time = timestamp
        if current:
            clusters.append(current)

        for cluster_number, cluster in enumerate(clusters, start=1):
            share_events = [event for _, event in cluster if "admin$" in (event.get("share_name") or "").lower()]
            execution_events = [
                event for _, event in cluster
                if any(term in (event.get("relative_target_name") or "").lower() for term in EXECUTION_TERMS)
            ]
            if not (share_events and execution_events):
                continue
            labels = [(event.get("ground_truth") or "").strip().lower() for _, event in cluster]
            targets = sorted({(event.get("relative_target_name") or "").strip() for _, event in cluster if (event.get("relative_target_name") or "").strip()})
            candidates.append({
                "Host": host,
                "User": user,
                "Window": cluster_number,
                "Events": len(cluster),
                "Labelled True records": labels.count("true"),
                "Labelled False records": labels.count("false"),
                "Targets": "; ".join(targets[:8]),
                "_events": [event for _, event in cluster],
            })
    return grouped, candidates


def count_smb_activity_windows(grouped: dict, window_seconds: int = 60) -> int:
    total = 0
    for events in grouped.values():
        timestamps = sorted(timestamp for timestamp, _ in events)
        if timestamps:
            total += 1 + sum((current - previous).total_seconds() > window_seconds for previous, current in zip(timestamps, timestamps[1:]))
    return total
