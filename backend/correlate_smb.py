import csv
from collections import defaultdict
from datetime import datetime, timezone

DATA_FILE = "backend/data/attack_scenario.csv"
WINDOW_SECONDS = 60

EXECUTION_TERMS = (
    "psexec", "psexesvc", "cmd.exe",
    "output.txt", "stdin", "stdout", "stderr"
)


def parse_time(value):
    try:
        dt = datetime.fromisoformat(
            value.strip().replace("Z", "+00:00")
        )
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


def main():
    groups = defaultdict(list)

    with open(DATA_FILE, newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            if (row.get("source_dataset") or "").strip() != "smb_security":
                continue

            timestamp = parse_time(row.get("_time", ""))
            if timestamp is None:
                continue

            key = (
                (row.get("host") or "").strip(),
                (row.get("user") or "").strip()
            )
            groups[key].append((timestamp, row))

    print("SENTINELX - SMB ACTIVITY WINDOW REVIEW")
    print("=" * 48)
    print(f"Window size: {WINDOW_SECONDS} seconds")
    print("Exploratory analysis; not production validated.")

    total_windows = 0
    suspicious_windows = 0

    for (host, user), events in sorted(groups.items()):
        events.sort(key=lambda item: item[0])
        clusters = []
        current = []
        previous_time = None

        for timestamp, row in events:
            if (
                previous_time is not None
                and (timestamp - previous_time).total_seconds()
                    > WINDOW_SECONDS
            ):
                clusters.append(current)
                current = []

            current.append((timestamp, row))
            previous_time = timestamp

        if current:
            clusters.append(current)

        for cluster in clusters:
            total_windows += 1

            has_admin_share = any(
                "admin$" in (r.get("share_name") or "").lower()
                for _, r in cluster
            )

            has_execution_target = any(
                term in (r.get("relative_target_name") or "").lower()
                for _, r in cluster
                for term in EXECUTION_TERMS
            )

            if not (has_admin_share and has_execution_target):
                continue

            suspicious_windows += 1
            labels = [
                (r.get("ground_truth") or "").strip().lower()
                for _, r in cluster
            ]
            true_count = labels.count("true")
            false_count = labels.count("false")

            print("\nCandidate activity window")
            print(f"Host: {host}")
            print(f"User: {user}")
            print(f"Events: {len(cluster)}")
            print(f"Labelled True records: {true_count}")
            print(f"Labelled False records: {false_count}")

            targets = sorted({
                (r.get("relative_target_name") or "").strip()
                for _, r in cluster
                if (r.get("relative_target_name") or "").strip()
            })

            for target in targets[:8]:
                print(f"  Target: {target}")

    print("\n" + "=" * 48)
    print(f"Activity windows reviewed: {total_windows}")
    print(f"Candidate windows flagged: {suspicious_windows}")
    print("Review labels and event context before drawing conclusions.")
    print("Read-only analysis complete.")


if __name__ == "__main__":
    main()
