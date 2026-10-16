
import csv
from collections import Counter
from pathlib import Path

DATA_FILE = Path(__file__).parent / "data" / "attack_scenario.csv"


def analyze_lsass():
    with DATA_FILE.open(
        "r", newline="", encoding="utf-8-sig"
    ) as file:
        rows = list(csv.DictReader(file))

    lsass_rows = [
        row for row in rows
        if row.get("technique_id", "").strip() == "T1003.001"
    ]

    print("\n=== SENTINELX LSASS INVESTIGATION ===")
    print(f"Total dataset records: {len(rows)}")
    print(f"LSASS-related records: {len(lsass_rows)}")

    print("\n=== REFERENCE LABELS ===")
    labels = Counter(
        row.get("ground_truth", "").strip().lower()
        for row in lsass_rows
    )
    for label, count in labels.items():
        print(f"{label or 'Unknown'}: {count}")

    print("\n=== GRANTED ACCESS VALUES ===")
    access_counts = Counter(
        row.get("granted_access", "").strip() or "Missing"
        for row in lsass_rows
    )
    for access, count in access_counts.most_common():
        print(f"{access}: {count}")

    print("\n=== LSASS EVENT DETAILS ===")
    for row in lsass_rows:
        print({
            "time": row.get("_time"),
            "host": row.get("host"),
            "user": row.get("user"),
            "process": row.get("image"),
            "target_image": row.get("target_image"),
            "granted_access": row.get("granted_access"),
            "reference_label": row.get("ground_truth"),
            "scenario_stage": row.get("scenario_stage"),
            "trace_id": row.get("trace_id"),
        })


if __name__ == "__main__":
    analyze_lsass()
