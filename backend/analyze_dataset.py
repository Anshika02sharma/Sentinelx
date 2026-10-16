
import csv
from collections import Counter
from pathlib import Path

DATA_FILE = Path(__file__).parent / "data" / "attack_scenario.csv"


def analyze_dataset():
    with DATA_FILE.open(
        "r", newline="", encoding="utf-8-sig"
    ) as file:
        reader = csv.DictReader(file)
        rows = list(reader)

    print("\n=== SENTINELX DATASET REPORT ===")
    print(f"Total records: {len(rows)}")
    print(f"Total columns: {len(reader.fieldnames or [])}")

    print("\n=== REFERENCE LABELS ===")
    for label, count in Counter(
        row.get("ground_truth", "").strip().lower()
        for row in rows
    ).most_common():
        print(f"{label or 'Unknown'}: {count}")

    positive_rows = [
        row for row in rows
        if row.get("ground_truth", "").strip().lower() == "true"
    ]

    print(f"\n=== REFERENCE-POSITIVE RECORDS: {len(positive_rows)} ===")

    print("\n=== TECHNIQUE BREAKDOWN ===")
    for technique, count in Counter(
        row.get("technique_name", "") for row in positive_rows
    ).most_common():
        print(f"{technique or 'Unknown'}: {count}")

    print("\n=== SAMPLE REFERENCE-POSITIVE EVENTS ===")
    for row in positive_rows[:5]:
        print({
            "time": row.get("_time"),
            "event_id": row.get("event_id"),
            "host": row.get("host"),
            "user": row.get("user"),
            "process": row.get("image"),
            "command_line": row.get("command_line"),
            "technique_id": row.get("technique_id"),
            "technique_name": row.get("technique_name"),
            "scenario_stage": row.get("scenario_stage"),
        })


if __name__ == "__main__":
    analyze_dataset()
