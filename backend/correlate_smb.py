"""Command-line view of SENTINELX's reusable SMB activity correlation."""
import csv
from pathlib import Path

try:  # Supports both `python -m backend.correlate_smb` and direct script execution.
    from backend.smb_correlation import build_smb_activity_windows, count_smb_activity_windows
except ModuleNotFoundError:  # pragma: no cover - direct script import path
    from smb_correlation import build_smb_activity_windows, count_smb_activity_windows

DATA_FILE = Path(__file__).parent / "data" / "attack_scenario.csv"
WINDOW_SECONDS = 60


def main():
    if not DATA_FILE.exists():
        raise FileNotFoundError(
            f"Dataset not found at {DATA_FILE}. Add the authorized CSV locally; it is not distributed with this repository."
        )
    with DATA_FILE.open(newline="", encoding="utf-8-sig") as file:
        rows = list(csv.DictReader(file))

    grouped, candidates = build_smb_activity_windows(rows, WINDOW_SECONDS)
    print("SENTINELX - SMB ACTIVITY WINDOW REVIEW")
    print("=" * 48)
    print(f"Window size: {WINDOW_SECONDS} seconds")
    print("Exploratory analysis; not production validated.")
    print(f"SMB host/user groups: {len(grouped)}")
    print(f"Activity windows reviewed: {count_smb_activity_windows(grouped, WINDOW_SECONDS)}")
    print(f"Candidate windows flagged: {len(candidates)}")

    for candidate in candidates:
        print("\nCandidate activity window")
        for key in ("Host", "User", "Window", "Events", "Labelled True records", "Labelled False records", "Targets"):
            print(f"{key}: {candidate[key]}")

    print("\nReview labels and event context before drawing conclusions.")
    print("Read-only analysis complete.")


if __name__ == "__main__":
    main()
