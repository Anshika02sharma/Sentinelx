
import csv
from pathlib import Path

DATA_FILE = (
    Path(__file__).parent
    / "data"
    / "attack_scenario.csv"
)

SUSPICIOUS_MASKS = {
    "0x1010",
    "0x1f3fff",
    "0x1fffff",
}

def evaluate_detection():
    with DATA_FILE.open(
        "r",
        newline="",
        encoding="utf-8-sig",
    ) as file:
        rows = list(csv.DictReader(file))

    tp = fp = fn = tn = 0

    for row in rows:
        if row.get("technique_id", "").strip() != "T1003.001":
            continue

        mask = row.get(
            "granted_access", ""
        ).strip().lower()

        label = row.get(
            "ground_truth", ""
        ).strip().lower()

        # Evaluate only records with known reference labels.
        if label not in {"true", "false"}:
            continue

        predicted = mask in SUSPICIOUS_MASKS
        actual = label == "true"

        if predicted and actual:
            tp += 1
        elif predicted and not actual:
            fp += 1
        elif not predicted and actual:
            fn += 1
        else:
            tn += 1

    total = tp + fp + fn + tn
    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    accuracy = (tp + tn) / total if total else 0

    print("\n=== SENTINELX LSASS DETECTION EVALUATION ===")
    print(f"Evaluated LSASS records: {total}")
    print(f"True Positives (TP): {tp}")
    print(f"False Positives (FP): {fp}")
    print(f"False Negatives (FN): {fn}")
    print(f"True Negatives (TN): {tn}")
    print(f"Precision: {precision:.2%}")
    print(f"Recall: {recall:.2%}")
    print(f"Accuracy: {accuracy:.2%}")

    print("\nNote: Results apply only to this dataset.")
    print("Access masks alone do not prove malicious activity.")


if __name__ == "__main__":
    evaluate_detection()
