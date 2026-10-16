
import csv
from pathlib import Path

# Dataset path
DATA_FILE = (
    Path(__file__).parent
    / "data"
    / "attack_scenario.csv"
)

# Rule A: Original detection rule
RULE_A = {
    "0x1f3fff",
    "0x1fffff",
}

# Rule B: Expanded access-mask rule
RULE_B = {
    "0x1010",
    "0x1f3fff",
    "0x1fffff",
}


def load_dataset():
    """Load the CSV without modifying it."""
    with DATA_FILE.open(
        "r",
        newline="",
        encoding="utf-8-sig",
    ) as file:
        return list(csv.DictReader(file))


def predict_rule(row, rule_name):
    """Apply one candidate rule to an event."""
    mask = row.get(
        "granted_access", ""
    ).strip().lower()

    if rule_name == "Rule A":
        return mask in RULE_A

    if rule_name == "Rule B":
        return mask in RULE_B

    if rule_name == "Rule C":
        # Rule C adds a user-specific condition
        # for the 0x1410 access mask.
        user = row.get("user", "").strip().lower()

        return (
            mask in RULE_B
            or (
                mask == "0x1410"
                and user == r"lab\user-admin"
            )
        )

    raise ValueError(f"Unknown rule: {rule_name}")


def evaluate_rule(rows, rule_name):
    """Evaluate a rule against labelled LSASS records."""
    tp = fp = fn = tn = 0

    for row in rows:
        if row.get("technique_id", "").strip() != "T1003.001":
            continue

        label = row.get(
            "ground_truth", ""
        ).strip().lower()

        if label not in {"true", "false"}:
            continue

        predicted = predict_rule(row, rule_name)
        actual = label == "true"

        if predicted and actual:
            tp += 1
        elif predicted and not actual:
            fp += 1
        elif not predicted and actual:
            fn += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0

    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0
    )

    return {
        "TP": tp,
        "FP": fp,
        "FN": fn,
        "TN": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def show_missed_detections(rows, rule_name):
    """Display reference-positive events missed by a rule."""
    missed = []

    for row in rows:
        if row.get("technique_id", "").strip() != "T1003.001":
            continue

        label = row.get(
            "ground_truth", ""
        ).strip().lower()

        if label != "true":
            continue

        if not predict_rule(row, rule_name):
            missed.append(row)

    print(f"\n=== MISSED EVENTS: {rule_name} ===")
    print(f"Missed records: {len(missed)}")

    fields = [
        "_time",
        "event_id",
        "host",
        "user",
        "image",
        "parent_image",
        "command_line",
        "target_image",
        "granted_access",
        "technique_id",
        "scenario_stage",
        "trace_id",
    ]

    for row in missed:
        print("\n--- Missed record ---")
        for field in fields:
            print(f"{field}: {row.get(field, '')}")


def main():
    rows = load_dataset()

    print("=== SENTINELX: LSASS RULE COMPARISON ===")

    labelled_count = sum(
        1
        for row in rows
        if row.get("technique_id", "").strip() == "T1003.001"
        and row.get("ground_truth", "").strip().lower()
        in {"true", "false"}
    )

    print(f"Labelled LSASS records: {labelled_count}")

    for rule_name in ("Rule A", "Rule B", "Rule C"):
        result = evaluate_rule(rows, rule_name)

        print(f"\n--- {rule_name} ---")
        print(f"True Positives (TP): {result['TP']}")
        print(f"False Positives (FP): {result['FP']}")
        print(f"False Negatives (FN): {result['FN']}")
        print(f"True Negatives (TN): {result['TN']}")
        print(f"Precision: {result['precision']:.2%}")
        print(f"Recall: {result['recall']:.2%}")
        print(f"F1 score: {result['f1']:.2%}")

        show_missed_detections(rows, rule_name)

    print("\n=== IMPORTANT LIMITATIONS ===")
    print("Results apply only to this dataset.")
    print("Reference labels are evaluation labels, not proof of malicious activity.")
    print("Access masks and usernames alone cannot establish credential theft.")
    print("Validate candidate rules on independent data before deployment.")


if __name__ == "__main__":
    main()
