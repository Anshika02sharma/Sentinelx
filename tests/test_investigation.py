import json

from backend.compare_lsass_rules import evaluate_rule, predict_rule
from backend.investigation import (
    build_investigation_report,
    explain_lsass_event,
    explain_smb_window,
    report_as_json,
    report_as_markdown,
)
from backend.smb_correlation import build_smb_activity_windows, count_smb_activity_windows, parse_smb_time


def smb_event(timestamp, share="", target="", host="WS-01", user=r"LAB\admin", label=""):
    return {
        "_time": timestamp,
        "source_dataset": "smb_security",
        "host": host,
        "user": user,
        "share_name": share,
        "relative_target_name": target,
        "event_id": "5145",
        "ground_truth": label,
    }


def test_rule_a_and_b_and_c_predictions():
    assert predict_rule({"granted_access": "0x1f3fff"}, "Rule A") is True
    assert predict_rule({"granted_access": "0x1010"}, "Rule A") is False
    assert predict_rule({"granted_access": "0x1010"}, "Rule B") is True
    assert predict_rule({"granted_access": "0x1410", "user": r"LAB\USER-ADMIN"}, "Rule C") is True
    assert predict_rule({"granted_access": "0x1410", "user": r"LAB\other"}, "Rule C") is False


def test_unknown_rule_rejected():
    try:
        predict_rule({}, "Rule Z")
    except ValueError as exc:
        assert "Unknown rule" in str(exc)
    else:
        raise AssertionError("Unknown rule should raise ValueError")


def test_evaluation_confusion_matrix_and_metrics():
    rows = [
        {"technique_id": "T1003.001", "ground_truth": "true", "granted_access": "0x1010"},
        {"technique_id": "T1003.001", "ground_truth": "false", "granted_access": "0x1010"},
        {"technique_id": "T1003.001", "ground_truth": "true", "granted_access": "0x0000"},
        {"technique_id": "T1003.001", "ground_truth": "false", "granted_access": "0x0000"},
        {"technique_id": "T1059", "ground_truth": "true", "granted_access": "0x1010"},
        {"technique_id": "T1003.001", "ground_truth": "unknown", "granted_access": "0x1010"},
    ]
    result = evaluate_rule(rows, "Rule B")
    assert (result["TP"], result["FP"], result["FN"], result["TN"]) == (1, 1, 1, 1)
    assert result["precision"] == 0.5
    assert result["recall"] == 0.5
    assert result["f1"] == 0.5


def test_smb_activity_windows_detect_both_conditions_in_same_window():
    rows = [
        smb_event("2026-01-01T00:00:00Z", share="ADMIN$"),
        smb_event("2026-01-01T00:00:45Z", target="PSEXESVC\\cmd.exe"),
        smb_event("2026-01-01T00:05:00Z", share="C$"),
    ]
    grouped, candidates = build_smb_activity_windows(rows, 60)
    assert len(grouped) == 1
    assert count_smb_activity_windows(grouped, 60) == 2
    assert len(candidates) == 1
    assert candidates[0]["Events"] == 2


def test_smb_window_does_not_flag_when_conditions_are_separate_windows():
    rows = [
        smb_event("2026-01-01T00:00:00Z", share="ADMIN$"),
        smb_event("2026-01-01T00:02:00Z", target="PSEXESVC"),
    ]
    _, candidates = build_smb_activity_windows(rows, 60)
    assert candidates == []


def test_smb_invalid_timestamp_is_ignored():
    rows = [smb_event("not-a-timestamp", share="ADMIN$", target="cmd.exe")]
    grouped, candidates = build_smb_activity_windows(rows, 60)
    assert grouped == {}
    assert candidates == []
    assert parse_smb_time("not-a-timestamp") is None


def test_smb_explanation_names_matched_conditions_and_limitations():
    candidate = {
        "Host": "WS-01", "User": r"LAB\admin", "Window": 1,
        "_events": [
            smb_event("2026-01-01T00:00:00Z", share="ADMIN$", label="true"),
            smb_event("2026-01-01T00:00:30Z", target="PSEXESVC\\cmd.exe", label="false"),
        ],
    }
    finding = explain_smb_window(candidate)
    assert finding["matched_conditions"][0]["matched"] is True
    assert finding["matched_conditions"][1]["matched"] is True
    assert finding["reference_label_counts"] == {"true": 1, "false": 1, "unknown": 0}
    assert finding["confidence_assessment"]["label"] == "Moderate"
    assert any("not proof" in item for item in finding["limitations_and_missing_evidence"])
    assert finding["signals_that_could_increase_confidence"]
    assert finding["signals_that_could_reduce_confidence"]


def test_lsass_explanation_does_not_claim_credential_theft():
    event = {
        "_time": "2026-01-01T00:00:00Z", "host": "LSASS-01",
        "user": r"LAB\user-admin", "granted_access": "0x1410",
        "technique_id": "T1003.001", "ground_truth": "true",
    }
    finding = explain_lsass_event(event, "Rule C", True)
    assert finding["matched_conditions"]
    assert "credential theft" in " ".join(finding["limitations_and_missing_evidence"])
    assert finding["confidence_assessment"]["label"] == "Rule match only"


def test_lsass_explanation_reports_missing_fields():
    finding = explain_lsass_event({"granted_access": "0x0000"}, "Rule A", False)
    assert finding["status"] == "Rule did not match"
    assert any("absent" in item for item in finding["limitations_and_missing_evidence"])


def test_report_exports_valid_json_and_useful_markdown():
    finding = explain_lsass_event({"granted_access": "0x1010"}, "Rule B", True)
    report = build_investigation_report("sample.csv", [finding], [], {"records": 1})
    parsed = json.loads(report_as_json(report))
    markdown = report_as_markdown(report)
    assert parsed["dataset"] == "sample.csv"
    assert "Why flagged" in markdown
    assert "Signals that could increase confidence" in markdown
    assert "not confirmed incidents" in markdown


def test_smb_window_boundary_of_exactly_sixty_seconds_stays_together():
    rows = [
        smb_event("2026-01-01T00:00:00Z", share="ADMIN$"),
        smb_event("2026-01-01T00:01:00Z", target="PSEXESVC"),
    ]
    _, candidates = build_smb_activity_windows(rows, 60)
    assert len(candidates) == 1


def test_smb_negative_or_unknown_labels_do_not_change_candidate_logic():
    rows = [
        smb_event("2026-01-01T00:00:00Z", share="ADMIN$", label="false"),
        smb_event("2026-01-01T00:00:20Z", target="cmd.exe", label="unknown"),
    ]
    _, candidates = build_smb_activity_windows(rows, 60)
    assert len(candidates) == 1
    explanation = explain_smb_window(candidates[0])
    assert explanation["reference_label_counts"] == {"true": 0, "false": 1, "unknown": 1}


def test_smb_evidence_events_are_traceable_to_source_fields():
    rows = [
        smb_event("2026-01-01T00:00:00Z", share="ADMIN$"),
        smb_event("2026-01-01T00:00:20Z", target="PSEXESVC"),
    ]
    _, candidates = build_smb_activity_windows(rows, 60)
    explanation = explain_smb_window(candidates[0])
    assert len(explanation["evidence_events"]) == 2
    assert {event.get("share_name", "") for event in explanation["evidence_events"]} == {"ADMIN$", ""}
