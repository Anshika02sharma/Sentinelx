"""Evidence-led explanations and exportable investigation reports for SENTINELX.

This module deliberately avoids probabilistic claims. Its qualitative assessment
summarizes observed corroboration and data limitations; it is not a calibrated
maliciousness score.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable
import json

EXECUTION_TERMS = (
    "psexec", "psexesvc", "cmd.exe", "output.txt",
    "stdin", "stdout", "stderr",
)


def _value(record: dict[str, Any], key: str) -> str:
    value = record.get(key, "")
    return "" if value is None else str(value).strip()


def _present(record: dict[str, Any], keys: Iterable[str]) -> list[str]:
    return [key for key in keys if _value(record, key)]


def explain_smb_window(candidate: dict[str, Any], window_seconds: int = 60) -> dict[str, Any]:
    """Explain an SMB candidate using only the events in that activity window."""
    events = list(candidate.get("_events", []))
    share_events = [e for e in events if "admin$" in _value(e, "share_name").lower()]
    execution_matches = []
    for event in events:
        target = _value(event, "relative_target_name")
        matched = [term for term in EXECUTION_TERMS if term in target.lower()]
        if matched:
            execution_matches.append({"target": target, "terms": matched, "event": event})

    evidence = []
    if share_events:
        evidence.append({
            "type": "Administrative share reference",
            "detail": f"{len(share_events)} event(s) reference an Admin$ share.",
            "event_ids": [_value(e, "event_id") for e in share_events if _value(e, "event_id")],
        })
    if execution_matches:
        evidence.append({
            "type": "Execution-related target",
            "detail": f"{len(execution_matches)} event(s) contain execution-related target terms.",
            "targets": sorted({m["target"] for m in execution_matches}),
            "matched_terms": sorted({t for m in execution_matches for t in m["terms"]}),
        })

    labels = [_value(e, "ground_truth").lower() for e in events]
    known_labels = [label for label in labels if label in {"true", "false"}]
    true_count = known_labels.count("true")
    false_count = known_labels.count("false")

    supporting_signals = [
        "An administrative-share reference and an execution-related target occur in the same host/user activity window.",
        f"The activity window contains {len(events)} timestamped event(s) grouped within a {window_seconds}-second maximum inter-event gap.",
    ]
    if _value(candidate, "Host"):
        supporting_signals.append(f"Host context is available: {_value(candidate, 'Host')}.")
    if _value(candidate, "User"):
        supporting_signals.append(f"User context is available: {_value(candidate, 'User')}.")

    limiting_signals = [
        "SMB share access and execution-related filenames are investigative indicators, not proof that code executed successfully.",
        "The correlation is based on temporal grouping by host and user; it does not independently prove causality between events.",
        "The current logic does not verify process creation, service installation, authentication origin, or endpoint execution telemetry.",
    ]
    if false_count:
        limiting_signals.append(f"The window also contains {false_count} reference-negative record(s); inspect each event rather than treating the whole window as malicious.")
    if not known_labels:
        limiting_signals.append("No recognized reference labels are available for this window.")

    raise_confidence = [
        "Correlated endpoint process-creation telemetry showing PSEXESVC or a related service/process on the same host and time range.",
        "Authentication logs identifying the source account, source host, logon type, and successful/failed logon sequence.",
        "Service-control or Windows event logs confirming service creation and execution, with matching timestamps and identifiers.",
        "Network telemetry linking the source host to the destination host during the same activity window.",
    ]
    lower_confidence = [
        "Approved software deployment or remote administration change records covering the same host, user, and time.",
        "Asset-management or administrator confirmation that the activity was expected.",
        "Evidence that the target names were merely accessed or listed and no process/service execution followed.",
        "A mismatch between the source host, account, timestamps, or related endpoint events.",
    ]

    corroboration = "Moderate" if share_events and execution_matches else "Limited"
    if len(events) >= 3 and share_events and execution_matches:
        corroboration = "Moderate"

    evidence_event_objects = []
    seen_event_keys = set()
    for event in share_events + [match["event"] for match in execution_matches]:
        event_key = (_value(event, "_time"), _value(event, "event_id"), _value(event, "relative_target_name"), _value(event, "share_name"))
        if event_key in seen_event_keys:
            continue
        seen_event_keys.add(event_key)
        evidence_event_objects.append({
            key: _value(event, key)
            for key in ("_time", "event_id", "host", "user", "share_name", "relative_target_name", "ground_truth", "scenario_stage", "trace_id")
            if _value(event, key)
        })

    return {
        "finding_type": "SMB activity correlation",
        "status": "Candidate activity window — investigation required",
        "title": f"SMB candidate on {_value(candidate, 'Host') or 'unknown host'}",
        "host": _value(candidate, "Host"),
        "user": _value(candidate, "User"),
        "window_number": candidate.get("Window"),
        "event_count": len(events),
        "window_seconds": window_seconds,
        "why_flagged": "The window matched both configured conditions: an Admin$ share reference and an execution-related target term.",
        "matched_conditions": [
            {"condition": "Admin$ share reference", "matched": bool(share_events), "matching_event_count": len(share_events)},
            {"condition": "Execution-related target term", "matched": bool(execution_matches), "matching_event_count": len(execution_matches)},
        ],
        "supporting_evidence": evidence,
        "evidence_events": evidence_event_objects,
        "supporting_signals": supporting_signals,
        "confidence_assessment": {
            "label": corroboration,
            "meaning": "Qualitative evidence-corroboration level only; not a probability or calibrated risk score.",
        },
        "signals_that_could_increase_confidence": raise_confidence,
        "signals_that_could_reduce_confidence": lower_confidence,
        "limitations_and_missing_evidence": limiting_signals,
        "reference_label_counts": {"true": true_count, "false": false_count, "unknown": len(events) - len(known_labels)},
        "recommended_next_steps": [
            "Validate the account and source host against an approved administrative activity/change record.",
            "Correlate the window with endpoint process creation, service installation, and authentication telemetry.",
            "Inspect the underlying events and preserve relevant timestamps and identifiers before assigning an incident disposition.",
        ],
        "events": events,
    }


def explain_lsass_event(event: dict[str, Any], rule_name: str, predicted: bool) -> dict[str, Any]:
    """Explain an LSASS rule outcome for one event without asserting credential theft."""
    mask = _value(event, "granted_access").lower()
    user = _value(event, "user").lower()
    rule_b_masks = {"0x1010", "0x1f3fff", "0x1fffff"}
    rule_a_masks = {"0x1f3fff", "0x1fffff"}
    matched = []
    if rule_name == "Rule A" and mask in rule_a_masks:
        matched.append(f"Granted-access mask {mask} is in Rule A's configured mask set.")
    elif rule_name in {"Rule B", "Rule C"} and mask in rule_b_masks:
        matched.append(f"Granted-access mask {mask} is in the expanded Rule B mask set.")
    elif rule_name == "Rule C" and mask == "0x1410" and user == r"lab\user-admin":
        matched.append("Rule C's additional condition matched: access mask 0x1410 with user LAB\\user-admin.")

    evidence_fields = ["_time", "event_id", "host", "user", "image", "parent_image", "command_line", "target_image", "granted_access", "technique_id", "scenario_stage", "trace_id"]
    available = {key: _value(event, key) for key in evidence_fields if _value(event, key)}
    missing = [key for key in ("_time", "host", "user", "image", "target_image", "command_line", "granted_access") if not _value(event, key)]
    actual_label = _value(event, "ground_truth").lower()

    return {
        "finding_type": "LSASS detection-rule evaluation",
        "status": "Rule matched" if predicted else "Rule did not match",
        "title": f"{rule_name} — {'matched' if predicted else 'not matched'} LSASS event",
        "rule": rule_name,
        "host": _value(event, "host"),
        "user": _value(event, "user"),
        "why_flagged": ("The event matched the configured rule condition(s)." if predicted else "The event did not satisfy the selected rule's configured access-mask/user conditions."),
        "matched_conditions": matched,
        "supporting_evidence": [{"type": "Event fields", "detail": "Observed fields copied from the source event.", "fields": available}],
        "confidence_assessment": {
            "label": "Rule match only" if predicted else "No rule match",
            "meaning": "This describes the rule outcome, not confidence that credential theft occurred.",
        },
        "signals_that_could_increase_confidence": [
            "Corroborating process telemetry showing the requesting process, parent process, signer, and execution chain.",
            "Endpoint telemetry showing suspicious access followed by credential-dumping behavior or related artifacts.",
            "Correlated user logon, host, and incident timeline evidence.",
        ],
        "signals_that_could_reduce_confidence": [
            "A verified, approved security product or administrative tool performing expected LSASS access.",
            "Known-good process signer, path, parent process, and change record consistent with authorized activity.",
            "Contradictory endpoint or identity telemetry showing no related suspicious behavior.",
        ],
        "limitations_and_missing_evidence": [
            "An access mask and username alone do not prove credential theft or successful memory extraction.",
            "The rule is evaluated against a small labelled subset and may be overfit to its reference data.",
            *( [f"The following useful event fields are absent: {', '.join(missing)}."] if missing else [] ),
            *( [f"Reference label: {actual_label}; this is an evaluation label, not independent proof."] if actual_label in {"true", "false"} else ["No recognized reference label is present for this event."] ),
        ],
        "recommended_next_steps": [
            "Review the process tree, signer, executable path, and command line.",
            "Correlate endpoint, identity, and security-product telemetry around the event timestamp.",
            "Record an evidence-based disposition and document any benign administrative explanation.",
        ],
        "event": event,
    }


def build_investigation_report(dataset_name: str, lsass_findings: list[dict[str, Any]], smb_findings: list[dict[str, Any]], summary: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build a portable report object; source records are retained as evidence."""
    return {
        "report_title": "SENTINELX Investigation Report",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "project": "SENTINELX",
        "dataset": dataset_name,
        "summary": summary or {},
        "important_notice": "Experimental, read-only analysis. Findings are candidates for investigation, not confirmed incidents. Reference labels are not proof of malicious activity.",
        "lsass_findings": lsass_findings,
        "smb_findings": smb_findings,
    }


def report_as_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False, default=str)


def report_as_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# {report['report_title']}",
        "",
        f"- **Generated (UTC):** {report['generated_at_utc']}",
        f"- **Dataset:** {report.get('dataset') or 'Not specified'}",
        "",
        f"> **Scope:** {report['important_notice']}",
        "",
        "## Summary",
    ]
    for key, value in (report.get("summary") or {}).items():
        lines.append(f"- **{key}:** {value}")
    for section, title in (("lsass_findings", "LSASS Findings"), ("smb_findings", "SMB Correlation Findings")):
        lines.extend(["", f"## {title}"])
        findings = report.get(section, [])
        if not findings:
            lines.append("No findings included in this section.")
        for index, finding in enumerate(findings, 1):
            lines.extend(["", f"### {index}. {finding.get('title', 'Finding')}", "", f"- **Status:** {finding.get('status', 'N/A')}", f"- **Why flagged:** {finding.get('why_flagged', 'N/A')}", f"- **Host:** {finding.get('host') or 'Unknown'}", f"- **User:** {finding.get('user') or 'Unknown'}"])
            assessment = finding.get("confidence_assessment", {})
            lines.append(f"- **Evidence assessment:** {assessment.get('label', 'N/A')} — {assessment.get('meaning', '')}")
            for field, heading in (("matched_conditions", "Matched conditions"), ("supporting_signals", "Supporting signals"), ("signals_that_could_increase_confidence", "Signals that could increase confidence"), ("signals_that_could_reduce_confidence", "Signals that could reduce confidence"), ("limitations_and_missing_evidence", "Limitations and missing evidence"), ("recommended_next_steps", "Recommended next steps")):
                values = finding.get(field, [])
                if values:
                    lines.extend(["", f"**{heading}:**"])
                    for item in values:
                        if isinstance(item, dict):
                            lines.append(f"- {item.get('condition') or item.get('type')}: {item.get('detail') or item.get('matched')}")
                        else:
                            lines.append(f"- {item}")
            evidence = finding.get("supporting_evidence", [])
            if evidence:
                lines.extend(["", "**Supporting evidence:**"])
                for item in evidence:
                    lines.append(f"- {item.get('type')}: {item.get('detail', '')}")
                    if item.get("targets"):
                        lines.append(f"  - Targets: {', '.join(item['targets'])}")
                    if item.get("matched_terms"):
                        lines.append(f"  - Matched terms: {', '.join(item['matched_terms'])}")
                    if item.get("fields"):
                        for key, value in item["fields"].items():
                            lines.append(f"  - `{key}`: {value}")
            evidence_events = finding.get("evidence_events", [])
            if evidence_events:
                lines.extend(["", "**Matched source events:**"])
                for event in evidence_events:
                    details = "; ".join(f"{key}={value}" for key, value in event.items())
                    lines.append(f"- {details}")
            single_event = finding.get("event")
            if isinstance(single_event, dict) and single_event:
                lines.extend(["", "**Source event fields:**"])
                for key, value in single_event.items():
                    if value not in (None, ""):
                        lines.append(f"- `{key}`: {value}")
    lines.extend(["", "## Handling note", "Review original event records and corroborating telemetry before assigning severity or incident status.", ""])
    return "\n".join(lines)
