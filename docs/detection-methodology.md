# Detection and Investigation Methodology

## LSASS rule evaluation

SENTINELX evaluates candidate rules only on records whose `technique_id` is `T1003.001` and whose `ground_truth` is `true` or `false`.

- **Rule A:** `granted_access` is `0x1f3fff` or `0x1fffff`.
- **Rule B:** Rule A plus `0x1010`.
- **Rule C:** Rule B plus `0x1410` when the normalized user is `lab\\user-admin`.

The evaluator reports TP, FP, FN, TN, precision, recall, and F1. These are dataset-specific evaluation results, not real-world detection guarantees. Rule C's user-specific condition may overfit the small labelled subset.

## SMB activity correlation

Events are selected when `source_dataset` is `smb_security`, parsed as timestamps, and grouped by `(host, user)`. Within each group, a new activity window begins when the gap from the previous event is greater than 60 seconds. A window is flagged as a candidate when both conditions occur in that same window:

1. At least one `share_name` contains `admin$`.
2. At least one `relative_target_name` contains one of: `psexec`, `psexesvc`, `cmd.exe`, `output.txt`, `stdin`, `stdout`, or `stderr`.

This is a correlation heuristic. It does not establish causality, successful execution, or malicious intent.

## Explainability model

Each finding documents the rule/window status, matched conditions, source event fields, missing fields, corroborating signals to seek, benign explanations that could reduce concern, limitations, and recommended investigation steps. The SMB evidence assessment is qualitative and explicitly not a probability. LSASS explanations describe a rule match only, not proof of credential theft.

## Investigation workflow

1. Validate host, account, timestamps, and event identifiers.
2. Correlate with endpoint process creation, service-control, authentication, and network telemetry.
3. Check approved change records and known administrative tooling.
4. Record the evidence and disposition; do not treat a candidate as a confirmed incident without corroboration.
