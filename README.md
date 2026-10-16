# SENTINELX

A hands-on cybersecurity project focused on security event analysis,
candidate detection rules, and evaluating detection outcomes using Python.

## Project Goals

- Analyze labelled security event datasets.
- Develop and test candidate detection logic.
- Review suspicious SMB administrative-share activity.
- Explore time-based correlation of related security events.
- Evaluate detection outcomes using true positives, false positives,
  false negatives, and true negatives.

## Current Implementation

SENTINELX is a work in progress. Current experiments include:

- Reading and inspecting security event CSV data.
- Reviewing SMB security records and execution-related target names.
- Testing a candidate rule using a 60-second activity window.
- Inspecting labelled records that a candidate rule may miss.
- Reporting exploratory evaluation results in the terminal.

## Technology

- Python
- CSV-based security event data
- Command-line analysis

## Project Structure

- `backend/` — Python analysis and detection scripts.
- `backend/data/` — Security event dataset.
- `frontend/` — Frontend project directory.
- `docs/` — Project documentation.

## Run the SMB Activity Analysis

From the project root, run:

```bash
python backend/correlate_smb.py
```

The script reviews SMB activity windows and prints candidate findings
and summary counts.

## Example Experimental Result

In one exploratory test, the script reviewed 55 SMB security records
and reported 18 true-labelled records, 0 false positives, 0 false
negatives, and 37 true negatives.

These results apply only to this dataset and this candidate rule.
They do not establish real-world detection accuracy.

## Limitations

- Results depend on the supplied dataset and its labels.
- Labels are reference data, not independent proof of malicious activity.
- Candidate rules require testing on additional datasets.
- The project is not production-validated and does not perform
  automated incident response.

## Future Improvements

- Add structured output for investigation findings.
- Improve detection-rule testing and documentation.
- Test against additional labelled datasets.
- Develop a clearer interface for reviewing findings.

## Status

Actively developing as a cybersecurity learning and portfolio project.
