# SENTINELX

A hands-on cybersecurity project focused on security event analysis, detection-rule development, event correlation, and investigation reporting using Python.

## Project Overview

SENTINELX is a cybersecurity learning and portfolio project designed to explore how security events can be analyzed, suspicious activity can be investigated, and candidate detection rules can be evaluated against labelled datasets.

The project focuses on understanding detection logic, correlating related events, evaluating investigation outcomes, and documenting findings.

## Project Goals

- Analyze labelled security event datasets.
- Develop and test candidate detection logic.
- Investigate suspicious SMB administrative-share activity.
- Explore time-based correlation of related security events.
- Analyze LSASS-related access patterns.
- Evaluate detection outcomes using True Positives, False Positives, False Negatives, and True Negatives.
- Generate structured investigation findings and reports.

## Current Implementation

SENTINELX is actively being developed. Current implementations and experiments include:

- Reading and analyzing security event data stored in CSV format.
- Reviewing SMB security records and execution-related target names.
- Investigating LSASS-related access patterns.
- Comparing candidate detection rules using granted-access values and contextual conditions.
- Testing time-based correlation of related SMB events using a 60-second activity window.
- Evaluating candidate rules against labelled records.
- Generating investigation reports and exporting findings.
- Writing automated tests for investigation, correlation, and reporting logic.

## Detection Engineering Experiments

The project includes experiments involving two security investigation areas:

### 1. SMB Activity Correlation

- Reviews SMB-related security events.
- Examines related activity within a defined 60-second time window.
- Evaluates candidate conditions for identifying suspicious activity.
- Considers event timestamps and source evidence during correlation.

### 2. LSASS Access Detection

- Examines LSASS-related process access events.
- Compares multiple candidate detection rules.
- Evaluates granted-access values and contextual conditions.
- Measures detection outcomes using confusion-matrix metrics.

**Note:** Experimental results are specific to the available labelled dataset and tested rules. They should not be interpreted as real-world detection accuracy.

## Example Experimental Results

### SMB Activity Analysis

In one exploratory experiment, the candidate SMB activity rule was evaluated against 55 security records.

| Metric | Result |
|---|---:|
| Records reviewed | 55 |
| True Positives | 18 |
| False Positives | 0 |
| False Negatives | 0 |
| True Negatives | 37 |

### LSASS Detection Rule Comparison

Multiple candidate rules were evaluated against a subset of 32 labelled LSASS-related records.

| Rule | True Positives | False Positives | False Negatives | True Negatives | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|
| Rule A | 2 | 0 | 3 | 27 | 100% | 40% |
| Rule B | 4 | 0 | 1 | 27 | 100% | 80% |
| Rule C | 5 | 0 | 0 | 27 | 100% | 100% |

Rule C achieved the highest metrics within this small evaluation subset. However, this result may reflect overfitting to the available records and does not establish general detection effectiveness.

## Technology Stack

- **Language:** Python
- **Data Handling:** CSV-based security event data, Pandas
- **Application Interface:** Streamlit
- **API Framework:** FastAPI
- **Testing:** Pytest
- **Analysis:** Command-line security event analysis and detection-rule evaluation

## Project Structure

```text
SENTINELX/
│
├── backend/
│   ├── analyze_dataset.py
│   ├── analyze_lsass.py
│   ├── compare_lsass_rules.py
│   ├── correlate_smb.py
│   ├── investigation.py
│   ├── main.py
│   └── smb_correlation.py
│
├── docs/
│   ├── architecture.md
│   └── detection-methodology.md
│
├── frontend/
│   └── app.py
│
├── tests/
│   └── test_investigation.py
│
├── requirements.txt
├── .gitignore
└── README.md
```

The security event dataset is kept locally and excluded from the public repository.

## Setup and Installation

### 1. Clone the repository

```bash
git clone https://github.com/Anshika02sharma/Sentinelx.git
cd Sentinelx
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

### 3. Activate the environment

**macOS/Linux:**

```bash
source .venv/bin/activate
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

### 5. Dataset Configuration

The original security event dataset is not included in this repository.

Place the required dataset locally at:

```text
backend/data/attack_scenario.csv
```

Dataset-dependent scripts require this file to be available locally.

## Running the Project

### SMB Activity Analysis

From the project root, run:

```bash
python backend/correlate_smb.py
```

This script analyzes SMB activity windows and prints candidate findings and summary counts.

### Running Automated Tests

Run the test suite using:

```bash
python -m pytest -v
```

**Latest local test result:** 13 tests passed.

The current tests cover:

- Detection-rule evaluation.
- Investigation logic.
- Confusion-matrix metrics.
- SMB activity correlation and time-window boundaries.
- Investigation explanations.
- Report export validation.

Test results validate the implemented test cases, not production-level detection accuracy.

## Documentation

Additional technical documentation is available in the `docs/` directory:

- `architecture.md` — Project architecture.
- `detection-methodology.md` — Detection methodology and experimental approach.

## Limitations

- Results depend on the supplied dataset and its labels.
- Dataset labels are reference data, not independent proof of malicious activity.
- Candidate detection rules require testing against additional datasets.
- Small evaluation subsets can produce misleadingly high performance metrics.
- The project is not production-validated.
- It does not currently provide automated incident response.

## Future Improvements

- Test detection logic against additional labelled datasets.
- Improve detection-rule precision and generalizability.
- Expand investigation reporting and structured output.
- Improve test coverage and documentation.
- Enhance the application interface.
- Explore additional detection techniques and event-correlation scenarios.

## Project Status

**Actively developing** as a cybersecurity learning and portfolio project.

The objective is to strengthen practical understanding of security event analysis, detection engineering, investigation workflows, and evidence-based alert evaluation.
