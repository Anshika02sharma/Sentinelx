from pathlib import Path
import sys
from collections import defaultdict
from datetime import datetime, timezone

import pandas as pd
import streamlit as st


# ==================================================
# PROJECT PATHS AND DETECTION ENGINE
# ==================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

DATA_FILE = PROJECT_ROOT / "backend" / "data" / "attack_scenario.csv"

try:
    from backend import compare_lsass_rules as lsass_engine
    from backend import investigation as investigation_engine
    from backend.smb_correlation import (
        build_smb_activity_windows, count_smb_activity_windows, parse_smb_time
    )
    DETECTION_ENGINE_AVAILABLE = True
    DETECTION_IMPORT_ERROR = None
except Exception as exc:
    DETECTION_ENGINE_AVAILABLE = False
    DETECTION_IMPORT_ERROR = str(exc)
    investigation_engine = None


# ==================================================
# PAGE CONFIGURATION
# ==================================================

st.set_page_config(
    page_title="SENTINELX | Security Operations",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ==================================================
# CUSTOM SOC THEME
# ==================================================

st.markdown("""
<style>
.stApp {
    background: #080d18;
    color: #e7edf7;
}
[data-testid="stSidebar"] {
    background: #0d1423;
    border-right: 1px solid #202c40;
}
.block-container {
    padding-top: 2rem;
    padding-bottom: 2rem;
    max-width: 1500px;
}
.hero {
    padding: 26px 30px;
    border: 1px solid #263750;
    border-radius: 16px;
    background: linear-gradient(120deg, #111e32, #101629);
    margin-bottom: 22px;
}
.eyebrow {
    color: #50dfc0;
    font-size: 12px;
    letter-spacing: 3px;
    font-weight: 700;
}
.hero h1 {
    font-size: 35px;
    margin: 8px 0;
    color: #f4f7ff;
}
.hero p {
    color: #a8b6cc;
    margin-bottom: 0;
}
.metric {
    background: #101827;
    border: 1px solid #263750;
    border-radius: 13px;
    padding: 18px;
    min-height: 112px;
}
.metric-label {
    color: #a8b6cc;
    font-size: 13px;
}
.metric-value {
    color: #f4f7ff;
    font-size: 29px;
    font-weight: 700;
    margin-top: 8px;
}
.section-title {
    color: #f4f7ff;
    font-size: 20px;
    font-weight: 650;
    margin: 18px 0 12px;
}
.small-note {
    color: #91a2ba;
    font-size: 12px;
}
</style>
""", unsafe_allow_html=True)


# ==================================================
# HELPER FUNCTIONS
# ==================================================

def find_column(columns, candidates):
    lookup = {
        str(column).lower().strip(): column
        for column in columns
    }

    for candidate in candidates:
        if candidate in lookup:
            return lookup[candidate]

    for column in columns:
        name = str(column).lower()
        if any(candidate in name for candidate in candidates):
            return column

    return None


# ==================================================
# DETECTION LAB
# ==================================================

def render_detection_lab(rows_override=None, dataset_label=None):

    st.markdown(
        '<div class="section-title">'
        'LSASS Detection Rule Evaluation'
        '</div>',
        unsafe_allow_html=True,
    )

    st.caption(
        "Compare candidate detection rules against labelled "
        "LSASS records using the existing SENTINELX evaluation engine."
    )

    if not DETECTION_ENGINE_AVAILABLE:

        st.error(
            "The LSASS detection engine could not be imported."
        )

        st.code(DETECTION_IMPORT_ERROR)

        st.info(
            "Check that backend/compare_lsass_rules.py exists "
            "and that its dependencies are available."
        )

        return

    try:
        rows = (
            rows_override
            if rows_override is not None
            else lsass_engine.load_dataset()
        )

    except Exception as exc:

        st.error(
            f"Could not load the configured dataset: {exc}"
        )

        return

    lsass_rows = [
        row for row in rows
        if (
            row.get("technique_id", "").strip()
            == "T1003.001"
            and row.get("ground_truth", "").strip().lower()
            in {"true", "false"}
        )
    ]

    if not lsass_rows:

        st.warning(
            "No labelled LSASS records (T1003.001) "
            "were found in the configured dataset."
        )

        return

    # --------------------------------------------------
    # LSASS EVALUATION SCOPE
    # --------------------------------------------------

    st.markdown("#### Evaluation scope")

    col1, col2 = st.columns(2)

    with col1:
        st.metric(
            "Labelled LSASS records",
            len(lsass_rows),
        )

    with col2:
        positive_records = sum(
            row.get("ground_truth", "").strip().lower()
            == "true"
            for row in lsass_rows
        )

        st.metric(
            "Reference-positive records",
            positive_records,
        )

    st.divider()

    # --------------------------------------------------
    # RULE COMPARISON
    # --------------------------------------------------

    results = {}

    for rule_name in (
        "Rule A",
        "Rule B",
        "Rule C",
    ):

        results[rule_name] = (
            lsass_engine.evaluate_rule(
                rows,
                rule_name,
            )
        )

    st.markdown("#### Rule comparison")

    comparison = pd.DataFrame([
        {
            "Rule": rule_name,
            "TP": result["TP"],
            "FP": result["FP"],
            "FN": result["FN"],
            "TN": result["TN"],
            "Precision": f'{result["precision"]:.2%}',
            "Recall": f'{result["recall"]:.2%}',
            "F1 Score": f'{result["f1"]:.2%}',
        }
        for rule_name, result in results.items()
    ])

    st.dataframe(
        comparison,
        width="stretch",
        hide_index=True,
    )

    # --------------------------------------------------
    # SELECT RULE
    # --------------------------------------------------

    st.markdown(
        "#### Select a rule for detailed analysis"
    )

    selected_rule = st.selectbox(
        "Detection rule",
        ["Rule A", "Rule B", "Rule C"],
    )

    result = results[selected_rule]

    # --------------------------------------------------
    # CONFUSION MATRIX METRICS
    # --------------------------------------------------

    metric_columns = st.columns(4)

    metric_values = [
        ("TRUE POSITIVES", result["TP"]),
        ("FALSE POSITIVES", result["FP"]),
        ("FALSE NEGATIVES", result["FN"]),
        ("TRUE NEGATIVES", result["TN"]),
    ]

    for column, (label, value) in zip(
        metric_columns,
        metric_values,
    ):

        with column:

            st.markdown(
                f'<div class="metric">'
                f'<div class="metric-label">{label}</div>'
                f'<div class="metric-value">{value}</div>'
                f'</div>',
                unsafe_allow_html=True,
            )

    # --------------------------------------------------
    # DETECTION PERFORMANCE
    # --------------------------------------------------

    st.markdown("#### Detection performance")

    performance_columns = st.columns(3)

    performance_values = [
        ("Precision", result["precision"]),
        ("Recall", result["recall"]),
        ("F1 Score", result["f1"]),
    ]

    for column, (label, value) in zip(
        performance_columns,
        performance_values,
    ):

        with column:
            st.metric(label, f"{value:.2%}")

    st.divider()

    # --------------------------------------------------
    # MISSED DETECTIONS
    # --------------------------------------------------

    st.markdown("#### Missed detections")

    missed = []

    for row in lsass_rows:

        actual = (
            row.get("ground_truth", "").strip().lower()
            == "true"
        )

        predicted = lsass_engine.predict_rule(
            row,
            selected_rule,
        )

        if actual and not predicted:
            missed.append(row)

    st.caption(
        f"{len(missed)} reference-positive records "
        f"were missed by {selected_rule}."
    )

    if missed:

        missed_df = pd.DataFrame(missed)

        preferred_columns = [
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

        available_columns = [
            column
            for column in preferred_columns
            if column in missed_df.columns
        ]

        if available_columns:
            missed_df = missed_df[available_columns]

        st.dataframe(
            missed_df,
            width="stretch",
            hide_index=True,
        )

        csv_data = (
            missed_df.to_csv(index=False)
            .encode("utf-8")
        )

        st.download_button(
            "Download missed detections",
            data=csv_data,
            file_name=(
                "sentinelx_"
                f"{selected_rule.lower().replace(' ', '_')}"
                "_missed.csv"
            ),
            mime="text/csv",
        )

    else:

        st.success(
            "No reference-positive records were missed by this rule "
            "in the evaluated dataset."
        )

    # Explain an individual LSASS rule outcome with traceable event evidence.
    st.markdown("#### Explain an LSASS event")
    lsass_event_options = list(enumerate(lsass_rows))
    selected_event_index = st.selectbox(
        "Choose an LSASS event",
        options=[index for index, _ in lsass_event_options],
        format_func=lambda index: (
            f"Event {lsass_rows[index].get('event_id') or index} · "
            f"{lsass_rows[index].get('host') or 'Unknown host'} · "
            f"{lsass_rows[index].get('_time') or 'Unknown time'}"
        ),
        key="lsass_explain_event",
    )
    selected_event = lsass_rows[selected_event_index]
    selected_prediction = lsass_engine.predict_rule(selected_event, selected_rule)
    lsass_explanation = investigation_engine.explain_lsass_event(
        selected_event, selected_rule, selected_prediction
    )
    with st.container(border=True):
        st.markdown(f"**{lsass_explanation['status']}**")
        st.write(lsass_explanation["why_flagged"])
        if lsass_explanation["matched_conditions"]:
            st.markdown("**Matched conditions**")
            for condition in lsass_explanation["matched_conditions"]:
                st.write(f"- {condition}")
        st.markdown("**Supporting event evidence**")
        st.json(lsass_explanation["supporting_evidence"][0]["fields"])
        st.markdown("**Signals that could increase confidence**")
        for signal in lsass_explanation["signals_that_could_increase_confidence"]:
            st.write(f"- {signal}")
        st.markdown("**Signals that could reduce confidence**")
        for signal in lsass_explanation["signals_that_could_reduce_confidence"]:
            st.write(f"- {signal}")
        st.markdown("**Limitations / missing evidence**")
        for item in lsass_explanation["limitations_and_missing_evidence"]:
            st.write(f"- {item}")
        st.markdown("**Recommended next steps**")
        for item in lsass_explanation["recommended_next_steps"]:
            st.write(f"- {item}")

    st.divider()

    # --------------------------------------------------
    # EVALUATION LIMITATIONS
    # --------------------------------------------------

    st.markdown("#### Evaluation limitations")

    st.warning(
        "These results apply only to the labelled LSASS records "
        "in the configured dataset. They do not establish real-world "
        "detection accuracy or prove credential theft."
    )

    st.markdown("""
    - Reference labels are evaluation labels, not proof of malicious activity.
    - Access masks and usernames alone cannot establish credential theft.
    - Rule performance needs validation against independent datasets.
    - A rule with high scores on a small dataset may be overfitted.
    - These rules are experimental and are not production-validated.
    """)

    # ==================================================
    # SMB ACTIVITY CORRELATION
    # ==================================================

    st.divider()

    st.markdown("### SMB Activity Correlation")

    st.caption(
        "Review SMB admin-share activity and execution-related "
        "targets within 60-second host/user activity windows."
    )

    smb_grouped, smb_candidates = (
        build_smb_activity_windows(
            rows,
            window_seconds=60,
        )
    )

    smb_window_count = (
        count_smb_activity_windows(
            smb_grouped,
            window_seconds=60,
        )
    )

    # --------------------------------------------------
    # SMB METRICS
    # --------------------------------------------------

    smb_metrics = st.columns(3)

    with smb_metrics[0]:
        st.metric(
            "SMB host/user groups",
            len(smb_grouped),
        )

    with smb_metrics[1]:
        st.metric(
            "Activity windows reviewed",
            smb_window_count,
        )

    with smb_metrics[2]:
        st.metric(
            "Candidate windows flagged",
            len(smb_candidates),
        )

    st.info(
        "A candidate window is flagged when it contains both "
        "an Admin$ share reference and an execution-related target term. "
        "This is an exploratory correlation signal, not a confirmed incident."
    )

    # --------------------------------------------------
    # SMB CANDIDATE WINDOWS
    # --------------------------------------------------

    if smb_candidates:

        smb_display = pd.DataFrame([
            {
                key: value
                for key, value in candidate.items()
                if key != "_events"
            }
            for candidate in smb_candidates
        ])

        st.markdown("#### Candidate activity windows")

        st.dataframe(
            smb_display,
            width="stretch",
            hide_index=True,
        )

        # --------------------------------------------------
        # SMB EVENT DETAILS
        # --------------------------------------------------

        smb_event_rows = [
            event
            for candidate in smb_candidates
            for event in candidate["_events"]
        ]

        smb_events_df = pd.DataFrame(
            smb_event_rows
        )

        preferred_smb_columns = [
            "_time",
            "event_id",
            "host",
            "user",
            "share_name",
            "relative_target_name",
            "ground_truth",
            "scenario_stage",
            "trace_id",
        ]

        available_smb_columns = [
            column
            for column in preferred_smb_columns
            if column in smb_events_df.columns
        ]

        if available_smb_columns:
            smb_events_df = smb_events_df[
                available_smb_columns
            ]

        with st.expander(
            "Inspect events in candidate windows"
        ):

            st.dataframe(
                smb_events_df,
                width="stretch",
                hide_index=True,
            )

        # --------------------------------------------------
        # SMB CSV DOWNLOAD
        # --------------------------------------------------

        st.download_button(
            "Download SMB candidate events",
            data=(
                smb_events_df.to_csv(index=False)
                .encode("utf-8")
            ),
            file_name="sentinelx_smb_candidate_events.csv",
            mime="text/csv",
        )

        # Evidence-led explanation for every flagged SMB activity window.
        st.markdown("#### Why each SMB window was flagged")
        smb_findings = []
        for candidate_index, candidate in enumerate(smb_candidates, start=1):
            finding = investigation_engine.explain_smb_window(candidate, window_seconds=60)
            smb_findings.append(finding)
            with st.expander(f"{candidate.get('Host', 'Unknown host')} · {candidate.get('User', 'Unknown user')} · Window {candidate.get('Window', candidate_index)}"):
                st.markdown(f"**{finding['status']}**")
                st.write(finding["why_flagged"])
                st.markdown("**Matched conditions**")
                for condition in finding["matched_conditions"]:
                    st.write(f"- {condition['condition']}: {'Matched' if condition['matched'] else 'Not matched'} ({condition['matching_event_count']} event(s))")
                st.markdown("**Supporting evidence**")
                for evidence in finding["supporting_evidence"]:
                    st.write(f"- **{evidence['type']}:** {evidence['detail']}")
                    if evidence.get("targets"):
                        st.write("  Targets: " + "; ".join(evidence["targets"]))
                    if evidence.get("matched_terms"):
                        st.write("  Matched terms: " + ", ".join(evidence["matched_terms"]))
                if finding.get("evidence_events"):
                    st.markdown("**Exact matching source events**")
                    st.dataframe(pd.DataFrame(finding["evidence_events"]), width="stretch", hide_index=True)
                st.markdown(f"**Evidence assessment:** {finding['confidence_assessment']['label']}")
                st.caption(finding["confidence_assessment"]["meaning"])
                for heading, key in (("Signals that could increase confidence", "signals_that_could_increase_confidence"), ("Signals that could reduce confidence", "signals_that_could_reduce_confidence"), ("Limitations and missing evidence", "limitations_and_missing_evidence"), ("Recommended next steps", "recommended_next_steps")):
                    st.markdown(f"**{heading}**")
                    for item in finding[key]:
                        st.write(f"- {item}")

    else:
        smb_findings = []

        st.success(
            "No SMB activity windows matched the configured "
            "candidate conditions in this dataset."
        )

    st.caption(
        "SMB review is read-only and exploratory. It does not calculate "
        "precision/recall because the current correlation logic flags "
        "activity windows rather than evaluating validated window-level "
        "ground truth."
    )

    # Export a combined, evidence-led investigation report.
    lsass_findings = [
        investigation_engine.explain_lsass_event(
            event, selected_rule, lsass_engine.predict_rule(event, selected_rule)
        )
        for event in lsass_rows
    ]
    report = investigation_engine.build_investigation_report(
        dataset_name=str(dataset_label or DATA_FILE.name),
        lsass_findings=lsass_findings,
        smb_findings=smb_findings,
        summary={
            "selected_lsass_rule": selected_rule,
            "labelled_lsass_records": len(lsass_rows),
            "true_positives": result["TP"],
            "false_positives": result["FP"],
            "false_negatives": result["FN"],
            "true_negatives": result["TN"],
            "precision": f"{result['precision']:.2%}",
            "recall": f"{result['recall']:.2%}",
            "f1_score": f"{result['f1']:.2%}",
            "smb_candidate_windows": len(smb_findings),
        },
    )
    st.divider()
    st.markdown("### Investigation report")
    st.caption("Export includes rule outcomes, explanations, event evidence, corroborating signals, limitations and recommended investigation steps.")
    report_col1, report_col2 = st.columns(2)
    with report_col1:
        st.download_button(
            "Download investigation report (Markdown)",
            data=investigation_engine.report_as_markdown(report),
            file_name="sentinelx_investigation_report.md",
            mime="text/markdown",
            use_container_width=True,
        )
    with report_col2:
        st.download_button(
            "Download investigation report (JSON)",
            data=investigation_engine.report_as_json(report),
            file_name="sentinelx_investigation_report.json",
            mime="application/json",
            use_container_width=True,
        )


# ==================================================
# SIDEBAR
# ==================================================

with st.sidebar:

    st.markdown("## 🛡️ SENTINELX")
    st.caption("SECURITY ANALYTICS")

    st.divider()

    st.markdown("### Data source")

    uploaded_file = st.file_uploader(
        "Upload a security-events CSV",
        type=["csv"],
    )

    st.caption(
        "Your uploaded file is processed for this dashboard session."
    )

    st.divider()

    st.markdown("### Navigation")

    page = st.radio(
        "Choose a view",
        [
            "Overview",
            "Event Explorer",
            "Dataset Information",
            "Detection Lab",
        ],
        label_visibility="collapsed",
    )

    st.divider()

    st.caption(
        "Portfolio project · Experimental detection analytics"
    )


# ==================================================
# LOAD DASHBOARD DATA
# ==================================================

data = None
data_source = None
load_error = None

try:

    if uploaded_file is not None:

        data = pd.read_csv(uploaded_file)
        data_source = uploaded_file.name

    elif DATA_FILE.exists():

        data = pd.read_csv(DATA_FILE)
        data_source = "backend/data/attack_scenario.csv"

except Exception as exc:
    load_error = str(exc)


# ==================================================
# DASHBOARD HEADER
# ==================================================

st.markdown("""
<div class="hero">
    <div class="eyebrow">SECURITY OPERATIONS CENTER</div>
    <h1>SENTINELX</h1>
    <p>
        Security event analysis · Detection experiments · Dataset exploration
    </p>
</div>
""", unsafe_allow_html=True)


# ==================================================
# DETECTION LAB PAGE
# ==================================================

if page == "Detection Lab":

    detection_rows = (
        data.fillna("").astype(str).to_dict(orient="records")
        if data is not None and not data.empty
        else None
    )
    render_detection_lab(detection_rows, data_source)


# ==================================================
# OTHER DASHBOARD PAGES
# ==================================================

else:

    if load_error:
        st.error(
            f"Could not read the CSV file: {load_error}"
        )

    if data is None:

        st.warning("No dataset loaded yet.")

        st.write(
            "Upload your security-events CSV using the sidebar, "
            "or place your existing dataset at "
            "`backend/data/attack_scenario.csv`."
        )

        st.info(
            "The dashboard can open without a dataset, but "
            "the metrics and charts will appear after a CSV is loaded."
        )

        st.stop()

    if data.empty:

        st.warning(
            "The CSV was loaded, but it contains no data rows."
        )

        st.stop()

    # --------------------------------------------------
    # IDENTIFY DATASET COLUMNS
    # --------------------------------------------------

    ground_truth_col = find_column(
        data.columns,
        [
            "ground_truth",
            "ground truth",
            "label",
        ],
    )

    technique_col = find_column(
        data.columns,
        [
            "technique_id",
            "technique_name",
            "technique",
            "attack_type",
            "attack type",
        ],
    )

    labels = None
    positive_count = None
    negative_count = None

    if ground_truth_col is not None:

        raw_labels = (
            data[ground_truth_col]
            .astype(str)
            .str.strip()
            .str.lower()
        )

        positive_values = {
            "true",
            "1",
            "yes",
            "positive",
            "malicious",
            "attack",
        }

        negative_values = {
            "false",
            "0",
            "no",
            "negative",
            "benign",
            "normal",
        }

        labels = raw_labels.map(
            lambda value: (
                True if value in positive_values
                else False if value in negative_values
                else None
            )
        )

        positive_count = int(
            (labels == True).sum()
        )

        negative_count = int(
            (labels == False).sum()
        )

    # ==================================================
    # OVERVIEW PAGE
    # ==================================================

    if page == "Overview":

        st.markdown(
            '<div class="section-title">Security Overview</div>',
            unsafe_allow_html=True,
        )

        metrics = [
            ("TOTAL RECORDS", f"{len(data):,}"),
            ("DATA COLUMNS", f"{len(data.columns):,}"),
            (
                "LABELLED POSITIVE",
                (
                    f"{positive_count:,}"
                    if positive_count is not None
                    else "N/A"
                ),
            ),
            (
                "LABELLED NEGATIVE",
                (
                    f"{negative_count:,}"
                    if negative_count is not None
                    else "N/A"
                ),
            ),
        ]

        columns = st.columns(4)

        for column, (label, value) in zip(
            columns,
            metrics,
        ):

            with column:

                st.markdown(
                    f'<div class="metric">'
                    f'<div class="metric-label">{label}</div>'
                    f'<div class="metric-value">{value}</div>'
                    f'</div>',
                    unsafe_allow_html=True,
                )

        st.markdown(
            '<div class="section-title">Dataset Analytics</div>',
            unsafe_allow_html=True,
        )

        left, right = st.columns(2)

        with left:

            st.markdown(
                "#### Records by attack technique"
            )

            if technique_col is not None:

                counts = (
                    data[technique_col]
                    .fillna("Unknown")
                    .astype(str)
                    .value_counts()
                    .head(12)
                )

                st.bar_chart(counts)

            else:

                st.info(
                    "No recognisable technique column "
                    "was found in this CSV."
                )

        with right:

            st.markdown(
                "#### Ground-truth distribution"
            )

            if labels is not None:

                distribution = pd.Series({
                    "Positive": int(
                        (labels == True).sum()
                    ),
                    "Negative": int(
                        (labels == False).sum()
                    ),
                    "Unrecognised / missing": int(
                        labels.isna().sum()
                    ),
                })

                st.bar_chart(distribution)

            else:

                st.info(
                    "No ground-truth or label column "
                    "was found in this CSV."
                )

        st.markdown(
            '<div class="section-title">'
            'Recent Dataset Records'
            '</div>',
            unsafe_allow_html=True,
        )

        st.dataframe(
            data.head(10),
            width="stretch",
            hide_index=True,
        )

    # ==================================================
    # EVENT EXPLORER PAGE
    # ==================================================

    elif page == "Event Explorer":

        st.markdown(
            '<div class="section-title">Event Explorer</div>',
            unsafe_allow_html=True,
        )

        st.caption(
            "Search and filter the records loaded from your CSV."
        )

        search_text = st.text_input(
            "Search across all columns",
            placeholder="Enter a keyword...",
        )

        filtered = data.copy()

        if search_text.strip():

            mask = filtered.astype(str).apply(
                lambda column: column.str.contains(
                    search_text,
                    case=False,
                    na=False,
                    regex=False,
                )
            ).any(axis=1)

            filtered = filtered[mask]

        if technique_col is not None:

            techniques = sorted(
                data[technique_col]
                .dropna()
                .astype(str)
                .unique()
            )

            selected = st.multiselect(
                "Filter by technique",
                techniques,
            )

            if selected:

                filtered = filtered[
                    filtered[technique_col]
                    .astype(str)
                    .isin(selected)
                ]

        st.caption(
            f"Showing {len(filtered):,} of {len(data):,} records"
        )

        st.dataframe(
            filtered,
            width="stretch",
            hide_index=True,
        )

        csv_bytes = (
            filtered.to_csv(index=False)
            .encode("utf-8")
        )

        st.download_button(
            "Download filtered records as CSV",
            data=csv_bytes,
            file_name="sentinelx_filtered_events.csv",
            mime="text/csv",
        )

    # ==================================================
    # DATASET INFORMATION PAGE
    # ==================================================

    elif page == "Dataset Information":

        st.markdown(
            '<div class="section-title">'
            'Dataset Information'
            '</div>',
            unsafe_allow_html=True,
        )

        st.write(
            f"**Loaded from:** `{data_source}`"
        )

        st.write(
            f"**Rows:** {len(data):,}"
        )

        st.write(
            f"**Columns:** {len(data.columns):,}"
        )

        st.write(
            f"**Missing cells:** "
            f"{int(data.isna().sum().sum()):,}"
        )

        schema = pd.DataFrame({
            "Column": data.columns.astype(str),
            "Data type": data.dtypes.astype(str).values,
            "Missing values": data.isna().sum().values,
            "Unique values": data.nunique(
                dropna=True
            ).values,
        })

        st.dataframe(
            schema,
            width="stretch",
            hide_index=True,
        )


# ==================================================
# FOOTER
# ==================================================

st.divider()

st.markdown(
    '<p class="small-note">'
    'SENTINELX · Experimental security analytics. '
    'Dataset labels are reference labels, not proof of real-world '
    'detection accuracy.'
    '</p>',
    unsafe_allow_html=True,
)