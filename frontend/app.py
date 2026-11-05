from pathlib import Path

import pandas as pd
import streamlit as st

st.set_page_config(
    page_title="SENTINELX | Security Operations",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Dark SOC-style interface
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


def find_column(columns, candidates):
    lookup = {str(c).lower().strip(): c for c in columns}
    for candidate in candidates:
        if candidate in lookup:
            return lookup[candidate]
    for column in columns:
        name = str(column).lower()
        if any(candidate in name for candidate in candidates):
            return column
    return None


# Locate the existing local dataset without modifying it.
project_root = Path(__file__).resolve().parent.parent
default_csv = project_root / "backend" / "data" / "attack_scenario.csv"

with st.sidebar:
    st.markdown("## 🛡️ SENTINELX")
    st.caption("SECURITY ANALYTICS")
    st.divider()
    st.markdown("### Data source")
    uploaded_file = st.file_uploader("Upload a security-events CSV", type=["csv"])
    st.caption("Your uploaded file is processed for this dashboard session.")
    st.divider()
    st.markdown("### Navigation")
    page = st.radio(
        "Choose a view",
        ["Overview", "Event Explorer", "Dataset Information"],
        label_visibility="collapsed",
    )
    st.divider()
    st.caption("Portfolio project · Experimental detection analytics")

data = None
data_source = None
load_error = None

try:
    if uploaded_file is not None:
        data = pd.read_csv(uploaded_file)
        data_source = uploaded_file.name
    elif default_csv.exists():
        data = pd.read_csv(default_csv)
        data_source = "backend/data/attack_scenario.csv"
except Exception as exc:
    load_error = str(exc)

st.markdown("""
<div class="hero">
  <div class="eyebrow">SECURITY OPERATIONS CENTER</div>
  <h1>SENTINELX</h1>
  <p>Security event analysis · Detection experiments · Dataset exploration</p>
</div>
""", unsafe_allow_html=True)

if load_error:
    st.error(f"Could not read the CSV file: {load_error}")

if data is None:
    st.warning("No dataset loaded yet.")
    st.write(
        "Upload your security-events CSV using the sidebar, or place your "
        "existing dataset at `backend/data/attack_scenario.csv`."
    )
    st.info(
        "The dashboard can open without a dataset, but the metrics and charts "
        "will appear after a CSV is loaded."
    )
    st.stop()

if data.empty:
    st.warning("The CSV was loaded, but it contains no data rows.")
    st.stop()

ground_truth_col = find_column(data.columns, ["ground_truth", "ground truth", "label"])
technique_col = find_column(data.columns, ["technique_id", "technique_name", "technique", "attack_type", "attack type"])
event_col = find_column(data.columns, ["event_id", "event id", "record_id", "timestamp"])
process_col = find_column(data.columns, ["process_name", "process name", "image"])
user_col = find_column(data.columns, ["user", "username", "account"])

labels = None
positive_count = None
negative_count = None

if ground_truth_col is not None:
    raw_labels = data[ground_truth_col].astype(str).str.strip().str.lower()
    positive_values = {"true", "1", "yes", "positive", "malicious", "attack"}
    negative_values = {"false", "0", "no", "negative", "benign", "normal"}
    labels = raw_labels.map(
        lambda value: True if value in positive_values
        else False if value in negative_values
        else None
    )
    positive_count = int((labels == True).sum())  # noqa: E712
    negative_count = int((labels == False).sum())  # noqa: E712

if page == "Overview":
    st.markdown('<div class="section-title">Security Overview</div>',
                unsafe_allow_html=True)

    metrics = [
        ("TOTAL RECORDS", f"{len(data):,}"),
        ("DATA COLUMNS", f"{len(data.columns):,}"),
        ("LABELLED POSITIVE", f"{positive_count:,}" if positive_count is not None else "N/A"),
        ("LABELLED NEGATIVE", f"{negative_count:,}" if negative_count is not None else "N/A"),
    ]

    columns = st.columns(4)
    for column, (label, value) in zip(columns, metrics):
        with column:
            st.markdown(
                f'<div class="metric"><div class="metric-label">{label}</div>'
                f'<div class="metric-value">{value}</div></div>',
                unsafe_allow_html=True,
            )

    st.markdown('<div class="section-title">Dataset Analytics</div>',
                unsafe_allow_html=True)
    left, right = st.columns(2)

    with left:
        st.markdown("#### Records by attack technique")
        if technique_col is not None:
            counts = (
                data[technique_col].fillna("Unknown")
                .astype(str).value_counts().head(12)
            )
            st.bar_chart(counts)
        else:
            st.info("No recognisable technique column was found in this CSV.")

    with right:
        st.markdown("#### Ground-truth distribution")
        if labels is not None:
            distribution = pd.Series({
                "Positive": int((labels == True).sum()),  # noqa: E712
                "Negative": int((labels == False).sum()),  # noqa: E712
                "Unrecognised / missing": int(labels.isna().sum()),
            })
            st.bar_chart(distribution)
        else:
            st.info("No ground-truth or label column was found in this CSV.")

    st.markdown('<div class="section-title">Recent Dataset Records</div>',
                unsafe_allow_html=True)
    st.dataframe(data.head(10), width="stretch", hide_index=True)

elif page == "Event Explorer":
    st.markdown('<div class="section-title">Event Explorer</div>',
                unsafe_allow_html=True)
    st.caption("Search and filter the records loaded from your CSV.")

    search_text = st.text_input("Search across all columns", placeholder="Enter a keyword...")
    filtered = data.copy()

    if search_text.strip():
        mask = filtered.astype(str).apply(
            lambda column: column.str.contains(
                search_text, case=False, na=False, regex=False
            )
        ).any(axis=1)
        filtered = filtered[mask]

    if technique_col is not None:
        techniques = sorted(data[technique_col].dropna().astype(str).unique())
        selected = st.multiselect("Filter by technique", techniques)
        if selected:
            filtered = filtered[filtered[technique_col].astype(str).isin(selected)]

    st.caption(f"Showing {len(filtered):,} of {len(data):,} records")
    st.dataframe(filtered, width="stretch", hide_index=True)

    csv_bytes = filtered.to_csv(index=False).encode("utf-8")
    st.download_button(
        "Download filtered records as CSV",
        data=csv_bytes,
        file_name="sentinelx_filtered_events.csv",
        mime="text/csv",
    )

else:
    st.markdown('<div class="section-title">Dataset Information</div>',
                unsafe_allow_html=True)
    st.write(f"**Loaded from:** `{data_source}`")
    st.write(f"**Rows:** {len(data):,}")
    st.write(f"**Columns:** {len(data.columns):,}")
    st.write(f"**Missing cells:** {int(data.isna().sum().sum()):,}")

    schema = pd.DataFrame({
        "Column": data.columns.astype(str),
        "Data type": data.dtypes.astype(str).values,
        "Missing values": data.isna().sum().values,
        "Unique values": data.nunique(dropna=True).values,
    })
    st.dataframe(schema, width="stretch", hide_index=True)

st.divider()
st.markdown(
    '<p class="small-note">SENTINELX · Experimental security analytics. '
    'Dataset labels are reference labels, not proof of real-world detection accuracy.</p>',
    unsafe_allow_html=True,
)
