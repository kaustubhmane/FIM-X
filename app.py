
import io
import os
import re
import sqlite3
from contextlib import redirect_stdout

import pandas as pd
import streamlit as st

from database import initialize_database, get_all_files
from scanner import create_baseline
from detector import scan_folder


st.set_page_config(
    page_title="FIM-X | Security Monitor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
.stApp {
    background: #0b1120;
}
[data-testid="stSidebar"] {
    background: #101a2c;
}
.block-container {
    padding-top: 2rem;
    max-width: 1500px;
}
div[data-testid="stMetric"] {
    background: #131f33;
    border: 1px solid #263650;
    padding: 18px;
    border-radius: 12px;
}
div[data-testid="stMetricLabel"] {
    color: #a9bad1;
}
h1, h2, h3 {
    color: #edf4ff;
}
.stButton button {
    border-radius: 8px;
    min-height: 42px;
}
</style>
""", unsafe_allow_html=True)


DB_PATH = os.path.join("data", "fimx.db")


def read_events():
    with sqlite3.connect(DB_PATH) as connection:
        return pd.read_sql_query("""
            SELECT timestamp AS Time,
                   event_type AS Event,
                   file_path AS File,
                   old_hash AS 'Previous Hash',
                   new_hash AS 'Current Hash'
            FROM events
            ORDER BY id DESC
            LIMIT 200
        """, connection)


def read_active_alerts():
    with sqlite3.connect(DB_PATH) as connection:
        return pd.read_sql_query("""
            SELECT file_path AS File,
                   event_type AS Status,
                   old_hash AS 'Baseline Hash',
                   new_hash AS 'Current Hash',
                   first_seen AS 'First Detected',
                   last_seen AS 'Last Detected'
            FROM active_alerts
            ORDER BY last_seen DESC
        """, connection)


def read_baseline():
    with sqlite3.connect(DB_PATH) as connection:
        return pd.read_sql_query("""
            SELECT file_path AS File,
                   file_hash AS 'SHA-256',
                   file_size AS 'Size (bytes)',
                   last_modified AS 'Last Modified'
            FROM files
            ORDER BY file_path
        """, connection)


def run_and_capture(function, *args):
    output = io.StringIO()
    with redirect_stdout(output):
        function(*args)
    return output.getvalue()


initialize_database()

# Sidebar
with st.sidebar:
    st.markdown("# 🛡️ FIM-X")
    st.caption("FILE INTEGRITY MONITOR")
    st.divider()

    st.markdown("### Monitoring settings")
    folder = st.text_input(
        "Folder to monitor",
        value="monitored",
        help="Enter a folder path accessible to this application.",
    )

    st.divider()
    st.markdown("### Actions")

    run_scan = st.button(
        "🔍 Scan Now",
        type="primary",
        use_container_width=True,
    )

    refresh = st.button(
        "↻ Refresh Dashboard",
        use_container_width=True,
    )

    st.caption("Local monitoring • SHA-256 • SQLite")

if "scan_output" not in st.session_state:
    st.session_state.scan_output = ""

if "scan_stats" not in st.session_state:
    st.session_state.scan_stats = {
        "OK": 0, "MODIFIED": 0, "NEW": 0, "DELETED": 0
    }

if "action_message" not in st.session_state:
    st.session_state.action_message = ""

if run_scan:
    if not os.path.isdir(folder):
        st.session_state.action_message = (
            f"Folder not found: {folder}"
        )
    else:
        try:
            st.session_state.scan_output = run_and_capture(
                scan_folder, folder
            )
            from datetime import datetime
            st.session_state.last_scan_time = datetime.now().strftime(
            "%d %b %Y, %I:%M:%S %p"
            )

            output = st.session_state.scan_output
            stats = st.session_state.scan_stats

            patterns = {
                "OK": r"Files OK\s*:\s*(\d+)",
                "MODIFIED": r"Modified\s*:\s*(\d+)",
                "NEW": r"New Files\s*:\s*(\d+)",
                "DELETED": r"Deleted Files\s*:\s*(\d+)",
            }

            for key, pattern in patterns.items():
                match = re.search(pattern, output)
                stats[key] = int(match.group(1)) if match else 0

            st.session_state.scan_stats = stats
            st.session_state.action_message = "Scan completed."
        except Exception as error:
            st.session_state.action_message = f"Scan failed: {error}"

if refresh:
    st.rerun()


# Main dashboard
st.title("Security Operations Center")
st.caption("File integrity, change detection and security event auditing")

st.markdown("---")

if st.session_state.action_message:
    st.info(st.session_state.action_message)

try:
    baseline = read_baseline()
    events = read_events()
    active_alerts = read_active_alerts()
except Exception as error:
    st.error(f"Unable to read the database: {error}")
    st.stop()

stats = st.session_state.scan_stats

# Summary metrics
st.subheader("Security overview")

c1, c2, c3, c4 = st.columns(4)

c1.metric("Baseline files", len(baseline))
c2.metric("Files OK", stats["OK"])
c3.metric("Modified files", stats["MODIFIED"])
c4.metric("New / deleted", stats["NEW"] + stats["DELETED"])

if stats["MODIFIED"] or stats["NEW"] or stats["DELETED"]:
    st.warning("Changes detected during the last scan. Review the event history.")
elif st.session_state.scan_output:
    st.success("No integrity changes detected during the last scan.")
else:
    st.info("Run a scan to view the current integrity status.")

# Tabs
overview, alerts_tab, inventory, history = st.tabs([
    "📊 Scan results",
    "🚨 Active alerts",
    "📁 File inventory",
    "🧾 Event history",
])


with overview:
    st.subheader("Integrity monitoring")

    last_scan_time = st.session_state.get("last_scan_time")

    if last_scan_time:
        st.caption(f"Last scan: {last_scan_time}")
    else:
        st.caption("No scan has been run in this session.")

    stats = st.session_state.scan_stats

    if stats["MODIFIED"] or stats["NEW"] or stats["DELETED"]:
        st.warning("Changes detected during the last scan.")
    elif last_scan_time:
        st.success("No integrity changes detected during the last scan.")
    else:
        st.info("Select Scan Now to check your monitored folder.")

    st.subheader("Last scan results")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Files OK", stats["OK"])
    col2.metric("Modified", stats["MODIFIED"])
    col3.metric("New files", stats["NEW"])
    col4.metric("Deleted files", stats["DELETED"])

    st.subheader("Recent security activity")

    if not events.empty:
        st.dataframe(
            events.head(10),
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No security events recorded yet.")

    with st.expander("View scan details"):
        if st.session_state.scan_output:
            st.code(st.session_state.scan_output, language="text")
        else:
            st.write("Run a scan to see detailed output.")


with alerts_tab:
    st.subheader("Active security alerts")
    st.caption(
        "Current unresolved file integrity findings, "
        "separate from historical events."
    )

    alert_count = len(active_alerts)
    st.metric("Active alerts", alert_count)

    if active_alerts.empty:
        st.success("No active file integrity alerts.")
    else:
        st.dataframe(
            active_alerts,
            use_container_width=True,
            hide_index=True,
        )

        st.download_button(
            "Download active alerts (CSV)",
            data=active_alerts.to_csv(index=False).encode("utf-8"),
            file_name="fimx_active_alerts.csv",
            mime="text/csv",
        )


















































































































































with inventory:
    st.subheader("Trusted baseline")
    st.caption("Files and SHA-256 hashes recorded in SQLite.")

    if not baseline.empty:
        st.dataframe(
            baseline,
            use_container_width=True,
            hide_index=True,
        )
        st.download_button(
            "Download inventory CSV",
            baseline.to_csv(index=False).encode("utf-8"),
            file_name="fimx_inventory.csv",
            mime="text/csv",
        )
    else:
        st.info("No baseline files recorded yet.")


with history:
    st.subheader("Security event history")
    st.caption("Search, filter and export recorded integrity events.")

    if not events.empty:
        # Event type filters
        event_types = sorted(
            events["Event"].dropna().unique().tolist()
        )

        selected_types = st.multiselect(
            "Filter by event type",
            options=event_types,
            default=event_types,
            placeholder="Select event types",
        )

        search_text = st.text_input(
            "Search events",
            placeholder="Search file path, event or hash...",
        )

        # Apply filters
        filtered_events = events[
            events["Event"].isin(selected_types)
        ].copy()

        if search_text.strip():
            mask = filtered_events.astype(str).apply(
                lambda column: column.str.contains(
                    search_text.strip(),
                    case=False,
                    na=False,
                    regex=False,
                )
            ).any(axis=1)

            filtered_events = filtered_events[mask]

        # Results summary
        st.metric("Matching events", len(filtered_events))

        if filtered_events.empty:
            st.info("No events match your filters.")
        else:
            st.dataframe(
                filtered_events,
                use_container_width=True,
                hide_index=True,
            )

            st.download_button(
                "Download filtered events (CSV)",
                data=filtered_events.to_csv(
                    index=False
                ).encode("utf-8"),
                file_name="fimx_filtered_events.csv",
                mime="text/csv",
            )
    else:
        st.info("No security events recorded yet.")


st.divider()
st.caption(
    "FIM-X • Academic cybersecurity project • "
    "SHA-256 integrity monitoring"
)
