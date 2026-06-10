import os
import datetime
from pathlib import Path

import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import yaml
import json
from typing import Any, Dict, List, Optional

# Import backend modules
from utils import load_config_file
from drift_detector import detect_drift
from database import (
    init_db,
    save_drift_entry,
    save_ai_analysis,
    get_scan_history_summary,
    get_scan_history_by_file,
    get_drill_down_drifts,
    search_drifts,
    get_analytics_metrics,
    clear_all_history,
)
from auth import (
    authenticate_user,
    create_default_admin_user,
    get_user_profile,
    register_user,
    save_user_profile,
    change_user_password,
    hash_password,
)
from notifications import send_email_notification
from ai_analysis import analyze_drift_with_ai
from report_generator import generate_pdf_report, get_severity_color

# Page config
st.set_page_config(
    page_title="Config Drift Detector",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Constants
DB_DIR = Path(__file__).resolve().parent
DB_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = str(DB_DIR / "database.db")

# Initialize SQLite database
init_db(DB_PATH)
create_default_admin_user(DB_PATH)

# Inject custom CSS for premium dark-themed DevOps style
st.markdown("""
<style>
    /* Dark Theme Base Overrides */
    .stApp {
        background-color: #0F172A;
        color: #F8FAFC;
    }
    
    /* Sidebar styling */
    section[data-testid="stSidebar"] {
        background-color: #1E293B !important;
        border-right: 1px solid #334155;
    }
    
    /* Title styling */
    h1, h2, h3 {
        color: #F8FAFC !important;
        font-family: 'Inter', -apple-system, sans-serif;
    }
    
    /* Glassmorphic Metric Cards */
    .metric-card {
        background: linear-gradient(135deg, #1E293B 0%, #0F172A 100%);
        border: 1px solid #334155;
        border-radius: 12px;
        padding: 20px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        text-align: center;
        transition: transform 0.2s;
    }
    .metric-card:hover {
        transform: translateY(-2px);
        border-color: #475569;
    }
    .metric-val {
        font-size: 2rem;
        font-weight: 700;
        color: #38BDF8;
        margin: 5px 0;
    }
    .metric-lbl {
        font-size: 0.85rem;
        color: #94A3B8;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    
    /* Status Badges */
    .badge {
        padding: 4px 10px;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 600;
        display: inline-block;
        text-align: center;
    }
    .badge-critical { background-color: rgba(239, 68, 68, 0.2); color: #EF4444; border: 1px solid #EF4444; }
    .badge-high { background-color: rgba(249, 115, 22, 0.2); color: #F97316; border: 1px solid #F97316; }
    .badge-medium { background-color: rgba(245, 158, 11, 0.2); color: #F59E0B; border: 1px solid #F59E0B; }
    .badge-low { background-color: rgba(16, 185, 129, 0.2); color: #10B981; border: 1px solid #10B981; }
    
    /* Card details */
    .drift-details-container {
        background-color: #1E293B;
        border: 1px solid #334155;
        border-radius: 8px;
        padding: 15px;
        margin-bottom: 15px;
    }
    .impact-header {
        font-size: 0.9rem;
        font-weight: 600;
        color: #E2E8F0;
        margin-top: 10px;
        margin-bottom: 2px;
        border-bottom: 1px solid #334155;
        padding-bottom: 2px;
    }
</style>
""", unsafe_allow_html=True)

# Helper function to load and parse uploaded config files
def load_uploaded_config(uploaded_file) -> Optional[Dict[str, Any]]:
    """Reads and parses an uploaded file uploader stream into a dictionary."""
    try:
        uploaded_file.seek(0)
        content = uploaded_file.read().decode("utf-8")
        name = uploaded_file.name.lower()
        if name.endswith(".json"):
            return json.loads(content)
        elif name.endswith((".yaml", ".yml")):
            return yaml.safe_load(content)
    except Exception as e:
        st.error(f"Error parsing uploaded file '{uploaded_file.name}': {str(e)}")
    return None


def compose_drift_alert_email(user_name: str, timestamp: str, drifts: List[Dict[str, Any]]) -> str:
    """Builds a user-specific alert email body for detected configuration drifts."""
    total = len(drifts)
    critical = sum(1 for d in drifts if d["severity"] == "Critical")
    high = sum(1 for d in drifts if d["severity"] == "High")
    medium = sum(1 for d in drifts if d["severity"] == "Medium")
    low = sum(1 for d in drifts if d["severity"] == "Low")
    files = sorted({d["file_name"] for d in drifts})

    tech = drifts[0].get("technical_impact", "No technical summary available.") if drifts else ""
    biz = drifts[0].get("business_impact", "No business summary available.") if drifts else ""
    sec = drifts[0].get("security_impact", "No security summary available.") if drifts else ""
    recommendation = drifts[0].get("recommendation", "No recommendation available.") if drifts else ""

    body_lines = [
        f"Hello {user_name},",
        "",
        f"Your latest configuration drift scan completed at {timestamp}.",
        f"Total drifts detected: {total}",
        "",
        "Severity breakdown:",
        f"- Critical: {critical}",
        f"- High: {high}",
        f"- Medium: {medium}",
        f"- Low: {low}",
        "",
        f"Affected files: {', '.join(files)}",
        "",
        "AI generated summary:",
        f"Technical Impact: {tech}",
        f"Business Impact: {biz}",
        f"Security Impact: {sec}",
        "",
        f"Recommended action: {recommendation}",
        "",
        "Please review the dashboard for a full drift analysis and remediation plan.",
        "",
        "Thank you,",
        "Config Drift Detector",
    ]

    return "\n".join(body_lines)

# Initialize Session State
for key, default in {
    "logged_in": False,
    "user_id": None,
    "user_email": "",
    "user_name": "",
    "selected_page": "🔍 Compare & Detect",
    "scan_results": None,
    "auth_page": "login",
    "auth_message": "",
}.items():
    if key not in st.session_state:
        st.session_state[key] = default


def render_login_page() -> None:
    st.title("🔐 Login to Config Drift Detector")
    st.write("Please sign in to access drift detection, dashboard analytics, and profile settings.")
    if st.session_state.get("auth_message"):
        st.success(st.session_state.pop("auth_message"))

    email = st.text_input("Email", value=st.session_state.get("login_email", ""), key="login_email")
    password = st.text_input("Password", type="password", key="login_password")
    login = st.button("Login", type="primary", use_container_width=True)

    if login:
        if not email or not password:
            st.error("Please enter both email and password.")
            return

        user = authenticate_user(DB_PATH, email, password)
        if user:
            st.session_state["logged_in"] = True
            st.session_state["user_id"] = user["id"]
            st.session_state["user_email"] = user["email"]
            st.session_state["user_name"] = user.get("name") or user["email"]
            st.session_state["selected_page"] = "🔍 Compare & Detect"
            st.success("Login successful. Redirecting to your dashboard...")
            st.rerun()
        else:
            st.error("Invalid email or password")

    if st.button("Create a new account", type="secondary", use_container_width=True):
        st.session_state["auth_page"] = "signup"
        st.rerun()

def render_signup_page() -> None:
    st.title("📝 Sign Up for Config Drift Detector")
    st.write("Create an account to begin tracking configuration drift and receive alert controls.")

    full_name = st.text_input("Full Name", key="signup_name")
    email = st.text_input("Email", key="signup_email")
    password = st.text_input("Password", type="password", key="signup_password")
    confirm_password = st.text_input("Confirm Password", type="password", key="signup_confirm_password")
    signup = st.button("Sign Up", type="primary", use_container_width=True)

    if signup:
        if not full_name or not email or not password or not confirm_password:
            st.error("Please complete all signup fields.")
            return
        if password != confirm_password:
            st.error("Passwords do not match.")
            return

        success, message = register_user(DB_PATH, full_name, email, password)
        if not success:
            st.error(message)
            return

        st.session_state["auth_page"] = "login"
        st.session_state["auth_message"] = message
        st.success(message)
        st.rerun()

    if st.button("Already have an account? Login", type="secondary", use_container_width=True):
        st.session_state["auth_page"] = "login"
        st.rerun()


if not st.session_state["logged_in"]:
    if st.session_state["auth_page"] == "signup":
        render_signup_page()
    else:
        render_login_page()
    st.stop()

# Sidebar Controls
st.sidebar.markdown("<h2 style='text-align: center; color: #38BDF8;'>🔍 Drift Control</h2>", unsafe_allow_html=True)
st.sidebar.markdown("---")

st.sidebar.markdown(
    f"<p style='color: #E2E8F0;'>Signed in as:<br><strong>{st.session_state['user_name']}</strong><br><span style='font-size: 0.9rem;'>{st.session_state['user_email']}</span></p>",
    unsafe_allow_html=True
)

pages = ["🔍 Compare & Detect", "📊 Analytics Dashboard", "📜 Scan History", "👤 Profile", "📄 Export Reports"]
selected_nav = st.sidebar.radio(
    "Navigation",
    pages,
    index=pages.index(st.session_state["selected_page"]) if st.session_state["selected_page"] in pages else 0,
    key="selected_page"
)

if st.sidebar.button("Logout", type="secondary"):
    for key in ["logged_in", "user_id", "user_email", "user_name", "selected_page", "scan_results"]:
        if key in st.session_state:
            del st.session_state[key]
    st.rerun()

st.sidebar.markdown("---")
st.sidebar.info(
    "💡 **Instructions:** Upload your golden templates (Intended) and your running environments (Actual). "
    "Matching is automatically executed by filenames. Review AI analysis and export compliance reports."
)

# ----------------- PAGE 1: COMPARE & DETECT -----------------
if st.session_state["selected_page"] == "🔍 Compare & Detect":
    st.title("🔍 Config Drift Comparison Engine")
    st.write("Upload intended ('golden') configurations and actual deployed properties to check compatibility and evaluate risks.")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### 1. Golden Configuration")
        intended_files = st.file_uploader(
            "Upload Intended Configs",
            accept_multiple_files=True,
            type=["json", "yaml", "yml"],
            key="intended_upload"
        )
        
    with col2:
        st.markdown("### 2. Deployed Configuration")
        actual_files = st.file_uploader(
            "Upload Actual Configs",
            accept_multiple_files=True,
            type=["json", "yaml", "yml"],
            key="actual_upload"
        )
        
    # Compare controls
    col_btn, _ = st.columns([1, 3])
    with col_btn:
        compare_clicked = st.button("🚀 Compare Configurations", type="primary", use_container_width=True)
        
    if compare_clicked:
        if not intended_files or not actual_files:
            st.error("Please upload files under both Golden and Deployed lists to begin comparison.")
        else:
            # Map uploaded files by lowercase filename
            intended_map = {f.name.lower(): f for f in intended_files}
            actual_map = {f.name.lower(): f for f in actual_files}
            
            # Match files
            matched_filenames = set(intended_map.keys()) & set(actual_map.keys())
            unmatched_intended = set(intended_map.keys()) - set(actual_map.keys())
            unmatched_actual = set(actual_map.keys()) - set(intended_map.keys())
            
            # Show warnings for unmatched filenames
            if unmatched_intended:
                unmatched_names = [intended_map[k].name for k in unmatched_intended]
                st.warning(f"⚠️ Unmatched Intended Files (no corresponding Deployed file): {', '.join(unmatched_names)}")
                
            if unmatched_actual:
                unmatched_names = [actual_map[k].name for k in unmatched_actual]
                st.warning(f"⚠️ Unmatched Actual Files (no corresponding Intended file): {', '.join(unmatched_names)}")
                
            if not matched_filenames:
                st.error("❌ No matching filenames found between uploaded Golden and Deployed config batches (filenames must be identical).")
            else:
                with st.spinner("Analyzing uploaded configuration payload..."):
                    files_checked = 0
                    all_drifts = []
                    parse_errors = []
                    
                    for filename_key in matched_filenames:
                        int_file = intended_map[filename_key]
                        act_file = actual_map[filename_key]
                        
                        int_conf = load_uploaded_config(int_file)
                        act_conf = load_uploaded_config(act_file)
                        
                        if int_conf is None or act_conf is None:
                            parse_errors.append(f"Failed to parse configuration structure for pair: {int_file.name}")
                            continue
                            
                        files_checked += 1
                        file_drifts = detect_drift(int_conf, act_conf, int_file.name)
                        all_drifts.extend(file_drifts)
                        
                    if parse_errors:
                        for err in parse_errors:
                            st.error(err)
                            
                    if files_checked > 0:
                        st.success(f"Successfully evaluated {files_checked} configuration file pair(s).")
                        
                        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        
                        if not all_drifts:
                            st.balloons()
                            st.success("Perfect alignment! Zero drifts detected between intended and deployed configurations.")
                            st.session_state["scan_results"] = None
                        else:
                            st.markdown(f"### Deployed Anomalies Found: `{len(all_drifts)}` issues")
                            
                            # Save findings and trigger AI impact
                            saved_drifts = []
                            progress_text = "Invoking AI Risk Assessments and writing logs to database..."
                            progress_info = st.empty()
                            progress_info.text(progress_text)
                            my_bar = st.progress(0)
                            
                            for idx, drift in enumerate(all_drifts):
                                # Save to SQLite comparison_history
                                comp_id = save_drift_entry(
                                    db_path=DB_PATH,
                                    timestamp=timestamp,
                                    file_name=drift["file_name"],
                                    config_path=drift["config_path"],
                                    drift_type=drift["drift_type"],
                                    severity=drift["severity"],
                                    intended_value=drift["intended_value"],
                                    actual_value=drift["actual_value"],
                                    user_id=st.session_state["user_id"]
                                )
                                
                                # Call Groq API / Fallback Mock (Reads API Key from env inside backend automatically)
                                ai_report = analyze_drift_with_ai(
                                    file_name=drift["file_name"],
                                    config_path=drift["config_path"],
                                    intended_value=drift["intended_value"],
                                    actual_value=drift["actual_value"],
                                    severity=drift["severity"]
                                )
                                
                                # Save to SQLite ai_analysis
                                save_ai_analysis(
                                    db_path=DB_PATH,
                                    comparison_id=comp_id,
                                    technical_impact=ai_report["technical_impact"],
                                    business_impact=ai_report["business_impact"],
                                    security_impact=ai_report["security_impact"],
                                    risk_rating=ai_report["risk_rating"],
                                    recommendation=ai_report["recommendation"]
                                )
                                
                                # Cache in session
                                merged = drift.copy()
                                merged.update(ai_report)
                                merged["drift_id"] = comp_id
                                merged["timestamp"] = timestamp
                                saved_drifts.append(merged)
                                
                                # Progress updates
                                my_bar.progress((idx + 1) / len(all_drifts))
                                progress_info.text(f"Analyzing {drift['config_path']} ({idx+1}/{len(all_drifts)})")
                                
                            st.session_state["scan_results"] = saved_drifts
                            my_bar.empty()

                            user_profile = get_user_profile(DB_PATH, st.session_state["user_id"])
                            recipient = st.session_state.get("user_email")
                            if not recipient:
                                st.warning("Drift detected, but no logged-in email address is available for alerts.")
                            elif not user_profile or not user_profile.get("notify_enabled", 1):
                                st.info("Email alerts are disabled in your profile; no SMTP notification was sent.")
                            else:
                                subject = f"Config Drift Alert – {len(saved_drifts)} issue(s) detected"
                                body = compose_drift_alert_email(
                                    user_name=user_profile.get("name") or recipient,
                                    timestamp=timestamp,
                                    drifts=saved_drifts,
                                )
                                sent, message = send_email_notification(
                                    to_address=recipient,
                                    subject=subject,
                                    body=body
                                )
                                if sent:
                                    st.success("Drift alert email notification was sent successfully.")
                                else:
                                    st.warning(f"Email alert could not be sent: {message}")

                            st.rerun()

    # Display Current Scan Results if available
    if st.session_state["scan_results"]:
        results = st.session_state["scan_results"]
        
        # Summary metrics
        total_d = len(results)
        crit_d = sum(1 for r in results if r["severity"] == "Critical")
        high_d = sum(1 for r in results if r["severity"] == "High")
        med_d = sum(1 for r in results if r["severity"] == "Medium")
        low_d = sum(1 for r in results if r["severity"] == "Low")
        
        col_m1, col_m2, col_m3, col_m4, col_m5 = st.columns(5)
        with col_m1:
            st.markdown(f'<div class="metric-card"><div class="metric-val">{total_d}</div><div class="metric-lbl">Total Drifts</div></div>', unsafe_allow_html=True)
        with col_m2:
            st.markdown(f'<div class="metric-card"><div class="metric-val" style="color: #EF4444;">{crit_d}</div><div class="metric-lbl">Critical</div></div>', unsafe_allow_html=True)
        with col_m3:
            st.markdown(f'<div class="metric-card"><div class="metric-val" style="color: #F97316;">{high_d}</div><div class="metric-lbl">High Risk</div></div>', unsafe_allow_html=True)
        with col_m4:
            st.markdown(f'<div class="metric-card"><div class="metric-val" style="color: #F59E0B;">{med_d}</div><div class="metric-lbl">Medium Risk</div></div>', unsafe_allow_html=True)
        with col_m5:
            st.markdown(f'<div class="metric-card"><div class="metric-val" style="color: #10B981;">{low_d}</div><div class="metric-lbl">Low Risk</div></div>', unsafe_allow_html=True)
            
        st.markdown("---")
        st.subheader("Anomalies Registry & AI Remediation Plans")
        
        # File selector to filter view
        files_list = list(set([r["file_name"] for r in results]))
        selected_file = st.selectbox("Filter Results by Config File", ["All Files"] + files_list)
        
        for idx, r in enumerate(results):
            if selected_file != "All Files" and r["file_name"] != selected_file:
                continue
                
            sev = r["severity"]
            badge_class = f"badge-{sev.lower()}"
            
            exp_header = f"🔧 {r['file_name']} ➔ `{r['config_path']}`"
            
            with st.expander(exp_header, expanded=True):
                # Columns for comparison
                col_exp1, col_exp2, col_exp3 = st.columns([2, 2, 2])
                with col_exp1:
                    st.markdown("**Expected Golden State:**")
                    st.code(r["intended_value"], language="json" if r["file_name"].endswith(".json") else "yaml")
                with col_exp2:
                    st.markdown("**Actual Deployed State:**")
                    st.code(r["actual_value"], language="json" if r["file_name"].endswith(".json") else "yaml")
                with col_exp3:
                    st.markdown("**Anomaly Severity Matrix:**")
                    st.markdown(f'<span class="badge {badge_class}">{sev.upper()} RISK</span>', unsafe_allow_html=True)
                    st.markdown(f"**Drift Classification:** {r['drift_type']}")
                    st.markdown(f"**AI Risk Rating:** `{r.get('risk_rating', sev)}`")
                    
                st.markdown("---")
                
                # AI Report Blocks
                st.markdown("#### 🧠 AI Compliance Auditing")
                
                tab_tech, tab_biz, tab_sec, tab_fix = st.tabs([
                    "💻 Technical Impact", 
                    "💼 Business Impact", 
                    "🔒 Security Vulnerabilities", 
                    "🛠️ Recommended Fix Playbook"
                ])
                
                with tab_tech:
                    st.write(r.get("technical_impact", "Analyzing..."))
                with tab_biz:
                    st.write(r.get("business_impact", "Analyzing..."))
                with tab_sec:
                    st.write(r.get("security_impact", "Analyzing..."))
                with tab_fix:
                    st.markdown(r.get("recommendation", "Revert to the expected config value.").replace("\n", "\n\n"))

# ----------------- PAGE 2: ANALYTICS DASHBOARD -----------------
elif st.session_state["selected_page"] == "📊 Analytics Dashboard":
    st.title("📊 Cloud Infrastructure Analytics")
    st.write("Aggregated visual intelligence of configurations audits, threat severity groups, and recurring drifts.")
    
    metrics = get_analytics_metrics(DB_PATH, st.session_state["user_id"])
    
    if metrics["total_drifts"] == 0:
        st.info("No scan records detected in the database. Perform a configuration comparison to populate analytics.")
    else:
        # KPI Cards
        col_a1, col_a2, col_a3, col_a4 = st.columns(4)
        with col_a1:
            st.markdown(f'<div class="metric-card"><div class="metric-val">{metrics["total_files_checked"]}</div><div class="metric-lbl">Total Files Audited</div></div>', unsafe_allow_html=True)
        with col_a2:
            st.markdown(f'<div class="metric-card"><div class="metric-val">{metrics["total_drifts"]}</div><div class="metric-lbl">Anomalies Detected</div></div>', unsafe_allow_html=True)
        with col_a3:
            st.markdown(f'<div class="metric-card"><div class="metric-val" style="color: #EF4444;">{metrics["critical_drifts"]}</div><div class="metric-lbl">Critical Risks</div></div>', unsafe_allow_html=True)
        with col_a4:
            st.markdown(f'<div class="metric-card"><div class="metric-val" style="color: #F97316;">{metrics["high_drifts"]}</div><div class="metric-lbl">High Risks</div></div>', unsafe_allow_html=True)
            
        st.markdown(f"<p style='text-align: right; color: #64748B; font-size: 0.8rem;'>Last Scan Event: {metrics['last_scan_time']}</p>", unsafe_allow_html=True)
        st.markdown("---")
        
        # Charts Grid
        col_c1, col_c2 = st.columns(2)
        
        with col_c1:
            st.subheader("Severity Level Distribution")
            sev_data = metrics["severity_dist"]
            df_sev = pd.DataFrame(list(sev_data.items()), columns=["Severity", "Count"])
            
            fig_pie = px.pie(
                df_sev, 
                values="Count", 
                names="Severity",
                color="Severity",
                color_discrete_map={k: get_severity_color(k) for k in sev_data.keys()},
                hole=0.4
            )
            fig_pie.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font_color="#F8FAFC"
            )
            st.plotly_chart(fig_pie, use_container_width=True)
            
        with col_c2:
            st.subheader("Drift Type Distribution")
            dt_data = metrics["drift_type_dist"]
            df_dt = pd.DataFrame(list(dt_data.items()), columns=["Drift Type", "Count"])
            fig_dt = px.bar(
                df_dt, 
                x="Drift Type", 
                y="Count",
                color="Drift Type",
                color_discrete_sequence=px.colors.qualitative.Pastel
            )
            fig_dt.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font_color="#F8FAFC",
                showlegend=False
            )
            st.plotly_chart(fig_dt, use_container_width=True)
            
        col_c3, col_c4 = st.columns(2)
        
        with col_c3:
            st.subheader("Drift Anomalies Trend Over Time")
            trends = metrics["drift_trends"]
            if trends:
                df_trends = pd.DataFrame(trends, columns=["Timestamp", "Drift Count"])
                df_trends["Timestamp"] = pd.to_datetime(df_trends["Timestamp"])
                
                fig_line = px.line(
                    df_trends,
                    x="Timestamp",
                    y="Drift Count",
                    markers=True
                )
                fig_line.update_traces(line_color="#38BDF8", line_width=2)
                fig_line.update_layout(
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    font_color="#F8FAFC"
                )
                st.plotly_chart(fig_line, use_container_width=True)
            else:
                st.write("Insufficient historical data points to plot trend.")
                
        with col_c4:
            st.subheader("Top Vulnerable Configuration Files")
            top_files = metrics["top_files"]
            if top_files:
                df_top = pd.DataFrame(top_files, columns=["Config File", "Drift Count"])
                fig_top = px.bar(
                    df_top,
                    x="Drift Count",
                    y="Config File",
                    orientation="h",
                    color="Config File",
                    color_discrete_sequence=px.colors.qualitative.Safe
                )
                fig_top.update_layout(
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    font_color="#F8FAFC",
                    showlegend=False
                )
                st.plotly_chart(fig_top, use_container_width=True)
            else:
                st.write("No files recorded.")

# ----------------- PAGE 3: SCAN HISTORY & FILTER -----------------
elif st.session_state["selected_page"] == "📜 Scan History":
    st.title("📜 Scan History & Interactive Audit Logs")
    st.write("Access historical audits, execute targeted filters, and drill down into compliance reports.")
    
    # Database Controls
    if st.sidebar.button("🗑️ Clear My Scan History", type="secondary"):
        clear_all_history(DB_PATH, st.session_state["user_id"])
        st.session_state["scan_results"] = None
        st.success("Your scan history has been cleared successfully.")
        st.rerun()
        
    # Search and Filter Options in page body
    st.markdown("### 🔍 Search & Filters")
    col_f1, col_f2, col_f3, col_f4 = st.columns(4)
    with col_f1:
        filter_file = st.text_input("Config File Name contains", placeholder="e.g. app.yaml")
    with col_f2:
        filter_sev = st.selectbox("Filter by Severity", ["All", "Critical", "High", "Medium", "Low"])
    with col_f3:
        filter_type = st.selectbox("Filter by Drift Type", ["All", "Missing Key", "Added Key", "Modified Value", "Data Type Change"])
    with col_f4:
        start_date = st.date_input("Start Date", value=None)
        end_date = st.date_input("End Date", value=None)
        
    start_str = start_date.strftime("%Y-%m-%d") if start_date else None
    end_str = end_date.strftime("%Y-%m-%d") if end_date else None
    
    # Query database
    drifts_found = search_drifts(
        db_path=DB_PATH,
        file_name=filter_file,
        severity=filter_sev,
        drift_type=filter_type,
        start_date=start_str,
        end_date=end_str,
        user_id=st.session_state["user_id"]
    )
    
    if not drifts_found:
        st.info("No drifts matched your search filters.")
    else:
        st.markdown(f"**Found `{len(drifts_found)}` matching records.**")
        
        # Display as a dataframe for fast summary
        summary_rows = []
        for d in drifts_found:
            summary_rows.append({
                "ID": d["drift_id"],
                "Timestamp": d["timestamp"],
                "File Name": d["file_name"],
                "Config Path": d["config_path"],
                "Drift Type": d["drift_type"],
                "Severity": d["severity"],
                "Risk Rating": d.get("risk_rating") or "N/A"
            })
        df_summary = pd.DataFrame(summary_rows)
        st.dataframe(df_summary, use_container_width=True, hide_index=True)
        
        st.markdown("---")
        st.subheader("Detailed Anomaly Inspector")
        
        selected_id = st.selectbox(
            "Select Drift Anomaly ID for Detailed Assessment & AI Remediation Guide", 
            df_summary["ID"].tolist(),
            format_func=lambda x: f"ID: {x} | {df_summary[df_summary['ID'] == x]['File Name'].values[0]} ➔ {df_summary[df_summary['ID'] == x]['Config Path'].values[0]}"
        )
        
        if selected_id:
            # Find the selected record
            selected_record = next(d for d in drifts_found if d["drift_id"] == selected_id)
            sev = selected_record["severity"]
            badge_class = f"badge-{sev.lower()}"
            
            col_d1, col_d2 = st.columns([1, 1])
            with col_d1:
                st.markdown(f"##### Anomaly Context")
                st.markdown(f"**File Name:** `{selected_record['file_name']}`")
                st.markdown(f"**Path Location:** `{selected_record['config_path']}`")
                st.markdown(f"**Timestamp:** `{selected_record['timestamp']}`")
                st.markdown(f"**Drift Classification:** {selected_record['drift_type']}")
                st.markdown(f'**Severity Matrix:** <span class="badge {badge_class}">{sev.upper()}</span>', unsafe_allow_html=True)
                
            with col_d2:
                st.markdown("##### Configuration State Diff")
                col_d_int, col_d_act = st.columns(2)
                with col_d_int:
                    st.markdown("**Expected (Golden):**")
                    st.code(selected_record["intended_value"])
                with col_d_act:
                    st.markdown("**Deployed (Live):**")
                    st.code(selected_record["actual_value"])
                    
            st.markdown("---")
            st.markdown("##### 🧠 Associated AI Risk Analysis Report")
            col_ai1, col_ai2 = st.columns([2, 1])
            with col_ai1:
                st.markdown(f"**Technical System Impact:**\n{selected_record['technical_impact']}")
                st.markdown(f"**Business SLA & Cost Impact:**\n{selected_record['business_impact']}")
                st.markdown(f"**Security & Data Threat Profile:**\n{selected_record['security_impact']}")
            with col_ai2:
                st.markdown(f"**AI Risk rating:** `{selected_record['risk_rating'] or sev}`")
                st.markdown("**Fix Playbook Instructions:**")
                st.write(selected_record["recommendation"])

# ----------------- PAGE 4: PROFILE MANAGEMENT -----------------
elif st.session_state["selected_page"] == "👤 Profile":
    st.title("👤 Profile & Notification Settings")
    st.write("Manage your personal profile, notification preferences, and password security.")

    user = get_user_profile(DB_PATH, st.session_state["user_id"])
    if not user:
        st.error("Unable to load your profile. Please log in again.")
        if st.button("Return to Login"):
            for key in ["logged_in", "user_id", "user_email", "user_name", "selected_page", "scan_results"]:
                if key in st.session_state:
                    del st.session_state[key]
            st.rerun()
    else:
        name = st.text_input("Name", value=user.get("name") or "", key="profile_name")
        st.text_input("Email", value=user.get("email") or "", disabled=True)
        notify_enabled = st.checkbox("Enable email alerts", value=bool(user.get("notify_enabled", 1)))

        st.markdown("---")
        st.subheader("Change Password")
        old_password = st.text_input("Old password", type="password", key="profile_old_password")
        new_password = st.text_input("New password", type="password", key="profile_new_password")
        confirm_password = st.text_input("Confirm new password", type="password", key="profile_confirm_password")

        save_changed = st.button("Save Changes", type="primary")
        if save_changed:
            if not name:
                st.error("Your name cannot be blank.")
            else:
                profile_saved = save_user_profile(DB_PATH, st.session_state["user_id"], name, notify_enabled)
                if profile_saved:
                    st.success("Profile settings updated successfully.")
                    st.session_state["user_name"] = name
                else:
                    st.warning("No changes were applied to your profile.")

                if old_password or new_password or confirm_password:
                    if not (old_password and new_password and confirm_password):
                        st.error("Fill in all password fields to change your password.")
                    elif new_password != confirm_password:
                        st.error("New password and confirmation do not match.")
                    else:
                        authenticated = authenticate_user(DB_PATH, user["email"], old_password)
                        if not authenticated:
                            st.error("Old password is incorrect.")
                        else:
                            updated = change_user_password(DB_PATH, st.session_state["user_id"], hash_password(new_password))
                            if updated:
                                st.success("Password changed successfully.")
                                st.rerun()
                            else:
                                st.error("Unable to update the password. Try again.")

# ----------------- PAGE 5: REPORT EXPORT -----------------
elif st.session_state["selected_page"] == "📄 Export Reports":
    st.title("📄 PDF Compliance Report Compiler")
    st.write("Compile and download print-ready executive reports containing all matched anomalies, statistics, and AI recommendations.")
    
    scans = get_scan_history_summary(DB_PATH, st.session_state["user_id"])
    
    if not scans:
        st.info("No scan histories available to compile. Run a configuration compare scan first.")
    else:
        st.subheader("Select Audit Scan Event to Compile")
        
        scan_options = [s["timestamp"] for s in scans]
        selected_scan_time = st.selectbox(
            "Select Scan Timestamp",
            scan_options,
            format_func=lambda x: f"Scan run at {x} (Anomalies: {next(s['total_drifts'] for s in scans if s['timestamp'] == x)} issues, Files: {next(s['files_count'] for s in scans if s['timestamp'] == x)})"
        )
        
        if selected_scan_time:
            # Load all drifts and AI records for this timestamp
            drifts_for_pdf = get_drill_down_drifts(DB_PATH, selected_scan_time, user_id=st.session_state["user_id"])
            
            st.success(f"Loaded {len(drifts_for_pdf)} drift records for reporting.")
            
            # Show a brief summary preview
            st.markdown("### Report Summary Preview")
            df_preview = pd.DataFrame([
                {
                    "File": d["file_name"],
                    "Path": d["config_path"],
                    "Drift Type": d["drift_type"],
                    "Severity": d["severity"],
                    "Risk Rating": d.get("risk_rating") or "N/A"
                } for d in drifts_for_pdf
            ])
            st.dataframe(df_preview, use_container_width=True, hide_index=True)
            
            # Create a target file path inside local workspace temp folder
            tmp_pdf_dir = os.path.join(os.path.abspath(os.path.dirname(__file__)), "reports")
            os.makedirs(tmp_pdf_dir, exist_ok=True)
            
            pdf_filename = f"Config_Drift_Report_{selected_scan_time.replace(':', '-').replace(' ', '_')}.pdf"
            pdf_path = os.path.join(tmp_pdf_dir, pdf_filename)
            
            # Compile PDF Button
            if st.button("🖨️ Compile and Export PDF Report", type="primary"):
                with st.spinner("Compiling PDF flowables and building NumberedCanvas..."):
                    try:
                        generate_pdf_report(drifts_for_pdf, pdf_path)
                        st.success(f"PDF successfully compiled and generated!")
                        
                        with open(pdf_path, "rb") as f:
                            pdf_data = f.read()
                            
                        st.download_button(
                            label="📥 Download PDF Report",
                            data=pdf_data,
                            file_name=pdf_filename,
                            mime="application/pdf",
                            use_container_width=True
                        )
                    except Exception as e:
                        st.error(f"Error compiling PDF: {str(e)}")
