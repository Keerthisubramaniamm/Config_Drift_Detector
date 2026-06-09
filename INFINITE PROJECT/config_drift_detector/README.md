# Config Drift Detector

An AI-powered DevOps and compliance platform to compare intended ("golden") configurations against live deployed environments, detect differences, classify threat severity, and perform AI impact assessments.

## 🚀 Features

*   **Intelligent Config Drift Engine:** Uses `DeepDiff` under the hood to recognize:
    *   *Missing Keys* (properties absent in deployment)
    *   *Added Keys* (unapproved live settings additions)
    *   *Modified Values* (parameter mismatches)
    *   *Data Type Changes* (e.g., parsing a port string instead of integer)
*   **DevOps Severity Matrix:** Automatically classifies risks into **Critical, High, Medium, or Low** severity based on configuration path keywords (e.g. `ssl`, `firewall`, `database`, `ui`).
*   **AI Impact Analysis:** Calls the **Groq API** (Llama 3.1) to generate:
    1.  *Technical System Impact*
    2.  *Business SLA Impact*
    3.  *Security & Threat Profile*
    4.  *Risk Rating*
    5.  *Recommended Step-by-Step Fix Playbook*
*   **Mock Fallback Mode:** Operates fully offline with zero setup! If no Groq API Key is configured in the environment, the app automatically generates high-quality simulated audits, so all dashboard and report workflows remain 100% testable out-of-the-box.
*   **Interactive Analytics Dashboard:** Aggregates database state using `Plotly` to display KPI cards, severity distribution pies, drift category bars, historical trend lines, and top vulnerable configurations.
*   **Interactive Audit History:** Browse past comparisons, query by filename or types, set calendar date ranges, and drill down into details.
*   **Compliance PDF Exporter:** Generates printable executive summaries with a custom two-pass footer page-numbering engine (`NumberedCanvas`), severity badges, and structured AI playbooks.

---

## 📁 Project Structure

```
config_drift_detector/
├── .streamlit/
│   └── config.toml        # Global theme configuration (dark DevOps visual scheme)
├── app.py                 # Streamlit frontend dashboard layout and navigation pages
├── drift_detector.py      # Core comparison engine using DeepDiff
├── ai_analysis.py         # Groq LLM integration and mock fallback templates
├── database.py            # SQLite schema initialization and query layers
├── report_generator.py    # ReportLab PDF compiler with header/footer page count logic
├── sample_data.py         # Utility tool to generate sample test configs locally
├── utils.py               # JSON/YAML parsers, path cleanups, and severity classifiers
├── database.db            # SQLite database file (auto-generated on startup)
├── requirements.txt       # Python libraries list
└── README.md              # Installation and user guide
```

---

## 🛠️ Installation & Setup

1.  **Clone or navigate** to the project workspace directory:
    ```bash
    cd config_drift_detector
    ```

2.  **Create and activate a Virtual Environment** (recommended):
    ```bash
    python -m venv venv
    
    # On Windows (PowerShell/CMD)
    .\venv\Scripts\activate
    
    # On Linux/MacOS
    source venv/bin/activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

---

## 🖥️ Running the Application

Launch the Streamlit web dashboard locally:

```bash
streamlit run app.py
```

Streamlit will print the local server URL (usually `http://localhost:8501`). Open this address in your web browser.

---

## 💡 How to Use

1.  Open the web interface in your browser.
2.  On the **🔍 Compare & Detect** page:
    *   Upload your intended golden configuration files to the **Golden Configuration** uploader.
    *   Upload your deployed live configuration files to the **Deployed Configuration** uploader.
    *   *(Filenames must match exactly to execute a comparison).*
3.  Click **🚀 Compare Configurations**.
4.  Once the progress bar finishes, you will see a high-level KPI card group, warning notices for any unmatched files, and collapsible details showing expected vs. actual code diffs, severity tags, and the AI impact report tabs.
5.  Navigate to **📊 Analytics Dashboard** to view the aggregated metrics charts.
6.  Check out **📜 Scan History** to see past scans, filter logs, and drill down.
7.  Go to **📄 Export Reports**, select your scan timestamp, and click **🖨️ Compile and Export PDF Report** to download the compliance PDF document.
