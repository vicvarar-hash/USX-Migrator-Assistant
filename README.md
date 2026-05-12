# USX Migrator Assistant

A local web application that helps customers migrate their Microsoft Sentinel environment from the Azure Portal to the Microsoft Defender (USX) portal.

The app auto-discovers your current Sentinel configuration via Azure CLI, runs 23+ migration checks based on the [official MS Learn migration guide](https://learn.microsoft.com/azure/sentinel/move-to-defender), and generates a personalized assessment report with actionable `az` CLI remediation commands.

## Features

- **🔍 Auto-Discovery** — Reads your Sentinel workspace configuration directly from Azure (automation rules, analytics rules, data connectors, playbooks, RBAC, CMK settings)
- **📊 Personalized Assessment** — 23+ checks across 8 categories, unique to your setup
- **🔧 Three Remediation Modes:**
  - **Assess Only** — view/export the report
  - **Fix All** — download a complete shell script with all `az` CLI commands
  - **Fix One-by-One** — interactive wizard to address each finding
- **📜 Assessment History** — Compare current vs. previous runs to track progress
- **✅ Pre-Flight Checklist** — Manual/organizational steps that can't be auto-detected
- **⚡ Permission Checks** — Validates Azure permissions upfront and tells you exactly what roles you need

## Prerequisites

- **Python 3.11+**
- **Azure CLI** installed and authenticated (`az login`)
- **Azure permissions:**
  - `Reader` role on the subscription
  - `Microsoft Sentinel Reader` on the workspace

## Quick Start

```bash
# 1. Clone the repo
git clone https://github.com/vivargas_microsoft/Agency.git
cd "Agency/USX Migrator Assistant"

# 2. Create a virtual environment
python -m venv .venv
.venv\Scripts\activate  # Windows
# source .venv/bin/activate  # macOS/Linux

# 3. Install dependencies
pip install -r requirements.txt

# 4. Login to Azure
az login

# 5. Run the app
python run.py
```

Open **http://localhost:5000** in your browser.

## How It Works

### Step 1: Select Workspace
The app discovers all Sentinel-enabled workspaces across your subscriptions. Pick the one you want to assess.

### Step 2: Assessment Report
The app fetches your workspace configuration and checks it against 23+ known migration issues:

| Category | Checks |
|----------|--------|
| Automation Rules & Playbooks | Alert triggers, incident provider, description field, title conditions, updated-by, incident creation rules, manual playbook runs, latency |
| Analytics Rules | Fusion rule, alert-only rules, alert grouping |
| Data Connectors | Defender for Cloud (tenant/subscription), hidden connectors |
| Data Storage | CMK encryption, data residency |
| Incidents & Alerts | Programmatic incidents, comment editing |
| RBAC & Permissions | URBAC mapping |
| Advanced Hunting | Bookmarks, IdentityInfo table, similar incidents |
| Multi-Workspace | Workspace Manager |

Each finding includes:
- Severity (🔴 Critical / ⚠️ Warning / ℹ️ Info)
- Description and impact specific to your setup
- Step-by-step remediation
- Ready-to-run `az` CLI command
- Link to MS Learn documentation

### Step 3: Remediation
Choose how to fix:
- **📋 Assess Only** — Export as Markdown
- **🔧 Fix All** — Download a bash script with all commands
- **🔧 Fix One-by-One** — Walk through each finding interactively

> **Safe by design:** The app never auto-executes commands against Azure. It generates `az` CLI commands for you to review and run yourself.

## Migration Deadline

> **After March 31, 2027**, Microsoft Sentinel will no longer be supported in the Azure portal and will be available only in the Microsoft Defender portal.

## Project Structure

```
USX Migrator Assistant/
├── app/
│   ├── __init__.py              # Flask app factory
│   ├── routes.py                # Flask routes (3 steps)
│   ├── models.py                # Data models
│   ├── history.py               # Assessment history & comparison
│   ├── report.py                # Markdown report generation
│   ├── discovery/               # Azure config auto-discovery
│   │   ├── azure_auth.py        # Credential & permission checks
│   │   ├── subscriptions.py     # List subscriptions & workspaces
│   │   ├── automation_rules.py  # Fetch automation rules
│   │   ├── analytics_rules.py   # Fetch analytics rules
│   │   ├── connectors.py        # Fetch data connectors
│   │   ├── playbooks.py         # Fetch playbooks
│   │   ├── rbac.py              # Fetch RBAC assignments
│   │   └── workspace.py         # Fetch workspace settings
│   ├── rules/                   # Migration rules engine (23 rules)
│   │   ├── base.py              # Base rule class
│   │   ├── automation.py        # Automation & playbook checks
│   │   ├── analytics.py         # Analytics rule checks
│   │   ├── connectors.py        # Data connector checks
│   │   ├── data_storage.py      # CMK & data residency checks
│   │   ├── incidents.py         # Incident & alert checks
│   │   ├── rbac.py              # RBAC checks
│   │   ├── hunting.py           # Advanced hunting checks
│   │   └── multi_workspace.py   # Multi-workspace checks
│   ├── remediation/             # az CLI command generation
│   │   ├── command_generator.py # Per-finding command generation
│   │   └── script_builder.py    # Fix-all script builder
│   └── templates/               # Jinja2 HTML templates
├── static/                      # CSS & JS
├── tests/                       # Unit tests
├── requirements.txt
├── run.py                       # Entry point
└── README.md
```

## References

- [Transition your Microsoft Sentinel environment to the Defender portal](https://learn.microsoft.com/azure/sentinel/move-to-defender)
- [Microsoft Sentinel in the Microsoft Defender portal](https://learn.microsoft.com/azure/sentinel/microsoft-sentinel-defender-portal)
- [Planning your move to Microsoft Defender portal](https://techcommunity.microsoft.com/blog/microsoft-security-blog/planning-your-move-to-microsoft-defender-portal-for-all-microsoft-sentinel-custo/4428613)

## License

Internal use — Microsoft.
