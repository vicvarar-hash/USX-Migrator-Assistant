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
The app fetches your workspace configuration and checks it against **23 known migration issues across 8 categories**:

#### 1. Automation Rules & Playbooks (8 checks)
| # | Check | Severity | What it detects |
|---|-------|----------|-----------------|
| 1 | Alert Trigger | 🔴 Critical | Automation rules using alert triggers — not supported in Defender |
| 2 | Incident Provider | 🔴 Critical | Rules with `IncidentProviderName` condition — not supported |
| 3 | Description Field | ⚠️ Warning | Rules using `Description` condition — maps differently in Defender |
| 4 | Incident Title | ⚠️ Warning | Rules using `Title` condition — behaves differently |
| 5 | Updated By | ⚠️ Warning | Rules using `UpdatedBy` condition — not supported |
| 6 | Incident Creation | 🔴 Critical | Rules with "incident creation" action — not available in Defender |
| 7 | Playbook Manual Run | ⚠️ Warning | Playbooks with manual triggers — need updated auth config |
| 8 | Playbook Latency | ℹ️ Info | Playbook execution latency — expect higher latency in Defender |

#### 2. Analytics Rules (3 checks)
| # | Check | Severity | What it detects |
|---|-------|----------|-----------------|
| 9 | Fusion Rules | ⚠️ Warning | Advanced multistage attack detection — changes in Defender |
| 10 | Alert-Only Rules | ⚠️ Warning | Rules without incident creation enabled — need review |
| 11 | Alert Grouping Reopen | 🔴 Critical | Alert grouping with "reopen on new alert" — not supported |

#### 3. Data Connectors (3 checks)
| # | Check | Severity | What it detects |
|---|-------|----------|-----------------|
| 12 | Tenant-level DfC | 🔴 Critical | Defender for Cloud connector at tenant level — must reconfigure |
| 13 | Subscription-level DfC | 🔴 Critical | Defender for Cloud connector per subscription — must reconfigure |
| 14 | Hidden Connectors | ℹ️ Info | Connectors that may be hidden in the Defender portal UI |

#### 4. Data Storage (2 checks)
| # | Check | Severity | What it detects |
|---|-------|----------|-----------------|
| 15 | CMK Encryption | ⚠️ Warning | Customer-managed keys — need verification post-migration |
| 16 | Data Residency | ℹ️ Info | Data residency compliance — verify after migration |

#### 5. Incidents & Alerts (2 checks)
| # | Check | Severity | What it detects |
|---|-------|----------|-----------------|
| 17 | Programmatic Incidents | 🔴 Critical | `SecurityIncident` table API usage — API changes in Defender |
| 18 | Comment Editing | ℹ️ Info | Incident comment editing — not available in Defender |

#### 6. RBAC & Permissions (1 check)
| # | Check | Severity | What it detects |
|---|-------|----------|-----------------|
| 19 | URBAC Mapping | 🔴 Critical | Sentinel RBAC roles — must map to Defender URBAC roles |

#### 7. Advanced Hunting (3 checks)
| # | Check | Severity | What it detects |
|---|-------|----------|-----------------|
| 20 | Bookmarks | ⚠️ Warning | Hunting bookmarks — not available in Defender portal |
| 21 | IdentityInfo Table | ⚠️ Warning | UEBA IdentityInfo table — behaves differently in Defender |
| 22 | Similar Incidents | ℹ️ Info | Similar incidents feature — not available in Defender |

#### 8. Multi-Workspace (1 check)
| # | Check | Severity | What it detects |
|---|-------|----------|-----------------|
| 23 | Workspace Manager | 🔴 Critical | Workspace Manager — not supported in Defender portal |

**Severity summary: 8 Critical · 8 Warning · 7 Info** (maximum if all issues detected — your report will only show findings relevant to your workspace)

Each finding includes:
- Severity level (🔴 Critical / ⚠️ Warning / ℹ️ Info)
- Description and impact specific to your setup
- Step-by-step remediation guidance
- Ready-to-run `az` CLI command
- Link to official MS Learn documentation

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
