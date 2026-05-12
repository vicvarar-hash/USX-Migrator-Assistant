"""Data models for the USX Migrator Assistant."""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Severity & Finding
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"
    OK = "ok"

    @property
    def label(self) -> str:
        return {
            "critical": "🔴 Critical",
            "warning": "⚠️ Warning",
            "info": "ℹ️ Info",
            "ok": "✅ OK",
        }[self.value]

    @property
    def sort_order(self) -> int:
        return {"critical": 0, "warning": 1, "info": 2, "ok": 3}[self.value]


@dataclass
class Finding:
    """A single migration assessment finding."""
    id: str
    title: str
    category: str
    severity: Severity
    description: str
    impact: str
    remediation: str
    az_command: Optional[str] = None
    doc_url: Optional[str] = None
    affected_resources: list[str] = field(default_factory=list)
    addressed: bool = False

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        d["severity"] = Severity(d["severity"])
        return cls(**d)


# ---------------------------------------------------------------------------
# Workspace & Discovery data
# ---------------------------------------------------------------------------

@dataclass
class SentinelWorkspace:
    """Represents a Sentinel-enabled Log Analytics workspace."""
    subscription_id: str
    subscription_name: str
    resource_group: str
    workspace_name: str
    workspace_id: str
    location: str


@dataclass
class AutomationRuleInfo:
    """Key properties of a Sentinel automation rule."""
    name: str
    display_name: str
    trigger_type: str  # "incident" | "alert"
    conditions: list[dict] = field(default_factory=list)
    actions: list[dict] = field(default_factory=list)
    enabled: bool = True


@dataclass
class AnalyticsRuleInfo:
    """Key properties of a Sentinel analytics rule."""
    name: str
    display_name: str
    kind: str  # Scheduled, Fusion, MicrosoftSecurityIncidentCreation, NRT, etc.
    enabled: bool = True
    incident_creation_enabled: bool = True
    alert_grouping_reopen_closed: bool = False
    alert_grouping_enabled: bool = False


@dataclass
class DataConnectorInfo:
    """Key properties of a Sentinel data connector."""
    name: str
    kind: str
    connected: bool = True


@dataclass
class PlaybookInfo:
    """Key properties of a Logic App playbook."""
    name: str
    resource_group: str
    trigger_type: str  # "alert" | "incident" | "entity" | "unknown"
    enabled: bool = True


@dataclass
class RBACAssignment:
    """An Azure role assignment."""
    principal_id: str
    principal_type: str
    role_name: str
    role_id: str
    scope: str


@dataclass
class WorkspaceConfig:
    """Aggregated workspace configuration for assessment."""
    workspace: SentinelWorkspace
    automation_rules: list[AutomationRuleInfo] = field(default_factory=list)
    analytics_rules: list[AnalyticsRuleInfo] = field(default_factory=list)
    data_connectors: list[DataConnectorInfo] = field(default_factory=list)
    playbooks: list[PlaybookInfo] = field(default_factory=list)
    rbac_assignments: list[RBACAssignment] = field(default_factory=list)
    cmk_enabled: bool = False
    workspace_manager_enabled: bool = False
    # Tracks which discovery steps failed
    discovery_errors: dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Assessment result (for history)
# ---------------------------------------------------------------------------

@dataclass
class AssessmentResult:
    """Full result of one assessment run."""
    workspace_name: str
    subscription_id: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    findings: list[Finding] = field(default_factory=list)
    discovery_errors: dict[str, str] = field(default_factory=dict)
    checklist: dict[str, bool] = field(default_factory=dict)

    # Computed properties
    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def warning_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.WARNING)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.INFO)

    @property
    def ok_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.OK)

    @property
    def readiness_score(self) -> int:
        """0-100 score. OK items are compatible; others are not."""
        total = len(self.findings)
        if total == 0:
            return 100
        compatible = self.ok_count
        return int(compatible / total * 100)

    def to_dict(self) -> dict:
        return {
            "workspace_name": self.workspace_name,
            "subscription_id": self.subscription_id,
            "timestamp": self.timestamp,
            "findings": [f.to_dict() for f in self.findings],
            "discovery_errors": self.discovery_errors,
            "checklist": self.checklist,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "AssessmentResult":
        return cls(
            workspace_name=d["workspace_name"],
            subscription_id=d["subscription_id"],
            timestamp=d["timestamp"],
            findings=[Finding.from_dict(f) for f in d.get("findings", [])],
            discovery_errors=d.get("discovery_errors", {}),
            checklist=d.get("checklist", {}),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_json(cls, raw: str) -> "AssessmentResult":
        return cls.from_dict(json.loads(raw))
