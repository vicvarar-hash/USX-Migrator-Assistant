"""Migration rules engine — registry and runner."""
from __future__ import annotations

from ..models import Finding, WorkspaceConfig
from .base import MigrationRule

from .automation import (
    AutomationAlertTriggerRule,
    AutomationIncidentProviderRule,
    AutomationDescriptionFieldRule,
    AutomationIncidentTitleRule,
    AutomationUpdatedByRule,
    IncidentCreationRule,
    PlaybookManualRunRule,
    PlaybookLatencyRule,
)
from .analytics import (
    FusionRuleCheck,
    AlertOnlyRuleCheck,
    AlertGroupingReopenCheck,
)
from .connectors import (
    TenantDefenderForCloudCheck,
    SubscriptionDefenderForCloudCheck,
    HiddenConnectorsCheck,
)
from .data_storage import CMKEncryptionCheck, DataResidencyCheck
from .incidents import ProgrammaticIncidentsCheck, CommentEditingCheck
from .rbac import URBACMappingCheck
from .hunting import BookmarksCheck, IdentityInfoCheck, SimilarIncidentsCheck
from .multi_workspace import WorkspaceManagerCheck


def get_all_rules() -> list[MigrationRule]:
    """Return instances of every registered migration rule."""
    return [
        # Automation & playbooks
        AutomationAlertTriggerRule(),
        AutomationIncidentProviderRule(),
        AutomationDescriptionFieldRule(),
        AutomationIncidentTitleRule(),
        AutomationUpdatedByRule(),
        IncidentCreationRule(),
        PlaybookManualRunRule(),
        PlaybookLatencyRule(),
        # Analytics
        FusionRuleCheck(),
        AlertOnlyRuleCheck(),
        AlertGroupingReopenCheck(),
        # Connectors
        TenantDefenderForCloudCheck(),
        SubscriptionDefenderForCloudCheck(),
        HiddenConnectorsCheck(),
        # Data storage
        CMKEncryptionCheck(),
        DataResidencyCheck(),
        # Incidents
        ProgrammaticIncidentsCheck(),
        CommentEditingCheck(),
        # RBAC
        URBACMappingCheck(),
        # Hunting
        BookmarksCheck(),
        IdentityInfoCheck(),
        SimilarIncidentsCheck(),
        # Multi-workspace
        WorkspaceManagerCheck(),
    ]


def run_assessment(config: WorkspaceConfig) -> list[Finding]:
    """Run all rules against *config* and return findings sorted by severity."""
    findings: list[Finding] = []
    for rule in get_all_rules():
        findings.extend(rule.evaluate(config))
    findings.sort(key=lambda f: f.severity.sort_order)
    return findings
