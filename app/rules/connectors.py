"""Data connector migration checks."""
from __future__ import annotations

from .base import MigrationRule
from ..models import Finding, Severity, WorkspaceConfig

_BASE_DOC = "https://learn.microsoft.com/azure/sentinel/move-to-defender"

_TENANT_DFC_KINDS = {"AzureSecurityCenter"}
_SUB_DFC_KINDS = {"ASC"}  # subscription-based variant
_HIDDEN_KINDS = {
    "MicrosoftDefenderAdvancedThreatProtection": "Microsoft Defender for Endpoint (MDE)",
    "AzureAdvancedThreatProtection": "Microsoft Defender for Identity (MDI)",
    "Office365": "Microsoft Defender for Office 365 (MDO)",
    "MicrosoftCloudAppSecurity": "Microsoft Defender for Cloud Apps (MCAS)",
    "MicrosoftThreatProtection": "Microsoft 365 Defender (XDR)",
}


class TenantDefenderForCloudCheck(MigrationRule):
    id = "connector-dfc-tenant"
    title = "Tenant-based Defender for Cloud connector"
    category = "Data Connectors"
    doc_url = f"{_BASE_DOC}#data-connectors"

    def evaluate(self, config: WorkspaceConfig) -> list[Finding]:
        affected = [
            c.name for c in config.data_connectors
            if c.connected and c.kind in _TENANT_DFC_KINDS
        ]
        if not affected:
            return []
        return [Finding(
            id=self.id,
            title=self.title,
            category=self.category,
            severity=Severity.WARNING,
            description=(
                "A tenant-based Defender for Cloud connector is present. "
                "After onboarding, this may cause duplicate security "
                "alerts because Defender XDR natively ingests DfC alerts."
            ),
            impact=(
                "Duplicate alerts may appear in the incident queue, "
                "increasing noise for SOC analysts."
            ),
            remediation=(
                "1. After onboarding, verify whether alerts are "
                "duplicated.\n"
                "2. If duplicates occur, switch to subscription-based "
                "DfC connectors and exclude the synced subscriptions, or "
                "disable the tenant-based connector.\n"
                "3. Monitor alert volume in the first week."
            ),
            doc_url=self.doc_url,
            affected_resources=affected,
        )]


class SubscriptionDefenderForCloudCheck(MigrationRule):
    id = "connector-dfc-subscription"
    title = "Subscription-based Defender for Cloud connector"
    category = "Data Connectors"
    doc_url = f"{_BASE_DOC}#data-connectors"

    def evaluate(self, config: WorkspaceConfig) -> list[Finding]:
        affected = [
            c.name for c in config.data_connectors
            if c.connected and c.kind in _SUB_DFC_KINDS
        ]
        if not affected:
            return []
        return [Finding(
            id=self.id,
            title=self.title,
            category=self.category,
            severity=Severity.WARNING,
            description=(
                f"{len(affected)} subscription-based Defender for Cloud "
                "connector(s) found. You must opt out of bi-directional "
                "sync for each subscription to avoid duplicate incidents."
            ),
            impact=(
                "Without opting out, DfC incidents will appear in both "
                "Sentinel and the DfC portal, causing confusion."
            ),
            remediation=(
                "1. For each subscription connector, disable "
                "bi-directional sync in the connector settings.\n"
                "2. Verify that alerts are only created once after "
                "onboarding.\n"
                "3. Document which subscriptions remain connected."
            ),
            doc_url=self.doc_url,
            affected_resources=affected,
        )]


class HiddenConnectorsCheck(MigrationRule):
    id = "connector-hidden-defender"
    title = "Defender connectors hidden after onboarding"
    category = "Data Connectors"
    doc_url = f"{_BASE_DOC}#data-connectors"

    def evaluate(self, config: WorkspaceConfig) -> list[Finding]:
        affected = []
        for c in config.data_connectors:
            if c.connected and c.kind in _HIDDEN_KINDS:
                label = _HIDDEN_KINDS[c.kind]
                affected.append(f"{c.name} ({label})")
        if not affected:
            return []
        return [Finding(
            id=self.id,
            title=self.title,
            category=self.category,
            severity=Severity.INFO,
            description=(
                f"{len(affected)} Defender connector(s) will be hidden "
                "from the Sentinel data-connectors UI after onboarding. "
                "They remain active — data continues to flow — but you "
                "cannot manage them from the connectors page."
            ),
            impact=(
                f"Connectors affected: {', '.join(affected)}. No data "
                "loss; management moves to Defender XDR settings."
            ),
            remediation=(
                "1. No immediate action required.\n"
                "2. Use the Defender XDR portal to manage these "
                "connectors after onboarding.\n"
                "3. Update runbooks that reference the Sentinel "
                "connector page."
            ),
            doc_url=self.doc_url,
            affected_resources=affected,
        )]
