"""Data storage & encryption migration checks."""
from __future__ import annotations

from .base import MigrationRule
from ..models import Finding, Severity, WorkspaceConfig

_BASE_DOC = "https://learn.microsoft.com/azure/sentinel/move-to-defender"


class CMKEncryptionCheck(MigrationRule):
    id = "data-cmk-encryption"
    title = "Customer-managed key (CMK) encryption enabled"
    category = "Data Storage"
    doc_url = f"{_BASE_DOC}#data-storage"

    def evaluate(self, config: WorkspaceConfig) -> list[Finding]:
        if not config.cmk_enabled:
            return []
        return [Finding(
            id=self.id,
            title=self.title,
            category=self.category,
            severity=Severity.WARNING,
            description=(
                "This workspace has Customer-Managed Key (CMK) encryption "
                "enabled. After onboarding to Defender XDR, alerts and "
                "incidents stored in the Defender platform will no longer "
                "be encrypted with your CMK."
            ),
            impact=(
                "Alerts and incidents in the Defender XDR data store "
                "will use Microsoft-managed encryption instead of your "
                "CMK. Log data in Log Analytics remains CMK-encrypted."
            ),
            remediation=(
                "1. Confirm with your security/compliance team that "
                "Microsoft-managed encryption for Defender XDR data is "
                "acceptable.\n"
                "2. If CMK is a hard requirement for all data, evaluate "
                "whether onboarding is appropriate at this time.\n"
                "3. Document the encryption scope change."
            ),
            doc_url=self.doc_url,
            affected_resources=["CMK-enabled workspace"],
        )]


class DataResidencyCheck(MigrationRule):
    id = "data-residency"
    title = "Data residency policy change"
    category = "Data Storage"
    doc_url = f"{_BASE_DOC}#data-storage"

    def evaluate(self, config: WorkspaceConfig) -> list[Finding]:
        return [Finding(
            id=self.id,
            title=self.title,
            category=self.category,
            severity=Severity.INFO,
            description=(
                "After onboarding, data residency for alerts and incidents "
                "is governed by Defender XDR regional policies instead of "
                "the Log Analytics workspace location."
            ),
            impact=(
                "Alert and incident data may be stored in a different "
                "geographic region than your Log Analytics workspace. "
                "Raw log data remains in the workspace region."
            ),
            remediation=(
                "1. Review Defender XDR data residency documentation.\n"
                "2. Verify that Defender XDR's region meets your "
                "compliance requirements.\n"
                "3. Inform your compliance team of the change."
            ),
            doc_url=self.doc_url,
        )]
