"""Multi-workspace migration checks."""
from __future__ import annotations

from .base import MigrationRule
from ..models import Finding, Severity, WorkspaceConfig

_BASE_DOC = "https://learn.microsoft.com/azure/sentinel/move-to-defender"


class WorkspaceManagerCheck(MigrationRule):
    id = "multi-workspace-manager"
    title = "Workspace manager not available in Defender XDR"
    category = "Multi-Workspace"
    doc_url = f"{_BASE_DOC}#multi-workspace"

    def evaluate(self, config: WorkspaceConfig) -> list[Finding]:
        if not config.workspace_manager_enabled:
            return []
        return [Finding(
            id=self.id,
            title=self.title,
            category=self.category,
            severity=Severity.CRITICAL,
            description=(
                "Workspace Manager is enabled on this workspace. "
                "This feature is not available in Defender XDR. "
                "Multi-workspace management must be handled through "
                "alternative methods."
            ),
            impact=(
                "Centralized content distribution and workspace "
                "management via Workspace Manager will stop working "
                "after onboarding."
            ),
            remediation=(
                "1. Document all content managed via Workspace Manager.\n"
                "2. Plan alternative distribution methods (e.g., "
                "CI/CD pipelines, Azure Lighthouse, or manual "
                "deployment).\n"
                "3. Migrate content distribution before onboarding.\n"
                "4. Verify all managed workspaces receive content "
                "through the new method."
            ),
            doc_url=self.doc_url,
            affected_resources=["Workspace Manager"],
        )]
