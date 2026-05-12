"""Incident handling migration checks."""
from __future__ import annotations

from .base import MigrationRule
from ..models import Finding, Severity, WorkspaceConfig

_BASE_DOC = "https://learn.microsoft.com/azure/sentinel/move-to-defender"


class ProgrammaticIncidentsCheck(MigrationRule):
    id = "incidents-programmatic"
    title = "Programmatic incident creation may be affected"
    category = "Incidents"
    doc_url = f"{_BASE_DOC}#incidents"

    def evaluate(self, config: WorkspaceConfig) -> list[Finding]:
        has_automation = any(r.enabled for r in config.automation_rules)
        if not has_automation:
            return []
        return [Finding(
            id=self.id,
            title=self.title,
            category=self.category,
            severity=Severity.INFO,
            description=(
                "If any external tools or scripts create incidents "
                "programmatically via the SecurityIncident table or API, "
                "those workflows may need updates after onboarding to "
                "Defender XDR."
            ),
            impact=(
                "Programmatically created incidents may not appear in the "
                "Defender XDR unified queue unless created through the "
                "supported API."
            ),
            remediation=(
                "1. Inventory any scripts or SOAR integrations that "
                "create incidents via the Sentinel API.\n"
                "2. Update them to use the Defender XDR incidents API "
                "after onboarding.\n"
                "3. Test incident creation end-to-end."
            ),
            doc_url=self.doc_url,
        )]


class CommentEditingCheck(MigrationRule):
    id = "incidents-comment-editing"
    title = "Incident comment editing not supported"
    category = "Incidents"
    doc_url = f"{_BASE_DOC}#incidents"

    def evaluate(self, config: WorkspaceConfig) -> list[Finding]:
        return [Finding(
            id=self.id,
            title=self.title,
            category=self.category,
            severity=Severity.INFO,
            description=(
                "In Defender XDR, incident comments cannot be edited "
                "or deleted after submission. This differs from Sentinel, "
                "where comments can be modified."
            ),
            impact=(
                "SOC analysts will need to be more deliberate when adding "
                "comments, as corrections require adding a new comment."
            ),
            remediation=(
                "1. Inform SOC analysts of the comment behavior change.\n"
                "2. Update any SOC documentation or runbooks that mention "
                "editing comments.\n"
                "3. No technical action required."
            ),
            doc_url=self.doc_url,
        )]
