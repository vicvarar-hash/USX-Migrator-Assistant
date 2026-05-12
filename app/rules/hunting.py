"""Advanced hunting migration checks."""
from __future__ import annotations

from .base import MigrationRule
from ..models import Finding, Severity, WorkspaceConfig

_BASE_DOC = "https://learn.microsoft.com/azure/sentinel/move-to-defender"


class BookmarksCheck(MigrationRule):
    id = "hunting-bookmarks"
    title = "Hunting bookmarks relocate after onboarding"
    category = "Advanced Hunting"
    doc_url = f"{_BASE_DOC}#hunting"

    def evaluate(self, config: WorkspaceConfig) -> list[Finding]:
        return [Finding(
            id=self.id,
            title=self.title,
            category=self.category,
            severity=Severity.INFO,
            description=(
                "Sentinel hunting bookmarks will move to a different "
                "location in the Defender XDR portal. Existing bookmarks "
                "are preserved but accessed through a different UI path."
            ),
            impact=(
                "SOC analysts and threat hunters will need to learn the "
                "new bookmark location in the Defender XDR interface."
            ),
            remediation=(
                "1. Document current bookmark usage patterns.\n"
                "2. After onboarding, locate bookmarks in the Defender "
                "XDR advanced hunting section.\n"
                "3. Update analyst training materials."
            ),
            doc_url=self.doc_url,
        )]


class IdentityInfoCheck(MigrationRule):
    id = "hunting-identityinfo"
    title = "IdentityInfo table schema changes"
    category = "Advanced Hunting"
    doc_url = f"{_BASE_DOC}#hunting"

    def evaluate(self, config: WorkspaceConfig) -> list[Finding]:
        return [Finding(
            id=self.id,
            title=self.title,
            category=self.category,
            severity=Severity.WARNING,
            description=(
                "The IdentityInfo table in advanced hunting has different "
                "field names and schema in Defender XDR compared to "
                "Sentinel. Queries referencing IdentityInfo fields may "
                "break."
            ),
            impact=(
                "Custom hunting queries, workbooks, and analytics rules "
                "that reference IdentityInfo fields will need to be "
                "updated to match the new schema."
            ),
            remediation=(
                "1. Inventory all queries using the IdentityInfo table.\n"
                "2. Review the Defender XDR IdentityInfo schema for "
                "field name changes.\n"
                "3. Update queries to use the new field names.\n"
                "4. Test updated queries before relying on them."
            ),
            doc_url=self.doc_url,
        )]


class SimilarIncidentsCheck(MigrationRule):
    id = "hunting-similar-incidents"
    title = "Similar incidents feature not available"
    category = "Advanced Hunting"
    doc_url = f"{_BASE_DOC}#hunting"

    def evaluate(self, config: WorkspaceConfig) -> list[Finding]:
        return [Finding(
            id=self.id,
            title=self.title,
            category=self.category,
            severity=Severity.INFO,
            description=(
                "The 'Similar incidents' feature in Sentinel is not "
                "available in the Defender XDR portal. Analysts will "
                "need alternative methods to find related incidents."
            ),
            impact=(
                "Analysts who rely on similar-incident suggestions for "
                "triage will need to use advanced hunting or manual "
                "search to find related cases."
            ),
            remediation=(
                "1. Train analysts on using advanced hunting queries "
                "to find related incidents.\n"
                "2. Consider creating saved queries for common "
                "correlation patterns.\n"
                "3. No technical action required."
            ),
            doc_url=self.doc_url,
        )]
