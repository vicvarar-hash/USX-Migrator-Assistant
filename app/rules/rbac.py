"""RBAC migration checks."""
from __future__ import annotations

from .base import MigrationRule
from ..models import Finding, Severity, WorkspaceConfig

_BASE_DOC = "https://learn.microsoft.com/azure/sentinel/move-to-defender"


class URBACMappingCheck(MigrationRule):
    id = "rbac-urbac-mapping"
    title = "RBAC to Unified RBAC (URBAC) mapping required"
    category = "RBAC"
    doc_url = f"{_BASE_DOC}#rbac"

    def evaluate(self, config: WorkspaceConfig) -> list[Finding]:
        unique_roles = sorted({a.role_name for a in config.rbac_assignments})
        return [Finding(
            id=self.id,
            title=self.title,
            category=self.category,
            severity=Severity.WARNING,
            description=(
                "Existing Azure RBAC role assignments must be mapped to "
                "Defender XDR Unified RBAC (URBAC) roles after onboarding. "
                f"{len(unique_roles)} unique role(s) found in current "
                "assignments."
            ),
            impact=(
                "Until URBAC roles are configured, users may lose access "
                "to Sentinel features in the Defender XDR portal. "
                f"Roles to map: {', '.join(unique_roles) if unique_roles else 'none discovered'}."
            ),
            remediation=(
                "1. Review the URBAC role mapping documentation.\n"
                "2. Create equivalent URBAC roles for each Azure RBAC "
                "role currently in use.\n"
                "3. Assign users to the new URBAC roles before or "
                "immediately after onboarding.\n"
                "4. Test access with a pilot group first."
            ),
            doc_url=self.doc_url,
            affected_resources=unique_roles,
        )]
