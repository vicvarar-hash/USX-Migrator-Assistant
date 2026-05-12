"""Generate az CLI commands for individual findings."""
from __future__ import annotations

import logging
from typing import Optional

from ..models import Finding

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Command templates keyed by finding.id
# ---------------------------------------------------------------------------

_COMMAND_MAP: dict[str, Optional[str]] = {
    "automation-incident-provider": (
        'az sentinel automation-rule update'
        ' --subscription "{subscription_id}"'
        ' --resource-group "{resource_group}"'
        ' --workspace-name "{workspace_name}"'
        ' --automation-rule-name "{{rule_name}}"'
        ' --conditions "[]"'
        '  # Update conditions to remove IncidentProvider references'
    ),
    "automation-description-field": (
        'az sentinel automation-rule update'
        ' --subscription "{subscription_id}"'
        ' --resource-group "{resource_group}"'
        ' --workspace-name "{workspace_name}"'
        ' --automation-rule-name "{{rule_name}}"'
        ' --conditions "[]"'
        '  # Update conditions to remove Description field references'
    ),
    "analytics-alert-only": (
        'az sentinel alert-rule update'
        ' --subscription "{subscription_id}"'
        ' --resource-group "{resource_group}"'
        ' --workspace-name "{workspace_name}"'
        ' --rule-id "{{rule_id}}"'
        ' --incident-configuration enabled=true'
        '  # Enable incident creation for alert-only rules'
    ),
    "analytics-fusion": None,  # Defender handles this — info only
    "incident-creation-rule": (
        'az sentinel alert-rule delete'
        ' --subscription "{subscription_id}"'
        ' --resource-group "{resource_group}"'
        ' --workspace-name "{workspace_name}"'
        ' --rule-id "{{rule_id}}"'
        ' --yes'
        '  # Remove MicrosoftSecurityIncidentCreation rule'
    ),
    "connector-subscription-dfc": (
        'az sentinel data-connector update'
        ' --subscription "{subscription_id}"'
        ' --resource-group "{resource_group}"'
        ' --workspace-name "{workspace_name}"'
        ' --data-connector-id "{{connector_id}}"'
        '  # Update subscription-based Defender for Cloud connector'
    ),
    "workspace-manager": None,  # No direct CLI fix — guidance only
}

_NO_FIX_COMMENT = "# No direct CLI fix — see remediation steps above"


def generate_command(
    finding: Finding,
    workspace_name: str,
    resource_group: str,
    subscription_id: str,
) -> str:
    """Return an az CLI command string for *finding*.

    If no actionable CLI command exists, returns a comment explaining why.
    """
    template = _COMMAND_MAP.get(finding.id)

    if template is None:
        # Fall back to whatever the finding itself carries
        if finding.az_command:
            return finding.az_command
        return _NO_FIX_COMMENT

    try:
        return template.format(
            subscription_id=subscription_id,
            resource_group=resource_group,
            workspace_name=workspace_name,
        )
    except KeyError:
        log.warning("Command template formatting failed for %s", finding.id)
        return _NO_FIX_COMMENT
