"""Fetch Sentinel analytics rules."""
from __future__ import annotations

import logging

from azure.identity import DefaultAzureCredential
from azure.mgmt.securityinsight import SecurityInsights

from ..models import AnalyticsRuleInfo

logger = logging.getLogger(__name__)


def fetch_analytics_rules(
    credential: DefaultAzureCredential,
    subscription_id: str,
    resource_group: str,
    workspace_name: str,
) -> list[AnalyticsRuleInfo]:
    """Return analytics rules from the Sentinel workspace."""
    try:
        client = SecurityInsights(credential, subscription_id)
        raw_rules = client.alert_rules.list(resource_group, workspace_name)
        return [_parse_rule(r) for r in raw_rules]
    except Exception as exc:
        logger.error("Failed to fetch analytics rules: %s", exc)
        return []


# -- parsing helpers ---------------------------------------------------------

def _parse_rule(rule) -> AnalyticsRuleInfo:
    """Convert an SDK alert rule object into an AnalyticsRuleInfo."""
    kind = getattr(rule, "kind", "Unknown") or "Unknown"
    name = getattr(rule, "name", "") or ""
    display_name = getattr(rule, "display_name", name) or name
    enabled = _is_enabled(rule)

    # Incident creation & alert grouping
    incident_creation_enabled = True
    alert_grouping_enabled = False
    alert_grouping_reopen_closed = False

    incident_config = getattr(rule, "incident_configuration", None)
    if incident_config is not None:
        create_flag = getattr(incident_config, "create_incident", None)
        if create_flag is not None:
            incident_creation_enabled = bool(create_flag)

        grouping = getattr(incident_config, "grouping_configuration", None)
        if grouping is not None:
            alert_grouping_enabled = bool(
                getattr(grouping, "enabled", False)
            )
            alert_grouping_reopen_closed = bool(
                getattr(grouping, "reopen_closed_incident", False)
            )

    # For Fusion and MicrosoftSecurityIncidentCreation kinds, incident
    # creation is implicitly enabled.
    if kind in ("Fusion", "MicrosoftSecurityIncidentCreation"):
        incident_creation_enabled = True

    return AnalyticsRuleInfo(
        name=name,
        display_name=display_name,
        kind=str(kind),
        enabled=enabled,
        incident_creation_enabled=incident_creation_enabled,
        alert_grouping_reopen_closed=alert_grouping_reopen_closed,
        alert_grouping_enabled=alert_grouping_enabled,
    )


def _is_enabled(rule) -> bool:
    """Determine whether the rule is enabled."""
    if hasattr(rule, "enabled"):
        return bool(rule.enabled)
    if hasattr(rule, "is_enabled"):
        return bool(rule.is_enabled)
    # Fusion rules use an "enabled" property directly
    return True
