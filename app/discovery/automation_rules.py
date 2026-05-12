"""Fetch Sentinel automation rules."""
from __future__ import annotations

import logging

from azure.identity import DefaultAzureCredential
from azure.mgmt.securityinsight import SecurityInsights

from ..models import AutomationRuleInfo

logger = logging.getLogger(__name__)


def fetch_automation_rules(
    credential: DefaultAzureCredential,
    subscription_id: str,
    resource_group: str,
    workspace_name: str,
) -> list[AutomationRuleInfo]:
    """Return automation rules configured in the Sentinel workspace."""
    try:
        client = SecurityInsights(credential, subscription_id)
        raw_rules = client.automation_rules.list(resource_group, workspace_name)
        return [_parse_rule(r) for r in raw_rules]
    except Exception as exc:
        logger.error("Failed to fetch automation rules: %s", exc)
        return []


# -- parsing helpers ---------------------------------------------------------

def _parse_rule(rule) -> AutomationRuleInfo:
    """Convert an SDK automation rule object into an AutomationRuleInfo."""
    trigger_type = _detect_trigger(rule)
    conditions = _extract_conditions(rule)
    actions = _extract_actions(rule)
    enabled = getattr(rule, "order", None) is not None  # rules without order are disabled

    # Prefer the explicit enabled flag when available
    if hasattr(rule, "enabled"):
        enabled = bool(rule.enabled)
    elif hasattr(rule, "is_enabled"):
        enabled = bool(rule.is_enabled)

    return AutomationRuleInfo(
        name=rule.name or "",
        display_name=getattr(rule, "display_name", rule.name) or "",
        trigger_type=trigger_type,
        conditions=conditions,
        actions=actions,
        enabled=enabled,
    )


def _detect_trigger(rule) -> str:
    """Determine whether the rule triggers on incidents or alerts."""
    triggering = getattr(rule, "triggering_logic", None)
    if triggering:
        trigger_type_raw = getattr(triggering, "triggers_on", "") or ""
        if "alert" in trigger_type_raw.lower():
            return "alert"
    return "incident"


def _extract_conditions(rule) -> list[dict]:
    """Pull migration-relevant condition metadata from the rule."""
    conditions: list[dict] = []
    triggering = getattr(rule, "triggering_logic", None)
    if not triggering:
        return conditions

    raw_conditions = getattr(triggering, "conditions", None) or []
    for cond in raw_conditions:
        entry: dict = {"type": type(cond).__name__}

        # PropertyConditionProperties / PropertyCondition
        prop_cond = getattr(cond, "condition_properties", None) or cond
        prop_name = getattr(prop_cond, "property_name", None)
        operator = getattr(prop_cond, "operator", None)
        values = getattr(prop_cond, "property_values", None) or []

        if prop_name:
            entry["property"] = str(prop_name)
        if operator:
            entry["operator"] = str(operator)
        if values:
            entry["values"] = [str(v) for v in values]

        # Flag patterns important for USX migration
        if prop_name:
            pn = str(prop_name).lower()
            if "incidentprovider" in pn or "provider" in pn:
                entry["migration_flag"] = "IncidentProvider"
            elif "description" in pn:
                entry["migration_flag"] = "DescriptionField"
            elif "title" in pn:
                entry["migration_flag"] = "TitleCondition"
            elif "updatedby" in pn:
                entry["migration_flag"] = "UpdatedByCondition"

        conditions.append(entry)
    return conditions


def _extract_actions(rule) -> list[dict]:
    """Extract action metadata from the rule."""
    actions: list[dict] = []
    raw_actions = getattr(rule, "actions", None) or []
    for action in raw_actions:
        entry: dict = {"type": type(action).__name__}
        action_type = getattr(action, "action_type", None)
        if action_type:
            entry["action_type"] = str(action_type)

        # Playbook action details
        logic_app_id = getattr(action, "logic_app_resource_id", None)
        if logic_app_id:
            entry["logic_app_resource_id"] = str(logic_app_id)

        # Modify-properties action details
        severity = getattr(action, "severity", None)
        status = getattr(action, "status", None)
        owner = getattr(action, "owner", None)
        if severity:
            entry["severity"] = str(severity)
        if status:
            entry["status"] = str(status)
        if owner:
            entry["owner"] = str(owner)

        actions.append(entry)
    return actions
