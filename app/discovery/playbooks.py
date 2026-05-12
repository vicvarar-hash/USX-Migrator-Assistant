"""Fetch Logic App playbooks used by Sentinel."""
from __future__ import annotations

import logging

from azure.identity import DefaultAzureCredential
from azure.mgmt.logic import LogicManagementClient

from ..models import PlaybookInfo

logger = logging.getLogger(__name__)

# Sentinel trigger type keywords found in the Logic App trigger body/kind
_TRIGGER_KEYWORDS = {
    "Microsoft.SecurityInsights/Incidents": "incident",
    "Microsoft-SecurityInsights-Incident": "incident",
    "SecurityInsights-Incident": "incident",
    "Microsoft.SecurityInsights/Alerts": "alert",
    "Microsoft-SecurityInsights-Alert": "alert",
    "SecurityInsights-Alert": "alert",
    "Microsoft.SecurityInsights/Entities": "entity",
    "Microsoft-SecurityInsights-Entity": "entity",
    "SecurityInsights-Entity": "entity",
    # Batched trigger names
    "When_Azure_Sentinel_incident": "incident",
    "When_a_response_to_an_Azure_Sentinel_alert": "alert",
}


def fetch_playbooks(
    credential: DefaultAzureCredential,
    subscription_id: str,
    resource_group: str,
) -> list[PlaybookInfo]:
    """Return Logic App workflows in the resource group.

    Only workflows that look like Sentinel playbooks (trigger contains
    SecurityInsights references) are included, but if trigger detection
    is ambiguous the workflow is still returned with ``trigger_type="unknown"``.
    """
    try:
        client = LogicManagementClient(credential, subscription_id)
        workflows = client.workflows.list_by_resource_group(resource_group)
        results: list[PlaybookInfo] = []
        for wf in workflows:
            info = _parse_workflow(client, resource_group, wf)
            if info is not None:
                results.append(info)
        return results
    except Exception as exc:
        logger.error("Failed to fetch playbooks: %s", exc)
        return []


# -- helpers -----------------------------------------------------------------

def _parse_workflow(client: LogicManagementClient, resource_group: str, wf) -> PlaybookInfo | None:
    """Parse a Logic App workflow into a PlaybookInfo if it's a Sentinel playbook."""
    name = getattr(wf, "name", "") or ""
    state = getattr(wf, "state", "Enabled") or "Enabled"
    enabled = str(state).lower() == "enabled"

    trigger_type = _detect_trigger_type(client, resource_group, name)

    return PlaybookInfo(
        name=name,
        resource_group=resource_group,
        trigger_type=trigger_type,
        enabled=enabled,
    )


def _detect_trigger_type(
    client: LogicManagementClient,
    resource_group: str,
    workflow_name: str,
) -> str:
    """Inspect the workflow trigger definition to classify the trigger."""
    try:
        triggers = client.workflow_triggers.list(resource_group, workflow_name)
        for trigger in triggers:
            trigger_name = getattr(trigger, "name", "") or ""
            trigger_type_raw = getattr(trigger, "type", "") or ""

            # Check trigger name and type against known patterns
            combined = f"{trigger_name} {trigger_type_raw}"
            for keyword, ttype in _TRIGGER_KEYWORDS.items():
                if keyword.lower() in combined.lower():
                    return ttype

            # Fallback: inspect the trigger's changed_time / kind attributes
            kind = getattr(trigger, "kind", "") or ""
            if kind:
                for keyword, ttype in _TRIGGER_KEYWORDS.items():
                    if keyword.lower() in kind.lower():
                        return ttype
    except Exception as exc:
        logger.debug("Could not inspect triggers for %s: %s", workflow_name, exc)

    return "unknown"
