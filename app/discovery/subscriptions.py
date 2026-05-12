"""List Azure subscriptions and Sentinel-enabled workspaces."""
from __future__ import annotations

import logging

from azure.identity import DefaultAzureCredential
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.securityinsight import SecurityInsights
from azure.mgmt.loganalytics import LogAnalyticsManagementClient
from azure.core.exceptions import HttpResponseError

from ..models import SentinelWorkspace

logger = logging.getLogger(__name__)


def list_subscriptions(
    credential: DefaultAzureCredential,
) -> list[tuple[str, str]]:
    """Return a list of ``(subscription_id, display_name)`` tuples."""
    try:
        client = SubscriptionClient(credential)
        return [
            (sub.subscription_id, sub.display_name or sub.subscription_id)
            for sub in client.subscriptions.list()
            if sub.subscription_id
        ]
    except Exception as exc:
        logger.error("Failed to list subscriptions: %s", exc)
        return []


def list_sentinel_workspaces(
    credential: DefaultAzureCredential,
    subscription_id: str,
) -> list[SentinelWorkspace]:
    """Return Log Analytics workspaces that have the SecurityInsights solution.

    We enumerate all workspaces in the subscription, then probe each for
    Sentinel alert rules as a lightweight check that the solution is enabled.
    """
    workspaces: list[SentinelWorkspace] = []

    try:
        la_client = LogAnalyticsManagementClient(credential, subscription_id)
        all_ws = list(la_client.workspaces.list())
    except Exception as exc:
        logger.error(
            "Failed to list Log Analytics workspaces for subscription %s: %s",
            subscription_id,
            exc,
        )
        return []

    # Resolve subscription display name once
    sub_name = subscription_id
    try:
        sub_client = SubscriptionClient(credential)
        sub_detail = sub_client.subscriptions.get(subscription_id)
        sub_name = sub_detail.display_name or subscription_id
    except Exception:
        pass

    for ws in all_ws:
        if not ws.name or not ws.id:
            continue

        # Extract resource group from the workspace resource ID
        rg = _resource_group_from_id(ws.id)
        if not rg:
            continue

        # Check whether Sentinel is enabled by probing SecurityInsights
        if _has_sentinel(credential, subscription_id, rg, ws.name):
            workspaces.append(
                SentinelWorkspace(
                    subscription_id=subscription_id,
                    subscription_name=sub_name,
                    resource_group=rg,
                    workspace_name=ws.name,
                    workspace_id=ws.customer_id or ws.id,
                    location=ws.location or "",
                )
            )

    return workspaces


# -- helpers -----------------------------------------------------------------

def _resource_group_from_id(resource_id: str) -> str | None:
    """Extract the resource group name from an ARM resource ID."""
    parts = resource_id.split("/")
    try:
        idx = [p.lower() for p in parts].index("resourcegroups")
        return parts[idx + 1]
    except (ValueError, IndexError):
        return None


def _has_sentinel(
    credential: DefaultAzureCredential,
    subscription_id: str,
    resource_group: str,
    workspace_name: str,
) -> bool:
    """Return True if the workspace has Sentinel (SecurityInsights) enabled."""
    try:
        si_client = SecurityInsights(credential, subscription_id)
        # Listing alert rules succeeds only when the solution is installed
        rules = si_client.alert_rules.list(resource_group, workspace_name)
        # Consume at least one item to confirm access
        next(iter(rules), None)
        return True
    except HttpResponseError as exc:
        if exc.status_code in (404, 400):
            return False
        logger.debug(
            "Sentinel check for %s/%s returned HTTP %s",
            resource_group,
            workspace_name,
            exc.status_code,
        )
        return False
    except Exception:
        return False
