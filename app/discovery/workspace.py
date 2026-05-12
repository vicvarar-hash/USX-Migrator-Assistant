"""Fetch workspace-level configuration (CMK, Workspace Manager)."""
from __future__ import annotations

import logging

from azure.identity import DefaultAzureCredential
from azure.mgmt.loganalytics import LogAnalyticsManagementClient
from azure.core.exceptions import HttpResponseError

from ..models import SentinelWorkspace, WorkspaceConfig

logger = logging.getLogger(__name__)


def fetch_workspace_config(
    credential: DefaultAzureCredential,
    subscription_id: str,
    resource_group: str,
    workspace_name: str,
) -> WorkspaceConfig:
    """Return a partial WorkspaceConfig with CMK and Workspace Manager flags.

    Other collections (analytics rules, connectors, etc.) are populated
    separately and merged by the caller.
    """
    # Build a minimal SentinelWorkspace placeholder; the caller typically
    # supplies the real one later.
    sentinel_ws = SentinelWorkspace(
        subscription_id=subscription_id,
        subscription_name="",
        resource_group=resource_group,
        workspace_name=workspace_name,
        workspace_id="",
        location="",
    )

    cmk_enabled = False
    workspace_manager_enabled = False
    discovery_errors: dict[str, str] = {}

    # --- CMK detection ---
    try:
        la_client = LogAnalyticsManagementClient(credential, subscription_id)
        ws = la_client.workspaces.get(resource_group, workspace_name)

        # Fill in placeholder fields from the real workspace
        sentinel_ws.workspace_id = getattr(ws, "customer_id", "") or ""
        sentinel_ws.location = getattr(ws, "location", "") or ""

        # CMK is indicated by a non-null default_data_collection_rule_resource_id
        # or, more reliably, by the encryption property
        encryption = getattr(ws, "encryption", None)
        if encryption is not None:
            key_vault = getattr(encryption, "key_vault_properties", None)
            if key_vault is not None:
                key_name = getattr(key_vault, "key_name", None)
                if key_name:
                    cmk_enabled = True

        # Some SDK versions expose cluster_resource_id instead
        cluster_id = getattr(ws, "cluster_resource_id", None) or getattr(
            ws, "dedicated_cluster_id", None
        )
        if cluster_id:
            cmk_enabled = True

    except HttpResponseError as exc:
        msg = f"HTTP {exc.status_code}: {exc.message}"
        logger.error("Failed to get workspace details: %s", msg)
        discovery_errors["workspace_details"] = msg
    except Exception as exc:
        logger.error("Failed to get workspace details: %s", exc)
        discovery_errors["workspace_details"] = str(exc)

    # --- Workspace Manager detection ---
    # Workspace Manager is configured via the SecurityInsights API; we probe
    # for workspace-manager settings using a lightweight check.
    workspace_manager_enabled = _check_workspace_manager(
        credential, subscription_id, resource_group, workspace_name, discovery_errors
    )

    return WorkspaceConfig(
        workspace=sentinel_ws,
        cmk_enabled=cmk_enabled,
        workspace_manager_enabled=workspace_manager_enabled,
        discovery_errors=discovery_errors,
    )


# -- helpers -----------------------------------------------------------------

def _check_workspace_manager(
    credential: DefaultAzureCredential,
    subscription_id: str,
    resource_group: str,
    workspace_name: str,
    discovery_errors: dict[str, str],
) -> bool:
    """Return True if Workspace Manager is configured."""
    try:
        from azure.mgmt.securityinsight import SecurityInsights

        si_client = SecurityInsights(credential, subscription_id)

        # The workspace_manager_groups operation is only present in
        # workspaces that have Workspace Manager enabled.
        if hasattr(si_client, "workspace_manager_groups"):
            groups = si_client.workspace_manager_groups.list(
                resource_group, workspace_name
            )
            # If we can iterate at least one group, it's enabled
            if next(iter(groups), None) is not None:
                return True

        # Fallback: check workspace_manager_configurations
        if hasattr(si_client, "workspace_manager_configurations"):
            configs = si_client.workspace_manager_configurations.list(
                resource_group, workspace_name
            )
            if next(iter(configs), None) is not None:
                return True

    except HttpResponseError as exc:
        if exc.status_code == 404:
            return False
        logger.debug("Workspace Manager check returned HTTP %s", exc.status_code)
    except Exception as exc:
        logger.debug("Workspace Manager check failed: %s", exc)
        discovery_errors["workspace_manager"] = str(exc)

    return False
