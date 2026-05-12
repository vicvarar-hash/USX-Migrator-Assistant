"""Fetch RBAC role assignments for the Sentinel workspace."""
from __future__ import annotations

import logging

from azure.identity import DefaultAzureCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.core.exceptions import HttpResponseError

from ..models import RBACAssignment

logger = logging.getLogger(__name__)


def fetch_rbac_assignments(
    credential: DefaultAzureCredential,
    subscription_id: str,
    resource_group: str,
    workspace_name: str,
) -> list[RBACAssignment]:
    """Return RBAC assignments scoped to the workspace (and inherited)."""
    try:
        client = AuthorizationManagementClient(credential, subscription_id)

        workspace_scope = (
            f"/subscriptions/{subscription_id}"
            f"/resourceGroups/{resource_group}"
            f"/providers/Microsoft.OperationalInsights"
            f"/workspaces/{workspace_name}"
        )

        # Build a cache of role-definition-id → display name
        role_names = _build_role_name_cache(client, subscription_id)

        results: list[RBACAssignment] = []
        for assignment in client.role_assignments.list_for_scope(workspace_scope):
            role_def_id = assignment.role_definition_id or ""
            role_guid = role_def_id.rsplit("/", 1)[-1]
            role_name = role_names.get(role_guid, role_guid)

            results.append(
                RBACAssignment(
                    principal_id=assignment.principal_id or "",
                    principal_type=assignment.principal_type or "Unknown",
                    role_name=role_name,
                    role_id=role_guid,
                    scope=assignment.scope or "",
                )
            )
        return results

    except HttpResponseError as exc:
        logger.error("HTTP error fetching RBAC assignments: %s", exc.message)
        return []
    except Exception as exc:
        logger.error("Failed to fetch RBAC assignments: %s", exc)
        return []


# -- helpers -----------------------------------------------------------------

def _build_role_name_cache(
    client: AuthorizationManagementClient,
    subscription_id: str,
) -> dict[str, str]:
    """Map role definition GUIDs to their display names."""
    cache: dict[str, str] = {}
    scope = f"/subscriptions/{subscription_id}"
    try:
        for role_def in client.role_definitions.list(scope):
            if role_def.name and role_def.role_name:
                cache[role_def.name] = role_def.role_name
    except Exception as exc:
        logger.warning("Could not cache role definitions: %s", exc)
    return cache
