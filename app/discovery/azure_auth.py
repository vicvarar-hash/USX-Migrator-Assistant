"""Azure credential management and permission checks."""
from __future__ import annotations

import logging
from typing import Any

from azure.identity import DefaultAzureCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.core.exceptions import ClientAuthenticationError, HttpResponseError

logger = logging.getLogger(__name__)

# Sentinel-relevant built-in role definition IDs (last GUID segment)
_SENTINEL_ROLES = {
    "ab8e14d6-4a74-4a29-9ba8-549422addade": "Microsoft Sentinel Reader",
    "3e150fc0-dc56-4d0c-916f-35815bbb5a50": "Microsoft Sentinel Contributor",
    "3e150fc0-dc56-4d0c-916f-35815bbb5a51": "Microsoft Sentinel Responder",
    "f4c81013-99ee-4d62-a7ee-b3f1f648599a": "Microsoft Sentinel Automation Contributor",
}

_SUBSCRIPTION_ROLES = {
    "acdd72a7-3385-48ef-bd42-f606fba81ae7": "Reader",
}


def get_credential() -> DefaultAzureCredential:
    """Return a DefaultAzureCredential (expects ``az login`` session)."""
    try:
        return DefaultAzureCredential()
    except Exception as exc:
        logger.error("Failed to acquire Azure credential: %s", exc)
        raise RuntimeError(
            "Could not authenticate to Azure. Run 'az login' first."
        ) from exc


def check_permissions(
    credential: DefaultAzureCredential,
    subscription_id: str,
    resource_group: str,
    workspace_name: str,
) -> dict[str, Any]:
    """Check whether the caller has Sentinel and subscription roles.

    Returns a dict with boolean flags and a ``missing_roles`` list.
    """
    result: dict[str, Any] = {
        "sentinel_reader": False,
        "subscription_reader": False,
        "missing_roles": [],
    }

    try:
        auth_client = AuthorizationManagementClient(credential, subscription_id)

        workspace_scope = (
            f"/subscriptions/{subscription_id}"
            f"/resourceGroups/{resource_group}"
            f"/providers/Microsoft.OperationalInsights"
            f"/workspaces/{workspace_name}"
        )

        # Collect role definition IDs assigned at workspace or broader scope
        assigned_role_ids: set[str] = set()
        try:
            for assignment in auth_client.role_assignments.list_for_scope(workspace_scope):
                role_def_id = assignment.role_definition_id or ""
                # The last segment is the role GUID
                role_guid = role_def_id.rsplit("/", 1)[-1]
                assigned_role_ids.add(role_guid)
        except HttpResponseError as exc:
            logger.warning(
                "Cannot enumerate role assignments (may lack permissions): %s", exc
            )

        # Check sentinel roles
        for role_id in _SENTINEL_ROLES:
            if role_id in assigned_role_ids:
                result["sentinel_reader"] = True
                break

        if not result["sentinel_reader"]:
            result["missing_roles"].append(
                "Microsoft Sentinel Reader (or Contributor/Responder)"
            )

        # Check subscription-level reader
        sub_scope = f"/subscriptions/{subscription_id}"
        try:
            for assignment in auth_client.role_assignments.list_for_scope(sub_scope):
                role_def_id = assignment.role_definition_id or ""
                role_guid = role_def_id.rsplit("/", 1)[-1]
                if role_guid in _SUBSCRIPTION_ROLES:
                    result["subscription_reader"] = True
                    break
        except HttpResponseError as exc:
            logger.warning("Cannot check subscription-level roles: %s", exc)

        if not result["subscription_reader"]:
            result["missing_roles"].append("Subscription Reader")

    except ClientAuthenticationError as exc:
        logger.error("Authentication failed during permission check: %s", exc)
        result["missing_roles"].append("Unable to authenticate – run 'az login'")
    except Exception as exc:
        logger.error("Unexpected error checking permissions: %s", exc)
        result["missing_roles"].append(f"Permission check failed: {exc}")

    return result
