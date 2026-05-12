"""Azure credential management and permission checks."""
from __future__ import annotations

import logging
import os
import shutil
from typing import Any

from azure.identity import DefaultAzureCredential, AzureCliCredential
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


def get_credential() -> AzureCliCredential | DefaultAzureCredential:
    """Return an Azure credential, preferring AzureCliCredential.

    AzureCliCredential is preferred because it directly reads the ``az login``
    token cache without needing the ``az`` CLI on PATH.  If that fails we fall
    back to ``DefaultAzureCredential``.
    """
    # Ensure the Azure CLI is discoverable — Flask may inherit a limited PATH
    _ensure_az_on_path()

    try:
        cred = AzureCliCredential()
        # Validate the credential with a quick token request
        cred.get_token("https://management.azure.com/.default")
        logger.info("Using AzureCliCredential")
        return cred
    except Exception as exc:
        logger.debug("AzureCliCredential failed: %s — falling back to DefaultAzureCredential", exc)

    try:
        return DefaultAzureCredential()
    except Exception as exc:
        logger.error("Failed to acquire Azure credential: %s", exc)
        raise RuntimeError(
            "Could not authenticate to Azure. Run 'az login' first."
        ) from exc


def _ensure_az_on_path() -> None:
    """Add common Azure CLI install locations to PATH if ``az`` is not found."""
    if shutil.which("az"):
        return

    extra_dirs = []
    # Windows default install location
    program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
    extra_dirs.append(os.path.join(program_files, "Microsoft SDKs", "Azure", "CLI2", "wbin"))
    program_files_x86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    extra_dirs.append(os.path.join(program_files_x86, "Microsoft SDKs", "Azure", "CLI2", "wbin"))
    # Also check user-level pip install
    local_bin = os.path.expanduser("~/.local/bin")
    extra_dirs.append(local_bin)

    current_path = os.environ.get("PATH", "")
    for d in extra_dirs:
        if os.path.isdir(d) and d not in current_path:
            os.environ["PATH"] = d + os.pathsep + current_path
            current_path = os.environ["PATH"]
            logger.info("Added %s to PATH for Azure CLI discovery", d)

    if shutil.which("az"):
        logger.info("Azure CLI found after PATH update")
    else:
        logger.warning("Azure CLI (az) not found on PATH — AzureCliCredential may fail")


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
