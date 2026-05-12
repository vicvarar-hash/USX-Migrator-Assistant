# Discovery package — Azure Sentinel workspace discovery layer
"""Re-export public helpers so callers can do ``from app.discovery import …``."""

from .azure_auth import get_credential, check_permissions
from .subscriptions import list_subscriptions, list_sentinel_workspaces
from .automation_rules import fetch_automation_rules
from .analytics_rules import fetch_analytics_rules
from .connectors import fetch_data_connectors
from .playbooks import fetch_playbooks
from .rbac import fetch_rbac_assignments
from .workspace import fetch_workspace_config

__all__ = [
    "get_credential",
    "check_permissions",
    "list_subscriptions",
    "list_sentinel_workspaces",
    "fetch_automation_rules",
    "fetch_analytics_rules",
    "fetch_data_connectors",
    "fetch_playbooks",
    "fetch_rbac_assignments",
    "fetch_workspace_config",
    "fetch_all",
]

import logging as _logging
from ..models import WorkspaceConfig, SentinelWorkspace

_log = _logging.getLogger(__name__)


def fetch_all(credential, subscription_id: str, resource_group: str,
              workspace_name: str) -> WorkspaceConfig:
    """Fetch all workspace config, handling partial failures gracefully."""
    errors: dict[str, str] = {}

    ws = SentinelWorkspace(
        subscription_id=subscription_id,
        subscription_name="",
        resource_group=resource_group,
        workspace_name=workspace_name,
        workspace_id="",
        location="",
    )
    config = WorkspaceConfig(workspace=ws)

    fetchers = {
        "automation_rules": lambda: fetch_automation_rules(credential, subscription_id, resource_group, workspace_name),
        "analytics_rules": lambda: fetch_analytics_rules(credential, subscription_id, resource_group, workspace_name),
        "data_connectors": lambda: fetch_data_connectors(credential, subscription_id, resource_group, workspace_name),
        "playbooks": lambda: fetch_playbooks(credential, subscription_id, resource_group),
        "rbac_assignments": lambda: fetch_rbac_assignments(credential, subscription_id, resource_group, workspace_name),
    }

    for attr, fetcher in fetchers.items():
        try:
            setattr(config, attr, fetcher())
        except Exception as e:
            _log.error("Failed to fetch %s: %s", attr, e)
            errors[attr] = str(e)

    try:
        ws_cfg = fetch_workspace_config(credential, subscription_id, resource_group, workspace_name)
        config.cmk_enabled = ws_cfg.cmk_enabled
        config.workspace_manager_enabled = ws_cfg.workspace_manager_enabled
    except Exception as e:
        _log.error("Failed to fetch workspace config: %s", e)
        errors["workspace_settings"] = str(e)

    config.discovery_errors = errors
    return config
