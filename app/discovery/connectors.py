"""Fetch Sentinel data connectors."""
from __future__ import annotations

import logging

from azure.identity import DefaultAzureCredential
from azure.mgmt.securityinsight import SecurityInsights

from ..models import DataConnectorInfo

logger = logging.getLogger(__name__)

# Map SDK kind values to friendly connector names for key connectors
_KNOWN_KINDS: dict[str, str] = {
    "AzureSecurityCenter": "Microsoft Defender for Cloud (subscription-based)",
    "MicrosoftDefenderAdvancedThreatProtection": "Microsoft Defender for Endpoint (MDE)",
    "MicrosoftCloudAppSecurity": "Microsoft Defender for Cloud Apps (MCAS)",
    "AzureAdvancedThreatProtection": "Microsoft Defender for Identity (MDI)",
    "Office365": "Microsoft Defender for Office 365 (MDO)",
    "OfficeATP": "Microsoft Defender for Office 365 (MDO)",
    "MicrosoftThreatProtection": "Microsoft 365 Defender (XDR)",
    "MicrosoftThreatIntelligence": "Microsoft Threat Intelligence",
    "AzureActiveDirectory": "Azure Active Directory",
}


def fetch_data_connectors(
    credential: DefaultAzureCredential,
    subscription_id: str,
    resource_group: str,
    workspace_name: str,
) -> list[DataConnectorInfo]:
    """Return data connectors configured in the Sentinel workspace."""
    try:
        client = SecurityInsights(credential, subscription_id)
        raw = client.data_connectors.list(resource_group, workspace_name)
        return [_parse_connector(c) for c in raw]
    except Exception as exc:
        logger.error("Failed to fetch data connectors: %s", exc)
        return []


# -- parsing helpers ---------------------------------------------------------

def _parse_connector(connector) -> DataConnectorInfo:
    """Convert an SDK data connector into a DataConnectorInfo."""
    kind = getattr(connector, "kind", "Unknown") or "Unknown"
    name = getattr(connector, "name", "") or ""
    connected = _is_connected(connector)

    friendly = _KNOWN_KINDS.get(str(kind), str(kind))

    # Detect tenant-based Defender for Cloud connectors
    if kind == "AzureSecurityCenter":
        sub_id = getattr(connector, "subscription_id", None)
        if not sub_id:
            friendly = "Microsoft Defender for Cloud (tenant-based)"

    return DataConnectorInfo(
        name=name,
        kind=friendly,
        connected=connected,
    )


def _is_connected(connector) -> bool:
    """Best-effort check for whether the connector is connected."""
    # Many connectors expose a data_types property with state info
    data_types = getattr(connector, "data_types", None)
    if data_types is None:
        return True  # assume connected when we can't determine

    # Iterate attributes of data_types (e.g., alerts, incidents, logs)
    for attr_name in dir(data_types):
        if attr_name.startswith("_"):
            continue
        dt = getattr(data_types, attr_name, None)
        if dt is None:
            continue
        state = getattr(dt, "state", None)
        if state is not None:
            return str(state).lower() == "enabled"

    return True
