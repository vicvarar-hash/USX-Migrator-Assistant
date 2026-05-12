"""Build runnable shell scripts from assessment findings."""
from __future__ import annotations

import logging
from collections import defaultdict

from ..models import Finding
from .command_generator import generate_command

log = logging.getLogger(__name__)

_SCRIPT_HEADER = """\
#!/bin/bash
set -e

###############################################################################
# USX Migrator — Remediation Script
# Workspace : {workspace_name}
# Subscription: {subscription_id}
# Generated automatically — review before executing.
###############################################################################

# Ensure we are logged in
if ! az account show > /dev/null 2>&1; then
    echo "Not logged in. Running az login..."
    az login
fi

az account set --subscription "{subscription_id}"
echo "Using subscription {subscription_id}"
echo ""
"""

_NO_FIX_COMMENT = "# No direct CLI fix"


def _is_actionable(cmd: str) -> bool:
    """Return True when *cmd* is a real az command, not just a comment."""
    return not cmd.lstrip().startswith("#")


def build_fix_single(
    finding: Finding,
    workspace_name: str,
    resource_group: str,
    subscription_id: str,
) -> str:
    """Return the CLI command (or comment) for a single finding."""
    return generate_command(finding, workspace_name, resource_group, subscription_id)


def build_fix_all_script(
    findings: list[Finding],
    workspace_name: str,
    resource_group: str,
    subscription_id: str,
) -> str:
    """Build a complete bash script that remediates all actionable findings.

    Findings are grouped by category, with comments explaining each section.
    Info-only findings (no CLI fix) are skipped.
    """
    header = _SCRIPT_HEADER.format(
        workspace_name=workspace_name,
        subscription_id=subscription_id,
    )

    # Group findings by category
    by_category: dict[str, list[tuple[Finding, str]]] = defaultdict(list)
    for f in findings:
        cmd = generate_command(f, workspace_name, resource_group, subscription_id)
        if _is_actionable(cmd):
            by_category[f.category].append((f, cmd))

    if not by_category:
        return header + "echo \"No actionable remediations found.\"\n"

    sections: list[str] = []
    for category, items in sorted(by_category.items()):
        lines: list[str] = []
        lines.append(f"# === {category} {'=' * max(1, 60 - len(category))}") 
        lines.append("")
        for finding, cmd in items:
            lines.append(f"# [{finding.severity.value.upper()}] {finding.title}")
            if finding.affected_resources:
                lines.append(f"#   Affected: {', '.join(finding.affected_resources[:5])}")
            lines.append(cmd)
            lines.append("")
        sections.append("\n".join(lines))

    return header + "\n".join(sections)
