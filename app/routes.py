"""Flask routes — the 3-step user flow."""
from __future__ import annotations

import logging
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, Response

from .models import WorkspaceConfig, AssessmentResult, Severity

bp = Blueprint("main", __name__)
log = logging.getLogger(__name__)

# Cache for the latest assessment result in this session
_latest_result: AssessmentResult | None = None
_latest_workspace_info: dict | None = None


# -----------------------------------------------------------------------
# Step 1 — Select Workspace
# -----------------------------------------------------------------------

@bp.route("/")
def index():
    """Show workspace selector (Step 1)."""
    from .discovery.azure_auth import get_credential
    from .discovery.subscriptions import list_subscriptions, list_sentinel_workspaces
    from .history import list_assessments

    auth_error = None
    workspaces = []
    permission_warnings = []
    history = []

    try:
        credential = get_credential()
        subscriptions = list_subscriptions(credential)

        for sub_id, sub_name in subscriptions:
            try:
                ws_list = list_sentinel_workspaces(credential, sub_id)
                for ws in ws_list:
                    ws.subscription_name = sub_name
                workspaces.extend(ws_list)
            except Exception as e:
                log.warning("Failed listing workspaces in %s: %s", sub_id, e)

        # Gather history for all discovered workspaces
        for ws in workspaces:
            try:
                entries = list_assessments(ws.workspace_name)
                history.extend(entries)
            except Exception:
                pass

    except Exception as e:
        auth_error = str(e)
        log.error("Azure auth failed: %s", e)

    return render_template(
        "select_workspace.html",
        workspaces=workspaces,
        auth_error=auth_error,
        permission_warnings=permission_warnings,
        history=sorted(history, key=lambda x: x.get("timestamp", ""), reverse=True)[:10],
    )


# -----------------------------------------------------------------------
# Step 2 — Run Assessment
# -----------------------------------------------------------------------

@bp.route("/assess", methods=["POST"])
def assess():
    """Discover config and run the rules engine."""
    global _latest_result, _latest_workspace_info

    workspace_key = request.form.get("workspace", "")
    if not workspace_key or "|" not in workspace_key:
        flash("Please select a workspace.", "danger")
        return redirect(url_for("main.index"))

    sub_id, rg, ws_name = workspace_key.split("|", 2)

    from .discovery.azure_auth import get_credential, check_permissions
    from .discovery.subscriptions import list_sentinel_workspaces
    from .discovery import fetch_all
    from .rules import run_assessment
    from .remediation.command_generator import generate_command
    from .history import save_assessment, load_latest, compare_assessments

    try:
        credential = get_credential()
    except Exception as e:
        flash(f"Azure authentication failed: {e}", "danger")
        return redirect(url_for("main.index"))

    # Permission check
    perm = check_permissions(credential, sub_id, rg, ws_name)
    if perm.get("missing_roles"):
        for role in perm["missing_roles"]:
            flash(f"Missing role: {role}", "warning")

    # Discover workspace config
    config = fetch_all(credential, sub_id, rg, ws_name)

    # Run rules
    findings = run_assessment(config)

    # Generate az commands for each finding
    for f in findings:
        if not f.az_command:
            f.az_command = generate_command(f, ws_name, rg, sub_id)

    # Build result
    result = AssessmentResult(
        workspace_name=ws_name,
        subscription_id=sub_id,
        findings=findings,
        discovery_errors=config.discovery_errors,
    )

    # Compare with previous
    previous = load_latest(ws_name)
    comparison = None
    if previous:
        comparison = compare_assessments(result, previous)

    # Save this run
    save_assessment(result)

    _latest_result = result
    _latest_workspace_info = {"subscription_id": sub_id, "resource_group": rg}

    return render_template("report.html", result=result, comparison=comparison)


# -----------------------------------------------------------------------
# Step 3 — Remediation
# -----------------------------------------------------------------------

@bp.route("/remediate/wizard")
def remediate_wizard():
    """Interactive fix-one-by-one wizard."""
    if not _latest_result:
        flash("Run an assessment first.", "warning")
        return redirect(url_for("main.index"))

    actionable = [
        f for f in _latest_result.findings
        if f.severity in (Severity.CRITICAL, Severity.WARNING)
    ]

    return render_template(
        "remediate.html",
        findings=actionable,
        workspace_name=_latest_result.workspace_name,
    )


@bp.route("/remediate/script")
def remediate_script():
    """Download a fix-all shell script."""
    if not _latest_result or not _latest_workspace_info:
        flash("Run an assessment first.", "warning")
        return redirect(url_for("main.index"))

    from .remediation.script_builder import build_fix_all_script

    script = build_fix_all_script(
        _latest_result.findings,
        _latest_result.workspace_name,
        _latest_workspace_info["resource_group"],
        _latest_result.subscription_id,
    )

    return Response(
        script,
        mimetype="text/plain",
        headers={
            "Content-Disposition": f"attachment; filename=usx-migration-fix-{_latest_result.workspace_name}.sh"
        },
    )


# -----------------------------------------------------------------------
# Report helpers
# -----------------------------------------------------------------------

@bp.route("/report/latest")
def report_latest():
    """Re-display the latest assessment report."""
    if not _latest_result:
        flash("No assessment results. Run an assessment first.", "warning")
        return redirect(url_for("main.index"))
    return render_template("report.html", result=_latest_result, comparison=None)


@bp.route("/report/download/markdown")
def report_download_markdown():
    """Export the latest report as Markdown."""
    if not _latest_result:
        flash("Run an assessment first.", "warning")
        return redirect(url_for("main.index"))

    from .report import generate_markdown_report

    md = generate_markdown_report(_latest_result)
    return Response(
        md,
        mimetype="text/markdown",
        headers={
            "Content-Disposition": f"attachment; filename=usx-report-{_latest_result.workspace_name}.md"
        },
    )


@bp.route("/report/<filename>")
def report_from_history(filename):
    """Load and display a saved assessment report."""
    from .history import load_by_filename

    result = load_by_filename(filename)
    if not result:
        flash("Assessment not found.", "warning")
        return redirect(url_for("main.index"))

    return render_template("report.html", result=result, comparison=None)


# -----------------------------------------------------------------------
# Checklist
# -----------------------------------------------------------------------

@bp.route("/checklist")
def checklist():
    """Pre-flight migration checklist page."""
    from .history import load_checklist

    ws_name = _latest_result.workspace_name if _latest_result else "default"
    saved_checklist = load_checklist(ws_name)

    return render_template(
        "checklist.html",
        checklist=saved_checklist,
        workspace_name=ws_name,
    )


@bp.route("/checklist/update", methods=["POST"])
def checklist_update():
    """AJAX: toggle a checklist item."""
    from .history import save_checklist, load_checklist

    data = request.get_json(silent=True) or {}
    ws = data.get("workspace", "default")
    key = data.get("key", "")
    checked = data.get("checked", False)

    current = load_checklist(ws)
    current[key] = checked
    save_checklist(ws, current)

    return jsonify({"ok": True})


# -----------------------------------------------------------------------
# Finding status (wizard)
# -----------------------------------------------------------------------

@bp.route("/finding/addressed", methods=["POST"])
def finding_addressed():
    """AJAX: mark a finding as addressed."""
    data = request.get_json(silent=True) or {}
    finding_id = data.get("finding_id", "")

    if _latest_result:
        for f in _latest_result.findings:
            if f.id == finding_id:
                f.addressed = True
                break

    return jsonify({"ok": True})
