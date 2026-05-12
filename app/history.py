"""Assessment history — persist and compare assessment runs."""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Optional

from .models import AssessmentResult

log = logging.getLogger(__name__)

_HISTORY_DIR = Path.home() / ".usx-migrator"


def _ensure_dir() -> Path:
    _HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    return _HISTORY_DIR


def _safe_name(workspace_name: str) -> str:
    """Sanitise workspace name for use in filenames."""
    return re.sub(r"[^\w\-]", "_", workspace_name)


# ---------------------------------------------------------------------------
# Save / load assessments
# ---------------------------------------------------------------------------

def save_assessment(result: AssessmentResult) -> str:
    """Persist *result* as JSON and return the filepath."""
    try:
        base = _ensure_dir()
        safe = _safe_name(result.workspace_name)
        ts = result.timestamp.replace(":", "-")
        filepath = base / f"{safe}_{ts}.json"
        filepath.write_text(result.to_json(), encoding="utf-8")
        log.info("Assessment saved to %s", filepath)
        return str(filepath)
    except OSError as exc:
        log.error("Failed to save assessment: %s", exc)
        raise


def _list_files(workspace_name: str) -> list[Path]:
    """Return assessment files for *workspace_name*, newest first."""
    base = _ensure_dir()
    safe = _safe_name(workspace_name)
    files = sorted(
        base.glob(f"{safe}_*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return files


def load_latest(workspace_name: str) -> Optional[AssessmentResult]:
    """Load the most recent assessment for *workspace_name*."""
    files = _list_files(workspace_name)
    if not files:
        return None
    try:
        raw = files[0].read_text(encoding="utf-8")
        return AssessmentResult.from_json(raw)
    except (OSError, json.JSONDecodeError, KeyError) as exc:
        log.error("Failed to load latest assessment: %s", exc)
        return None


def load_previous(workspace_name: str) -> Optional[AssessmentResult]:
    """Load the second-most-recent assessment (for comparison)."""
    files = _list_files(workspace_name)
    if len(files) < 2:
        return None
    try:
        raw = files[1].read_text(encoding="utf-8")
        return AssessmentResult.from_json(raw)
    except (OSError, json.JSONDecodeError, KeyError) as exc:
        log.error("Failed to load previous assessment: %s", exc)
        return None


def list_assessments(workspace_name: str) -> list[dict]:
    """Return metadata dicts for every saved assessment of *workspace_name*."""
    results: list[dict] = []
    for fp in _list_files(workspace_name):
        try:
            raw = fp.read_text(encoding="utf-8")
            result = AssessmentResult.from_json(raw)
            results.append({
                "timestamp": result.timestamp,
                "filepath": str(fp),
                "filename": fp.name,
                "workspace_name": result.workspace_name,
                "critical_count": result.critical_count,
                "warning_count": result.warning_count,
            })
        except (OSError, json.JSONDecodeError, KeyError) as exc:
            log.warning("Skipping corrupt file %s: %s", fp, exc)
    return results


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------

def compare_assessments(
    current: AssessmentResult,
    previous: AssessmentResult,
) -> dict:
    """Compare two assessment runs and return a diff summary."""
    cur_ids = {f.id for f in current.findings}
    prev_ids = {f.id for f in previous.findings}

    prev_map = {f.id: f for f in previous.findings}
    cur_map = {f.id: f for f in current.findings}

    resolved_ids = prev_ids - cur_ids
    new_ids = cur_ids - prev_ids
    unchanged_ids = cur_ids & prev_ids

    resolved = [prev_map[fid].to_dict() for fid in resolved_ids]
    new = [cur_map[fid].to_dict() for fid in new_ids]
    unchanged = [cur_map[fid].to_dict() for fid in unchanged_ids]

    # Build delta summary string
    prev_crit = sum(1 for f in previous.findings if f.severity.value == "critical")
    cur_crit = sum(1 for f in current.findings if f.severity.value == "critical")
    prev_warn = sum(1 for f in previous.findings if f.severity.value == "warning")
    cur_warn = sum(1 for f in current.findings if f.severity.value == "warning")

    delta_parts: list[str] = []
    if prev_crit or cur_crit:
        resolved_c = prev_crit - cur_crit
        direction = f"({resolved_c} resolved)" if resolved_c > 0 else (
            f"({abs(resolved_c)} new)" if resolved_c < 0 else "(unchanged)"
        )
        delta_parts.append(f"{prev_crit} critical → {cur_crit} critical {direction}")
    if prev_warn or cur_warn:
        resolved_w = prev_warn - cur_warn
        direction = f"({resolved_w} resolved)" if resolved_w > 0 else (
            f"({abs(resolved_w)} new)" if resolved_w < 0 else "(unchanged)"
        )
        delta_parts.append(f"{prev_warn} warning → {cur_warn} warning {direction}")

    return {
        "resolved_findings": [f["title"] for f in resolved],
        "new_findings": [cur_map[fid].title for fid in new_ids],
        "unchanged_findings": unchanged,
        "delta_summary": "; ".join(delta_parts) if delta_parts else "No change",
        "previous_timestamp": previous.timestamp,
        "previous_critical": prev_crit,
        "delta_critical": cur_crit - prev_crit,
    }


# ---------------------------------------------------------------------------
# Checklist persistence
# ---------------------------------------------------------------------------

def save_checklist(workspace_name: str, checklist: dict[str, bool]) -> None:
    """Persist manual-checklist state."""
    try:
        base = _ensure_dir()
        safe = _safe_name(workspace_name)
        filepath = base / f"{safe}_checklist.json"
        filepath.write_text(json.dumps(checklist, indent=2), encoding="utf-8")
    except OSError as exc:
        log.error("Failed to save checklist: %s", exc)


def load_checklist(workspace_name: str) -> dict[str, bool]:
    """Load persisted checklist state (empty dict on error/missing)."""
    try:
        base = _ensure_dir()
        safe = _safe_name(workspace_name)
        filepath = base / f"{safe}_checklist.json"
        if not filepath.exists():
            return {}
        return json.loads(filepath.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        log.error("Failed to load checklist: %s", exc)
        return {}


def load_by_filename(filename: str) -> Optional[AssessmentResult]:
    """Load an assessment result by its filename."""
    try:
        filepath = _ensure_dir() / filename
        if not filepath.exists():
            return None
        raw = filepath.read_text(encoding="utf-8")
        return AssessmentResult.from_json(raw)
    except (OSError, json.JSONDecodeError, KeyError) as exc:
        log.error("Failed to load assessment %s: %s", filename, exc)
        return None
