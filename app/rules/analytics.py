"""Analytics rule migration checks."""
from __future__ import annotations

from .base import MigrationRule
from ..models import Finding, Severity, WorkspaceConfig

_BASE_DOC = "https://learn.microsoft.com/azure/sentinel/move-to-defender"


class FusionRuleCheck(MigrationRule):
    id = "analytics-fusion"
    title = "Fusion analytics rule enabled"
    category = "Analytics Rules"
    doc_url = f"{_BASE_DOC}#analytics-rules"

    def evaluate(self, config: WorkspaceConfig) -> list[Finding]:
        affected = [
            r.display_name for r in config.analytics_rules
            if r.enabled and r.kind == "Fusion"
        ]
        if not affected:
            return []
        return [Finding(
            id=self.id,
            title=self.title,
            category=self.category,
            severity=Severity.WARNING,
            description=(
                f"{len(affected)} Fusion analytics rule(s) found enabled. "
                "Fusion rules will be automatically disabled after "
                "onboarding because Defender XDR's correlation engine "
                "replaces Fusion's multi-stage attack detection."
            ),
            impact=(
                f"Rules affected: {', '.join(affected)}. Multi-stage "
                "attack detection will be handled by Defender XDR "
                "instead of Sentinel Fusion."
            ),
            remediation=(
                "1. Review current Fusion detection coverage.\n"
                "2. Verify that Defender XDR correlation covers the "
                "same attack scenarios.\n"
                "3. No action required — Fusion is disabled automatically."
            ),
            doc_url=self.doc_url,
            affected_resources=affected,
        )]


class AlertOnlyRuleCheck(MigrationRule):
    id = "analytics-alert-only"
    title = "Analytics rules with incident creation disabled"
    category = "Analytics Rules"
    doc_url = f"{_BASE_DOC}#analytics-rules"

    def evaluate(self, config: WorkspaceConfig) -> list[Finding]:
        affected = [
            r.display_name for r in config.analytics_rules
            if r.enabled and not r.incident_creation_enabled
            and r.kind in ("Scheduled", "NRT")
        ]
        if not affected:
            return []
        return [Finding(
            id=self.id,
            title=self.title,
            category=self.category,
            severity=Severity.CRITICAL,
            description=(
                f"{len(affected)} analytics rule(s) have incident creation "
                "disabled (alert-only mode). In Defender XDR, alerts that "
                "do not create incidents are not visible in the unified "
                "incident queue."
            ),
            impact=(
                f"Rules affected: {', '.join(affected)}. Alerts from "
                "these rules will be invisible in the Defender XDR portal "
                "unless incident creation is enabled."
            ),
            remediation=(
                "1. Enable incident creation on each affected rule, or\n"
                "2. Accept that these alerts will only be visible in the "
                "Log Analytics SecurityAlert table.\n"
                "3. Update any SOAR workflows that depend on alert-only "
                "rules."
            ),
            doc_url=self.doc_url,
            affected_resources=affected,
        )]


class AlertGroupingReopenCheck(MigrationRule):
    id = "analytics-alert-grouping-reopen"
    title = "Alert grouping configured to reopen closed incidents"
    category = "Analytics Rules"
    doc_url = f"{_BASE_DOC}#analytics-rules"

    def evaluate(self, config: WorkspaceConfig) -> list[Finding]:
        affected = [
            r.display_name for r in config.analytics_rules
            if r.enabled and r.alert_grouping_enabled
            and r.alert_grouping_reopen_closed
        ]
        if not affected:
            return []
        return [Finding(
            id=self.id,
            title=self.title,
            category=self.category,
            severity=Severity.WARNING,
            description=(
                f"{len(affected)} analytics rule(s) have alert grouping "
                "configured to reopen closed incidents. This feature is "
                "not supported in Defender XDR."
            ),
            impact=(
                f"Rules affected: {', '.join(affected)}. New alerts will "
                "create new incidents instead of reopening closed ones, "
                "potentially increasing incident volume."
            ),
            remediation=(
                "1. Review each affected rule's grouping settings.\n"
                "2. Adjust SOC workflows to handle new incidents "
                "instead of reopened ones.\n"
                "3. Consider using automation rules to link related "
                "incidents post-onboarding."
            ),
            doc_url=self.doc_url,
            affected_resources=affected,
        )]
