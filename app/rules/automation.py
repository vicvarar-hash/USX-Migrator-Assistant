"""Automation & playbook migration rules."""
from __future__ import annotations

from .base import MigrationRule
from ..models import Finding, Severity, WorkspaceConfig

_BASE_DOC = "https://learn.microsoft.com/azure/sentinel/move-to-defender"


class AutomationAlertTriggerRule(MigrationRule):
    id = "automation-alert-trigger"
    title = "Automation rules using alert triggers"
    category = "Automation Rules"
    doc_url = f"{_BASE_DOC}#automation-rules"

    def evaluate(self, config: WorkspaceConfig) -> list[Finding]:
        affected = [
            r.display_name for r in config.automation_rules
            if r.enabled and r.trigger_type == "alert"
        ]
        if not affected:
            return []
        return [Finding(
            id=self.id,
            title=self.title,
            category=self.category,
            severity=Severity.WARNING,
            description=(
                f"{len(affected)} automation rule(s) use an alert trigger. "
                "After onboarding to Defender XDR, alert-triggered automation "
                "rules will only fire on Microsoft Sentinel alerts, not on "
                "alerts from other Defender workloads."
            ),
            impact=(
                f"Rules affected: {', '.join(affected)}. These rules will "
                "have reduced scope because they cannot act on native "
                "Defender XDR alerts."
            ),
            remediation=(
                "1. Review each alert-triggered automation rule.\n"
                "2. Consider converting them to incident-triggered rules "
                "where possible.\n"
                "3. For rules that must stay alert-triggered, verify they "
                "only need to act on Sentinel-generated alerts."
            ),
            doc_url=self.doc_url,
            affected_resources=affected,
        )]


class AutomationIncidentProviderRule(MigrationRule):
    id = "automation-incident-provider"
    title = "Automation rules with 'Incident provider = Microsoft Sentinel'"
    category = "Automation Rules"
    doc_url = f"{_BASE_DOC}#automation-rules"

    def evaluate(self, config: WorkspaceConfig) -> list[Finding]:
        affected = []
        for r in config.automation_rules:
            if not r.enabled:
                continue
            for cond in r.conditions:
                prop = cond.get("conditionProperties", cond)
                operator_val = str(prop.get("propertyName", "")).lower()
                values = [str(v).lower() for v in prop.get("propertyValues", [])]
                if (
                    operator_val == "incidentprovidernames"
                    or "incidentprovidernames" in operator_val
                    or "incident provider" in operator_val
                ):
                    if any("sentinel" in v for v in values):
                        affected.append(r.display_name)
                        break
        if not affected:
            return []
        return [Finding(
            id=self.id,
            title=self.title,
            category=self.category,
            severity=Severity.CRITICAL,
            description=(
                f"{len(affected)} automation rule(s) filter on "
                "'Incident provider = Microsoft Sentinel'. This condition is "
                "removed after onboarding to Defender XDR, so these rules "
                "may fire on incidents they were not designed for."
            ),
            impact=(
                f"Rules affected: {', '.join(affected)}. Without the "
                "provider filter, these rules will apply to all incidents, "
                "potentially causing unintended actions."
            ),
            remediation=(
                "1. Open each affected automation rule.\n"
                "2. Replace the 'Incident provider' condition with an "
                "equivalent filter (e.g., analytics rule name).\n"
                "3. Test the updated rules before onboarding."
            ),
            doc_url=self.doc_url,
            affected_resources=affected,
        )]


class AutomationDescriptionFieldRule(MigrationRule):
    id = "automation-description-field"
    title = "Automation rules using SecurityIncident.Description"
    category = "Automation Rules"
    doc_url = f"{_BASE_DOC}#automation-rules"

    def evaluate(self, config: WorkspaceConfig) -> list[Finding]:
        affected = []
        for r in config.automation_rules:
            if not r.enabled:
                continue
            for cond in r.conditions:
                prop = cond.get("conditionProperties", cond)
                prop_name = str(prop.get("propertyName", "")).lower()
                if "description" in prop_name:
                    affected.append(r.display_name)
                    break
        if not affected:
            return []
        return [Finding(
            id=self.id,
            title=self.title,
            category=self.category,
            severity=Severity.CRITICAL,
            description=(
                f"{len(affected)} automation rule(s) use the "
                "SecurityIncident.Description field as a condition. "
                "This field is removed from the incident schema in "
                "Defender XDR."
            ),
            impact=(
                f"Rules affected: {', '.join(affected)}. These rules "
                "will stop matching after onboarding because the "
                "Description field no longer exists."
            ),
            remediation=(
                "1. Open each affected rule.\n"
                "2. Replace the Description condition with an alternative "
                "field (e.g., incident title or custom tag).\n"
                "3. Validate updated rules in a test environment."
            ),
            doc_url=self.doc_url,
            affected_resources=affected,
        )]


class AutomationIncidentTitleRule(MigrationRule):
    id = "automation-incident-title"
    title = "Automation rules filtering on incident title"
    category = "Automation Rules"
    doc_url = f"{_BASE_DOC}#automation-rules"

    def evaluate(self, config: WorkspaceConfig) -> list[Finding]:
        affected = []
        for r in config.automation_rules:
            if not r.enabled:
                continue
            for cond in r.conditions:
                prop = cond.get("conditionProperties", cond)
                prop_name = str(prop.get("propertyName", "")).lower()
                if "title" in prop_name:
                    affected.append(r.display_name)
                    break
        if not affected:
            return []
        return [Finding(
            id=self.id,
            title=self.title,
            category=self.category,
            severity=Severity.WARNING,
            description=(
                f"{len(affected)} automation rule(s) filter on incident "
                "title. Defender XDR may rename incidents during "
                "correlation, causing title-based conditions to stop "
                "matching."
            ),
            impact=(
                f"Rules affected: {', '.join(affected)}. Incident titles "
                "may change after onboarding, breaking these conditions."
            ),
            remediation=(
                "1. Review each affected rule's title condition.\n"
                "2. Use broader substring matching or switch to "
                "analytics-rule-name conditions where possible.\n"
                "3. Monitor rule execution after onboarding."
            ),
            doc_url=self.doc_url,
            affected_resources=affected,
        )]


class AutomationUpdatedByRule(MigrationRule):
    id = "automation-updated-by"
    title = "Automation rules with 'Updated by = Microsoft 365 Defender'"
    category = "Automation Rules"
    doc_url = f"{_BASE_DOC}#automation-rules"

    def evaluate(self, config: WorkspaceConfig) -> list[Finding]:
        affected = []
        for r in config.automation_rules:
            if not r.enabled:
                continue
            for cond in r.conditions:
                prop = cond.get("conditionProperties", cond)
                prop_name = str(prop.get("propertyName", "")).lower()
                values = [str(v).lower() for v in prop.get("propertyValues", [])]
                if "updatedby" in prop_name or "updated by" in prop_name:
                    if any("365 defender" in v or "microsoft 365" in v for v in values):
                        affected.append(r.display_name)
                        break
        if not affected:
            return []
        return [Finding(
            id=self.id,
            title=self.title,
            category=self.category,
            severity=Severity.WARNING,
            description=(
                f"{len(affected)} automation rule(s) filter on "
                "'Updated by = Microsoft 365 Defender'. After onboarding, "
                "this value is replaced by 'Other'."
            ),
            impact=(
                f"Rules affected: {', '.join(affected)}. The condition "
                "will no longer match because the source label changes."
            ),
            remediation=(
                "1. Open each affected rule.\n"
                "2. Change the 'Updated by' value from "
                "'Microsoft 365 Defender' to 'Other'.\n"
                "3. Test that the rule fires as expected."
            ),
            doc_url=self.doc_url,
            affected_resources=affected,
        )]


class IncidentCreationRule(MigrationRule):
    id = "automation-incident-creation"
    title = "Active MicrosoftSecurityIncidentCreation rules"
    category = "Automation Rules"
    doc_url = f"{_BASE_DOC}#analytics-rules"

    def evaluate(self, config: WorkspaceConfig) -> list[Finding]:
        affected = [
            r.display_name for r in config.analytics_rules
            if r.enabled and r.kind == "MicrosoftSecurityIncidentCreation"
        ]
        if not affected:
            return []
        return [Finding(
            id=self.id,
            title=self.title,
            category=self.category,
            severity=Severity.CRITICAL,
            description=(
                f"{len(affected)} active MicrosoftSecurityIncidentCreation "
                "analytics rule(s) found. This rule type is not supported in "
                "Defender XDR and will be automatically disabled."
            ),
            impact=(
                f"Rules affected: {', '.join(affected)}. Incident creation "
                "from Microsoft security products will be handled natively "
                "by Defender XDR. Any custom filters in these rules will "
                "be lost."
            ),
            remediation=(
                "1. Document any custom filters configured in these rules.\n"
                "2. After onboarding, use Defender XDR alert-tuning to "
                "replicate any filtering logic.\n"
                "3. Acknowledge that these rules will be disabled "
                "automatically."
            ),
            doc_url=self.doc_url,
            affected_resources=affected,
        )]


class PlaybookManualRunRule(MigrationRule):
    id = "playbook-manual-trigger"
    title = "Playbooks with manual trigger on alerts/entities"
    category = "Automation Rules"
    doc_url = f"{_BASE_DOC}#automation-rules"

    def evaluate(self, config: WorkspaceConfig) -> list[Finding]:
        affected = [
            p.name for p in config.playbooks
            if p.enabled and p.trigger_type in ("alert", "entity")
        ]
        if not affected:
            return []
        return [Finding(
            id=self.id,
            title=self.title,
            category=self.category,
            severity=Severity.WARNING,
            description=(
                f"{len(affected)} playbook(s) use an alert or entity "
                "manual trigger. Manual-run playbooks on alerts and entities "
                "have limited support in the Defender XDR portal."
            ),
            impact=(
                f"Playbooks affected: {', '.join(affected)}. You may not "
                "be able to run these playbooks manually from the Defender "
                "XDR UI on alerts or entities."
            ),
            remediation=(
                "1. Where possible, convert manual-trigger playbooks to "
                "incident-trigger playbooks.\n"
                "2. Alternatively, trigger them via automation rules "
                "instead of manual execution.\n"
                "3. Test playbook execution in the Defender portal after "
                "onboarding."
            ),
            doc_url=self.doc_url,
            affected_resources=affected,
        )]


class PlaybookLatencyRule(MigrationRule):
    id = "playbook-latency"
    title = "Playbook trigger latency after onboarding"
    category = "Automation Rules"
    doc_url = f"{_BASE_DOC}#automation-rules"

    def evaluate(self, config: WorkspaceConfig) -> list[Finding]:
        return [Finding(
            id=self.id,
            title=self.title,
            category=self.category,
            severity=Severity.INFO,
            description=(
                "After onboarding to Defender XDR, playbook triggers may "
                "experience a delay of 5-10 minutes for incidents created "
                "by Defender XDR correlation."
            ),
            impact=(
                "Incident-triggered playbooks may run later than expected. "
                "This affects time-sensitive response workflows."
            ),
            remediation=(
                "1. Review any playbooks with strict SLA requirements.\n"
                "2. Adjust timeout and retry settings if needed.\n"
                "3. Monitor playbook execution times after onboarding."
            ),
            doc_url=self.doc_url,
        )]
