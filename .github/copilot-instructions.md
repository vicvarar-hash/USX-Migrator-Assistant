# Copilot Instructions — USX Migrator Assistant

## Project Overview
This is a Python Flask web app that helps customers migrate Microsoft Sentinel from the Azure Portal to the Defender (USX) portal. It auto-discovers workspace configuration via Azure SDKs and generates a personalized migration assessment report with `az` CLI remediation commands.

## Architecture
- **Flask backend** with Jinja2 templates and Bootstrap 5 frontend
- **Discovery layer** (`app/discovery/`) — uses Azure SDKs to fetch workspace config
- **Rules engine** (`app/rules/`) — 23+ migration checks, each as a `MigrationRule` subclass
- **Remediation** (`app/remediation/`) — generates `az` CLI commands per finding
- **History** (`app/history.py`) — saves/compares assessment runs in `~/.usx-migrator/`

## Key Conventions
- All Azure SDK calls must be wrapped in try/except with graceful degradation
- The app never auto-executes commands against Azure — it only generates commands for the user
- Models are in `app/models.py` using Python dataclasses
- Use `Severity` enum: CRITICAL, WARNING, INFO, OK
- Each `Finding` must include: id, title, category, severity, description, impact, remediation, doc_url
- Migration rules reference the MS Learn guide: https://learn.microsoft.com/azure/sentinel/move-to-defender

## Adding New Migration Rules
1. Create a class inheriting from `MigrationRule` in the appropriate `app/rules/` module
2. Implement `evaluate(self, config: WorkspaceConfig) -> list[Finding]`
3. Register it in `app/rules/__init__.py` → `get_all_rules()`
4. Add the corresponding `az` command mapping in `app/remediation/command_generator.py`

## Running
```bash
az login
python run.py
# Open http://localhost:5000
```

## Testing
```bash
python -m pytest tests/
```
