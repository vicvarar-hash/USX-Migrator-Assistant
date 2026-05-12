"""Base class for all migration assessment rules."""
from __future__ import annotations

from ..models import Finding, WorkspaceConfig


class MigrationRule:
    """A single migration check that evaluates a WorkspaceConfig."""

    id: str = ""
    title: str = ""
    category: str = ""
    doc_url: str = ""

    def evaluate(self, config: WorkspaceConfig) -> list[Finding]:
        """Return list of findings. Empty list = no issues found."""
        raise NotImplementedError
