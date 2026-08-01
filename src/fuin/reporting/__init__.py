"""Read-only views of an APK: what would be encrypted, and what a pack changed."""

from fuin.reporting.analyze import analyze_targets
from fuin.reporting.report import fmt_size, format_report, generate_report

__all__ = ["analyze_targets", "fmt_size", "format_report", "generate_report"]
