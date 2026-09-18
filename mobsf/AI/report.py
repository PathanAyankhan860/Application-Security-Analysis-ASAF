"""Report helpers for ASAF AI."""

from mobsf.AI.analyzer import ASAFAnalyzer


def generate_ai_report(checksum):
    """Generate an AI-enhanced security report for an ASAF scan."""
    return ASAFAnalyzer().report(checksum)
