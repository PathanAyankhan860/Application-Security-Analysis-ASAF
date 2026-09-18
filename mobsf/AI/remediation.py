"""Remediation helpers for ASAF AI."""

from mobsf.AI.analyzer import ASAFAnalyzer


def generate_remediation(checksum, category='', index='', title=''):
    """Generate AI remediation guidance for one ASAF finding."""
    return ASAFAnalyzer().remediation(checksum, category, index, title)
