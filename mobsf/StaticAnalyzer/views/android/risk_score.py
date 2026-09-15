# -*- coding: utf_8 -*-
"""Security Risk Score Calculator (SentinelX Feature #1)."""

SEVERITY_WEIGHTS = {
    'high': 10,
    'dangerous': 10,
    'warning': 5,
    'medium': 5,
    'info': 1,
    'low': 1,
    'good': 0,
    'secure': 0,
}

SEVERITY_MAX_CAP = {
    'high': 40,
    'warning': 30,
    'info': 10,
}


def _count_severities(items, key='severity'):
    """Count occurrences of each severity string in a list of dicts."""
    counts = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        sev = str(item.get(key, 'info')).lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _count_code_analysis_severities(code_analysis):
    """code_analysis is a dict keyed by rule name -> {'metadata': {...}}."""
    counts = {}
    if not isinstance(code_analysis, dict):
        return counts
    for _, finding in code_analysis.items():
        if not isinstance(finding, dict):
            continue
        meta = finding.get('metadata', {})
        sev = str(meta.get('severity', 'info')).lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _count_binary_analysis_severities(binary_analysis):
    """binary_analysis is a list of dicts, each with multiple nested checks."""
    counts = {}
    for entry in binary_analysis:
        if not isinstance(entry, dict):
            continue
        for k, v in entry.items():
            if k == 'name' or not isinstance(v, dict):
                continue
            sev = str(v.get('severity', 'info')).lower()
            counts[sev] = counts.get(sev, 0) + 1
    return counts


def calculate_risk_score(context):
    """
    Calculate a 0-100 security risk score from MobSF analysis context.
    100 = perfectly secure, 0 = maximally risky.
    Returns dict: {score, grade, high, warning, info, total_findings}
    """
    manifest = context.get('manifest_analysis', [])
    if isinstance(manifest, dict):
        manifest = manifest.get('manifest_findings', [])

    code = context.get('code_analysis', {})
    binary = context.get('binary_analysis', [])

    m_counts = _count_severities(manifest)
    c_counts = _count_code_analysis_severities(code)
    b_counts = _count_binary_analysis_severities(binary)

    total = {}
    for counts in (m_counts, c_counts, b_counts):
        for sev, n in counts.items():
            total[sev] = total.get(sev, 0) + n

    high = total.get('high', 0) + total.get('dangerous', 0)
    warning = total.get('warning', 0) + total.get('medium', 0)
    info = total.get('info', 0) + total.get('low', 0)

    penalty = 0
    penalty += min(high * SEVERITY_WEIGHTS['high'], SEVERITY_MAX_CAP['high'])
    penalty += min(warning * SEVERITY_WEIGHTS['warning'], SEVERITY_MAX_CAP['warning'])
    penalty += min(info * SEVERITY_WEIGHTS['info'], SEVERITY_MAX_CAP['info'])

    score = max(0, 100 - penalty)

    if score >= 90:
        grade = 'A'
    elif score >= 75:
        grade = 'B'
    elif score >= 60:
        grade = 'C'
    elif score >= 40:
        grade = 'D'
    else:
        grade = 'F'

    return {
        'score': int(score),
        'grade': grade,
        'high': high,
        'warning': warning,
        'info': info,
        'total_findings': high + warning + info,
    }