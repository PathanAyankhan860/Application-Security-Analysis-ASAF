# -*- coding: utf_8 -*-
"""Vulnerability Priority Ranking (SentinelX Feature #12)."""

SEVERITY_ORDER = {
    'high': 0,
    'dangerous': 0,
    'warning': 1,
    'medium': 1,
    'info': 2,
    'low': 2,
    'good': 3,
    'secure': 3,
}


def _severity_rank(sev):
    return SEVERITY_ORDER.get(str(sev).lower(), 2)


def get_priority_findings(context, limit=25):
    """
    Build a unified, severity-ranked list of findings from
    manifest_analysis, code_analysis, and binary_analysis.
    Returns a list of dicts: [{title, severity, source, description}, ...]
    sorted High -> Warning -> Info.
    """
    findings = []

    # Manifest findings
    manifest = context.get('manifest_analysis', [])
    if isinstance(manifest, dict):
        manifest = manifest.get('manifest_findings', [])
    for item in manifest:
        if not isinstance(item, dict):
            continue
        sev = str(item.get('severity', 'info')).lower()
        if sev in ('good', 'secure'):
            continue
        findings.append({
            'title': item.get('title', item.get('name', 'Manifest Issue')),
            'severity': sev,
            'source': 'Manifest',
            'description': item.get('description', ''),
        })

    # Code analysis findings
    code = context.get('code_analysis', {})
    if isinstance(code, dict):
        code_findings = code.get('findings', code)
        if isinstance(code_findings, dict):
            for _, finding in code_findings.items():
                if not isinstance(finding, dict):
                    continue
                meta = finding.get('metadata', {})
                sev = str(meta.get('severity', 'info')).lower()
                if sev in ('good', 'secure'):
                    continue
                findings.append({
                    'title': meta.get('description', 'Code Issue'),
                    'severity': sev,
                    'source': 'Code',
                    'description': meta.get('cwe', ''),
                })

    # Binary analysis findings
    binary = context.get('binary_analysis', [])
    for entry in binary:
        if not isinstance(entry, dict):
            continue
        so_name = entry.get('name', 'Shared Object')
        for k, v in entry.items():
            if k == 'name' or not isinstance(v, dict):
                continue
            sev = str(v.get('severity', 'info')).lower()
            if sev in ('good', 'secure'):
                continue
            findings.append({
                'title': f'{k.upper()} check on {so_name}',
                'severity': sev,
                'source': 'Binary',
                'description': v.get('description', ''),
            })

    findings.sort(key=lambda f: _severity_rank(f['severity']))
    return findings[:limit]