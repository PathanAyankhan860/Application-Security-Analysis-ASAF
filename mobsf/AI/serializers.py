"""Serialize ASAF scan data for AI analysis.

The helpers in this module intentionally extract a small, structured subset of
existing ASAF scan results. They do not run detection logic and they never modify
scanner findings.
"""
import json
from ast import literal_eval

from django.conf import settings

from mobsf.MobSF.utils import python_dict, python_list
from mobsf.StaticAnalyzer.models import (
    RecentScansDB,
    StaticAnalyzerAndroid,
    StaticAnalyzerIOS,
    StaticAnalyzerWindows,
)
from mobsf.StaticAnalyzer.views.android.db_interaction import (
    get_context_from_db_entry as android_db_context,
)
from mobsf.StaticAnalyzer.views.ios.db_interaction import (
    get_context_from_db_entry as ios_db_context,
)
from mobsf.StaticAnalyzer.views.windows.db_interaction import (
    get_context_from_db_entry as windows_db_context,
)

INSUFFICIENT_EVIDENCE = 'Insufficient evidence in the scan results.'
AI_UNAVAILABLE = (
    'AI analysis is currently unavailable. The original ASAF security finding '
    'is still available.'
)
FINDING_FIELDS = (
    'manifest_analysis',
    'binary_analysis',
    'file_analysis',
    'android_api',
    'ios_api',
    'code_analysis',
    'niap_analysis',
    'network_security',
    'secrets',
    'ats_analysis',
    'macho_analysis',
    'dylib_analysis',
    'framework_analysis',
    'binary_warnings',
    'domains',
    'urls',
    'emails',
    'firebase_urls',
    'trackers',
)
SEVERITIES = ('critical', 'high', 'warning', 'medium', 'low', 'info')


def _limit(value, max_chars=None):
    max_chars = max_chars or getattr(settings, 'AI_MAX_EVIDENCE_CHARS', 4000)
    text = '' if value is None else str(value)
    if len(text) > max_chars:
        return f'{text[:max_chars]}... [truncated]'
    return text


def _safe_parse(value):
    if isinstance(value, (dict, list, tuple)):
        return value
    if value in (None, ''):
        return value
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except Exception:
        try:
            return literal_eval(value)
        except Exception:
            return value


def _first_present(data, names):
    for name in names:
        if isinstance(data, dict) and data.get(name) not in (None, '', [], {}):
            return data.get(name)
    return ''


def _severity_from(data):
    if isinstance(data, dict):
        sev = _first_present(data, (
            'severity', 'Severity', 'level', 'Level', 'risk', 'Risk',
        ))
        if sev:
            return str(sev)
        cvss = _first_present(data, ('cvss', 'cvssv2', 'cvss_score'))
        if cvss:
            return f'CVSS {cvss}'
    return ''


def _title_from(data, category):
    if isinstance(data, dict):
        title = _first_present(data, (
            'title', 'name', 'rule', 'rule_id', 'issue', 'check', 'desc',
            'description', 'message', 'warning',
        ))
        if title:
            return _limit(title, 300)
    if isinstance(data, str):
        return _limit(data, 300)
    return category.replace('_', ' ').title()


def _file_from(data):
    if not isinstance(data, dict):
        return ''
    return _limit(_first_present(data, (
        'file', 'files', 'path', 'component', 'class', 'activity', 'service',
        'receiver', 'provider',
    )), 1000)


def _line_from(data):
    if not isinstance(data, dict):
        return ''
    return _limit(_first_present(data, ('line', 'line_number', 'lines')), 200)


def _description_from(data):
    if isinstance(data, dict):
        return _limit(_first_present(data, (
            'description', 'desc', 'message', 'info', 'details', 'summary',
        )))
    return _limit(data)


def _evidence_from(data):
    if isinstance(data, dict):
        evidence = _first_present(data, (
            'evidence', 'match', 'matches', 'files', 'file', 'component',
            'details', 'metadata', 'value', 'values', 'url', 'domain',
        ))
        if evidence:
            return _limit(evidence)
    if data not in (None, '', [], {}):
        return _limit(data)
    return ''


def normalize_finding(category, index, raw_finding):
    """Normalize one ASAF finding without changing scanner evidence."""
    data = _safe_parse(raw_finding)
    finding = {
        'category': category,
        'index': str(index),
        'title': _title_from(data, category),
        'severity': _severity_from(data),
        'description': _description_from(data),
        'file': _file_from(data),
        'line': _line_from(data),
        'evidence': _evidence_from(data),
        'raw': _limit(data),
    }
    if not finding['evidence'] and not finding['description']:
        finding['limitations'] = [INSUFFICIENT_EVIDENCE]
    else:
        finding['limitations'] = []
    return finding


def _walk_findings(category, value, prefix=''):
    value = _safe_parse(value)
    if value in (None, '', [], {}):
        return []
    findings = []
    if isinstance(value, list):
        for index, item in enumerate(value):
            if isinstance(item, (dict, str)):
                findings.append(normalize_finding(
                    category, f'{prefix}{index}', item))
            else:
                findings.extend(_walk_findings(category, item, f'{prefix}{index}.'))
    elif isinstance(value, dict):
        for key, item in value.items():
            child_index = f'{prefix}{key}'
            if isinstance(item, list):
                for idx, child in enumerate(item):
                    findings.append(normalize_finding(
                        category, f'{child_index}.{idx}', child))
            elif isinstance(item, dict):
                if any(name in item for name in (
                    'title', 'name', 'desc', 'description', 'severity',
                    'files', 'file', 'evidence', 'match',
                )):
                    findings.append(normalize_finding(category, child_index, item))
                else:
                    findings.extend(_walk_findings(
                        category, item, f'{child_index}.'))
            else:
                findings.append(normalize_finding(
                    category, child_index, {key: item, 'evidence': item}))
    else:
        findings.append(normalize_finding(category, prefix or '0', value))
    return findings


def _application_from_context(context, platform):
    return {
        'name': context.get('app_name') or context.get('file_name') or '',
        'package': context.get('package_name') or context.get('bundle_id')
        or context.get('publisher_name') or '',
        'version': context.get('version_name') or context.get('app_version') or '',
        'platform': platform,
        'scan_date': _limit(context.get('timestamp') or ''),
        'md5': context.get('md5') or '',
    }


def get_scan_context(checksum):
    """Return normalized scan context for an existing ASAF scan."""
    android_db = StaticAnalyzerAndroid.objects.filter(MD5=checksum)
    ios_db = StaticAnalyzerIOS.objects.filter(MD5=checksum)
    windows_db = StaticAnalyzerWindows.objects.filter(MD5=checksum)
    platform = ''
    context = None
    if android_db.exists():
        platform = 'Android'
        context = android_db_context(android_db)
    elif ios_db.exists():
        platform = 'iOS'
        context = ios_db_context(ios_db)
    elif windows_db.exists():
        platform = 'Windows'
        context = windows_db_context(windows_db)
    if not context:
        return None
    try:
        recent = RecentScansDB.objects.get(MD5=checksum)
        context['timestamp'] = recent.TIMESTAMP
        context['package_name'] = recent.PACKAGE_NAME
        context['version_name'] = recent.VERSION_NAME
    except RecentScansDB.DoesNotExist:
        pass
    findings = []
    for field in FINDING_FIELDS:
        findings.extend(_walk_findings(field, context.get(field)))
    return {
        'application': _application_from_context(context, platform),
        'findings': findings,
        'raw_context_keys': sorted(context.keys()),
    }


def find_finding(scan_data, category='', index='', title=''):
    """Find a normalized finding by category/index or title."""
    if not scan_data:
        return None
    findings = scan_data.get('findings', [])
    for finding in findings:
        if category and finding.get('category') != category:
            continue
        if index != '' and str(finding.get('index')) != str(index):
            continue
        if title and finding.get('title') != title:
            continue
        return finding
    return None


def severity_summary(findings):
    """Count findings by ASAF severity without changing original values."""
    summary = {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'informational': 0,
        'unknown': 0,
    }
    for finding in findings:
        severity = str(finding.get('severity', '')).strip().lower()
        if 'critical' in severity:
            summary['critical'] += 1
        elif 'high' in severity:
            summary['high'] += 1
        elif 'medium' in severity or 'warning' in severity:
            summary['medium'] += 1
        elif 'low' in severity:
            summary['low'] += 1
        elif 'info' in severity:
            summary['informational'] += 1
        else:
            summary['unknown'] += 1
    return summary


def compact_scan(scan_data):
    """Prepare bounded scan data for AI summary/report prompts."""
    if not scan_data:
        return None
    max_findings = getattr(settings, 'AI_MAX_FINDINGS', 50)
    findings = scan_data.get('findings', [])[:max_findings]
    return {
        'application': scan_data.get('application', {}),
        'total_findings': len(scan_data.get('findings', [])),
        'severity_summary': severity_summary(scan_data.get('findings', [])),
        'findings': findings,
    }
