"""AI analysis workflows for ASAF scan results."""

from mobsf.AI.ai_engine import AIEngine
from mobsf.AI.prompts import (
    ask_prompt,
    finding_prompt,
    remediation_prompt,
    report_prompt,
    summary_prompt,
)
from mobsf.AI.serializers import (
    INSUFFICIENT_EVIDENCE,
    compact_scan,
    find_finding,
    get_scan_context,
    severity_summary,
)


def _fallback_for_finding(finding):
    return {
        'finding': finding.get('title', ''),
        'severity': finding.get('severity', ''),
        'evidence': finding.get('evidence') or INSUFFICIENT_EVIDENCE,
    }


class ASAFAnalyzer:
    """High-level AI operations using existing ASAF scan evidence."""

    def __init__(self, engine=None):
        self.engine = engine or AIEngine()

    def _scan_or_error(self, checksum):
        scan_data = get_scan_context(checksum)
        if not scan_data:
            return None, {
                'success': False,
                'ai_generated': False,
                'error': 'Scan results not found.',
            }
        return scan_data, None

    def analyze_finding(self, checksum, category='', index='', title=''):
        scan_data, error = self._scan_or_error(checksum)
        if error:
            return error
        finding = find_finding(scan_data, category, index, title)
        if not finding:
            return {
                'success': False,
                'ai_generated': True,
                'error': INSUFFICIENT_EVIDENCE,
                'limitations': [INSUFFICIENT_EVIDENCE],
            }
        if finding.get('limitations'):
            return {
                'success': True,
                'ai_generated': True,
                **_fallback_for_finding(finding),
                'explanation': INSUFFICIENT_EVIDENCE,
                'impact': INSUFFICIENT_EVIDENCE,
                'remediation': INSUFFICIENT_EVIDENCE,
                'limitations': finding['limitations'],
            }
        return self.engine.generate_json(
            finding_prompt(scan_data['application'], finding),
            _fallback_for_finding(finding),
        )

    def scan_summary(self, checksum):
        scan_data, error = self._scan_or_error(checksum)
        if error:
            return error
        compact = compact_scan(scan_data)
        fallback = {
            'total_findings': compact['total_findings'],
            'severity_summary': compact['severity_summary'],
        }
        return self.engine.generate_json(summary_prompt(compact), fallback)

    def ask(self, checksum, question):
        scan_data, error = self._scan_or_error(checksum)
        if error:
            return error
        compact = compact_scan(scan_data)
        return self.engine.generate_json(
            ask_prompt(compact, question),
            {'question': question, 'answer': INSUFFICIENT_EVIDENCE},
        )

    def remediation(self, checksum, category='', index='', title=''):
        scan_data, error = self._scan_or_error(checksum)
        if error:
            return error
        finding = find_finding(scan_data, category, index, title)
        if not finding:
            return {
                'success': False,
                'ai_generated': True,
                'error': INSUFFICIENT_EVIDENCE,
                'limitations': [INSUFFICIENT_EVIDENCE],
            }
        return self.engine.generate_json(
            remediation_prompt(scan_data['application'], finding),
            _fallback_for_finding(finding),
        )

    def report(self, checksum):
        scan_data, error = self._scan_or_error(checksum)
        if error:
            return error
        compact = compact_scan(scan_data)
        fallback = {
            'title': 'APPLICATION SECURITY REPORT',
            'application_information': compact['application'],
            'asaf_scan_summary': severity_summary(scan_data.get('findings', [])),
        }
        return self.engine.generate_json(report_prompt(compact), fallback)
