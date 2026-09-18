"""Prompt builders for ASAF AI security analysis."""
import json

SYSTEM_GUARDRAILS = """
You are ASAF AI, a security intelligence layer for ASAF scan results.
ASAF scanners are the source of truth for detection and evidence.
Do not invent evidence, files, line numbers, severity, packages, or findings.
If the provided ASAF data lacks evidence, say exactly:
Insufficient evidence in the scan results.
Clearly label explanations as AI-generated context, not ASAF detection.
Do not provide destructive commands or instructions for attacking systems.
Return valid JSON only.
""".strip()


def _json(data):
    return json.dumps(data, indent=2, sort_keys=True, default=str)


def finding_prompt(application, finding):
    return f"""
{SYSTEM_GUARDRAILS}

Task: Explain this ASAF security finding for a developer.

Required JSON keys:
success, ai_generated, finding, severity, explanation, evidence,
why_it_matters, impact, affected_component, investigation_steps,
remediation, limitations

ASAF application data:
{_json(application)}

ASAF finding data:
{_json(finding)}
""".strip()


def summary_prompt(scan_data):
    return f"""
{SYSTEM_GUARDRAILS}

Task: Generate an AI security summary for this ASAF scan.
Preserve ASAF severity values. Do not reclassify severity.

Required JSON keys:
success, ai_generated, total_findings, severity_summary,
important_categories, main_investigation_areas, common_patterns,
potentially_related_findings, recommended_remediation_areas, summary,
limitations

ASAF scan data:
{_json(scan_data)}
""".strip()


def ask_prompt(scan_data, question):
    return f"""
{SYSTEM_GUARDRAILS}

Task: Answer the user's question using only this ASAF scan data.
If the answer is not present in the scan data, say exactly:
Insufficient evidence in the scan results.

Required JSON keys:
success, ai_generated, question, answer, supporting_evidence,
limitations

User question:
{question}

ASAF scan data:
{_json(scan_data)}
""".strip()


def remediation_prompt(application, finding):
    return f"""
{SYSTEM_GUARDRAILS}

Task: Generate safe, developer-oriented remediation guidance for this ASAF finding.
Include recommended fix, why it works, secure development practices,
and what to verify after fixing. Include example code/config only when suitable.

Required JSON keys:
success, ai_generated, finding, severity, recommended_fix,
why_fix_works, secure_practices, verification_steps, example,
limitations

ASAF application data:
{_json(application)}

ASAF finding data:
{_json(finding)}
""".strip()


def report_prompt(scan_data):
    return f"""
{SYSTEM_GUARDRAILS}

Task: Generate an AI-enhanced application security report from ASAF data.
Use this structure:
APPLICATION SECURITY REPORT
Application Information
ASAF SCAN SUMMARY
AI SECURITY SUMMARY
KEY FINDINGS
RECOMMENDED ACTIONS

Required JSON keys:
success, ai_generated, title, application_information,
asaf_scan_summary, ai_security_summary, key_findings, recommended_actions,
limitations

ASAF scan data:
{_json(scan_data)}
""".strip()
