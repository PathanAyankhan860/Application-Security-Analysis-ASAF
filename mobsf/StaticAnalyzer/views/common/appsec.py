# -*- coding: utf_8 -*-
"""
Shared Functions.

AppSec Dashboard
"""

import json
import logging

from django.shortcuts import render

from mobsf.MobSF import settings
from mobsf.MobSF.utils import (
    is_md5,
    print_n_send_error_response,
)
from mobsf.StaticAnalyzer.models import (
    StaticAnalyzerAndroid,
    StaticAnalyzerIOS,
    StaticAnalyzerWindows,
)
from mobsf.StaticAnalyzer.views.android.db_interaction import (
    get_context_from_db_entry as adb,
)
from mobsf.StaticAnalyzer.views.ios.db_interaction import (
    get_context_from_db_entry as idb,
)
from mobsf.MobSF.views.authentication import (
    login_required,
)

logger = logging.getLogger(__name__)


def _safe_json(value, default=None):
    """Safely convert a database JSON/text value to Python."""
    if default is None:
        default = {}

    if value is None:
        return default

    if isinstance(value, (dict, list)):
        return value

    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8", errors="replace")
        except Exception:
            return default

    if isinstance(value, str):
        value = value.strip()

        if not value:
            return default

        try:
            return json.loads(value)
        except (TypeError, ValueError, json.JSONDecodeError):
            return default

    return default


def _safe_int(value, default=0):
    """Convert a value to int safely."""
    try:
        if isinstance(value, bool):
            return int(value)
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _severity(value):
    """Normalize severity values."""
    if value is None:
        return "info"

    sev = str(value).strip().lower()

    aliases = {
        "critical": "high",
        "crit": "high",
        "error": "high",
        "danger": "high",
        "dangerous": "high",
        "high": "high",
        "warning": "warning",
        "warn": "warning",
        "medium": "warning",
        "moderate": "warning",
        "low": "info",
        "info": "info",
        "informational": "info",
        "notice": "info",
        "good": "secure",
        "secure": "secure",
        "safe": "secure",
        "pass": "secure",
        "passed": "secure",
    }

    return aliases.get(sev, "info")


def _finding_title(finding):
    """Extract a finding title from an analyzer finding."""
    if not isinstance(finding, dict):
        return str(finding)

    for key in (
        "title",
        "issue",
        "name",
        "rule",
        "finding",
        "check",
        "id",
    ):
        value = finding.get(key)

        if value:
            return str(value)

    return "Windows PE security finding"


def _finding_description(finding):
    """Extract a finding description."""
    if not isinstance(finding, dict):
        return str(finding)

    parts = []

    for key in (
        "description",
        "details",
        "detail",
        "detailed_desc",
        "message",
        "reason",
        "recommendation",
    ):
        value = finding.get(key)

        if value:
            if isinstance(value, (dict, list)):
                parts.append(json.dumps(value, indent=2, ensure_ascii=False))
            else:
                text = str(value).strip()

                if text and text not in parts:
                    parts.append(text)

    if not parts:
        extra = {}

        for key, value in finding.items():
            if key not in {
                "title",
                "issue",
                "name",
                "rule",
                "finding",
                "check",
                "id",
                "severity",
                "level",
            }:
                extra[key] = value

        if extra:
            return json.dumps(
                extra,
                indent=2,
                ensure_ascii=False,
                default=str,
            )

    return "\n\n".join(parts) if parts else "Static PE analysis finding."


def _extract_windows_findings(analysis, warnings):
    """Extract findings from the EXE analyzer output."""
    findings = []

    candidate_lists = []

    if isinstance(analysis, dict):
        for key in (
            "findings",
            "security_findings",
            "issues",
            "warnings",
            "checks",
            "results",
        ):
            value = analysis.get(key)

            if isinstance(value, list):
                candidate_lists.append(value)

            elif isinstance(value, dict):
                for item_key, item_value in value.items():
                    if isinstance(item_value, dict):
                        item = dict(item_value)

                        if not item.get("title"):
                            item["title"] = str(item_key)

                        candidate_lists.append([item])

                    elif isinstance(item_value, list):
                        candidate_lists.append(item_value)

    if isinstance(warnings, list):
        candidate_lists.append(warnings)

    elif isinstance(warnings, dict):
        for key, value in warnings.items():
            if isinstance(value, list):
                candidate_lists.append(value)

            elif isinstance(value, dict):
                item = dict(value)

                if not item.get("title"):
                    item["title"] = str(key)

                candidate_lists.append([item])

    seen = set()

    for candidate_list in candidate_lists:
        for finding in candidate_list:
            if isinstance(finding, str):
                finding = {
                    "title": finding,
                    "description": finding,
                    "severity": "info",
                }

            if not isinstance(finding, dict):
                continue

            title = _finding_title(finding)
            description = _finding_description(finding)
            severity = _severity(
                finding.get(
                    "severity",
                    finding.get("level", finding.get("risk")),
                )
            )

            key = (
                severity,
                title.strip().lower(),
                description.strip().lower(),
            )

            if key in seen:
                continue

            seen.add(key)

            findings.append({
                "title": title,
                "description": description,
                "severity": severity,
                "section": "windows",
            })

    return findings


def _add_secure_checks(findings, analysis):
    """Add positive PE security checks where the analyzer provides data."""
    if not isinstance(analysis, dict):
        return

    security = analysis.get("security")

    if isinstance(security, dict):
        for key, value in security.items():
            if value is True:
                title = str(key).replace("_", " ").strip().title()

                findings["secure"].append({
                    "title": title,
                    "description": (
                        f"{title} is enabled according to the "
                        "static PE analysis."
                    ),
                    "section": "windows-security",
                })


def _calculate_windows_score(findings):
    """Calculate a score if the analyzer did not provide one."""
    high = len(findings.get("high", []))
    warning = len(findings.get("warning", []))
    info = len(findings.get("info", []))
    secure = len(findings.get("secure", []))

    total = high + warning + info + secure

    if total == 0:
        return 0

    score = 100 - (
        (
            (high * 1.0)
            + (warning * 0.5)
            + (info * 0.05)
            - (secure * 0.2)
        )
        / total
        * 100
    )

    score = int(round(score))

    if score < 0:
        score = 0

    if score > 100:
        score = 100

    return score


def _windows_risk(score, analysis):
    """Determine EXE risk label."""
    if isinstance(analysis, dict):
        risk = analysis.get("risk")

        if risk:
            return str(risk).upper()

    score = _safe_int(score, 0)

    if score >= 90:
        return "LOW"

    if score >= 70:
        return "MEDIUM"

    if score >= 40:
        return "HIGH"

    return "CRITICAL"


def get_windows_dashboard(context):
    """
    Generate the AppSec scorecard for Windows PE files.

    This is static PE analysis only. The uploaded executable is never
    executed by this dashboard.
    """
    findings = {
        "high": [],
        "warning": [],
        "info": [],
        "secure": [],
        "hotspot": [],
        "total_trackers": None,
        "trackers": 0,
    }

    if context is None:
        return findings

    if isinstance(context, (list, tuple)):
        if not context:
            return findings

        windows_db = context[0]
    else:
        windows_db = context

    if windows_db is None:
        return findings

    analysis = _safe_json(
        getattr(windows_db, "BINARY_ANALYSIS", None),
        {},
    )

    warnings = _safe_json(
        getattr(windows_db, "BINARY_WARNINGS", None),
        [],
    )

    strings = _safe_json(
        getattr(windows_db, "STRINGS", None),
        [],
    )

    files_data = _safe_json(
        getattr(windows_db, "FILES", None),
        [],
    )

    extracted_findings = _extract_windows_findings(
        analysis,
        warnings,
    )

    for finding in extracted_findings:
        severity = finding["severity"]

        if severity not in findings:
            severity = "info"

        findings[severity].append({
            "title": finding["title"],
            "description": finding["description"],
            "section": finding["section"],
        })

    # ------------------------------------------------------------------
    # PE security features
    # ------------------------------------------------------------------
    security_data = {}

    if isinstance(analysis, dict):
        security_data = analysis.get("security", {})

        if not isinstance(security_data, dict):
            security_data = {}

    security_checks = (
        ("aslr", "ASLR"),
        ("dep", "DEP / NX"),
        ("cfg", "Control Flow Guard"),
    )

    for key, label in security_checks:
        if key not in security_data:
            continue

        enabled = security_data.get(key)

        if isinstance(enabled, str):
            enabled = enabled.strip().lower() in {
                "true",
                "yes",
                "enabled",
                "on",
                "1",
            }

        if enabled is True:
            findings["secure"].append({
                "title": f"{label} is enabled",
                "description": (
                    f"{label} is enabled according to static PE "
                    "security analysis."
                ),
                "section": "windows-security",
            })
        elif enabled is False:
            findings["warning"].append({
                "title": f"{label} is not enabled",
                "description": (
                    f"{label} does not appear to be enabled. "
                    "This can reduce the binary's exploit mitigations."
                ),
                "section": "windows-security",
            })

    # ------------------------------------------------------------------
    # Architecture
    # ------------------------------------------------------------------
    architecture = getattr(
        windows_db,
        "ARCHITECTURE",
        "",
    )

    if architecture:
        findings["info"].append({
            "title": f"PE architecture: {architecture}",
            "description": (
                "The executable architecture was identified during "
                "static PE analysis."
            ),
            "section": "headers",
        })

    # ------------------------------------------------------------------
    # Compiler
    # ------------------------------------------------------------------
    compiler = getattr(
        windows_db,
        "COMPILER_VERSION",
        "",
    )

    if compiler:
        findings["info"].append({
            "title": f"Compiler: {compiler}",
            "description": (
                "Compiler information identified from the PE metadata "
                "and static analysis."
            ),
            "section": "compiler",
        })

    # ------------------------------------------------------------------
    # Strings
    # ------------------------------------------------------------------
    string_count = 0

    if isinstance(strings, list):
        string_count = len(strings)

    elif isinstance(strings, dict):
        string_count = sum(
            len(value) if isinstance(value, list) else 1
            for value in strings.values()
        )

    if string_count:
        findings["info"].append({
            "title": f"Extracted {string_count} strings",
            "description": (
                "ASCII and/or UTF-16 strings were extracted from the "
                "Windows PE during static analysis."
            ),
            "section": "strings",
        })

    # ------------------------------------------------------------------
    # Files / PE sections
    # ------------------------------------------------------------------
    file_count = 0

    if isinstance(files_data, list):
        file_count = len(files_data)

    elif isinstance(files_data, dict):
        file_count = len(files_data)

    if file_count:
        findings["info"].append({
            "title": f"PE analysis contains {file_count} file item(s)",
            "description": (
                "Static PE analysis information was collected for the "
                "uploaded Windows binary."
            ),
            "section": "binary",
        })

    # ------------------------------------------------------------------
    # Score
    # ------------------------------------------------------------------
    analyzer_score = None

    if isinstance(analysis, dict):
        for key in (
            "score",
            "security_score",
            "risk_score",
        ):
            if key in analysis:
                value = analysis.get(key)

                try:
                    analyzer_score = float(value)
                    break
                except (TypeError, ValueError):
                    pass

    if analyzer_score is None:
        analyzer_score = _calculate_windows_score(findings)

    analyzer_score = max(
        0,
        min(100, int(round(analyzer_score))),
    )

    risk = _windows_risk(
        analyzer_score,
        analysis,
    )

    # ------------------------------------------------------------------
    # Basic metadata expected by the frontend
    # ------------------------------------------------------------------
    findings["security_score"] = analyzer_score

    findings["score"] = analyzer_score

    findings["risk"] = risk

    findings["app_name"] = (
        getattr(windows_db, "APP_NAME", "")
        or getattr(windows_db, "FILE_NAME", "")
        or ""
    )

    findings["file_name"] = (
        getattr(windows_db, "FILE_NAME", "")
        or ""
    )

    findings["hash"] = (
        getattr(windows_db, "MD5", "")
        or ""
    )

    findings["md5"] = findings["hash"]

    findings["sha1"] = (
        getattr(windows_db, "SHA1", "")
        or ""
    )

    findings["sha256"] = (
        getattr(windows_db, "SHA256", "")
        or ""
    )

    findings["architecture"] = (
        architecture or ""
    )

    findings["compiler_version"] = (
        compiler or ""
    )

    findings["version_name"] = (
        getattr(windows_db, "APP_VERSION", "")
        or ""
    )

    findings["publisher_name"] = (
        getattr(windows_db, "PUBLISHER_NAME", "")
        or ""
    )

    findings["size"] = (
        getattr(windows_db, "SIZE", "")
        or ""
    )

    findings["static_only"] = True

    findings["execution_performed"] = False

    findings["analysis_type"] = "Windows PE Static Analysis"

    findings["platform"] = "Windows"

    findings["file_type"] = "EXE"

    findings["risk_level"] = risk

    findings["high_count"] = len(findings["high"])

    findings["warning_count"] = len(findings["warning"])

    findings["info_count"] = len(findings["info"])

    findings["secure_count"] = len(findings["secure"])

    findings["hotspot_count"] = len(findings["hotspot"])

    findings["total_findings"] = (
        len(findings["high"])
        + len(findings["warning"])
        + len(findings["info"])
        + len(findings["secure"])
        + len(findings["hotspot"])
    )

    return findings


def common_fields(findings, data):
    """Common Fields for Android and iOS."""

    # Code Analysis
    for cd in data["code_analysis"]["findings"].values():
        if cd["metadata"]["severity"] == "good":
            sev = "secure"
        else:
            sev = cd["metadata"]["severity"]

        desc = cd["metadata"]["description"]
        ref = cd["metadata"].get("ref", "")

        files_dict = cd.get("files", {})

        files_lines = [
            f"{file}, line(s) {lines}"
            for file, lines in files_dict.items()
        ]

        all_files_str = "\n".join(files_lines)

        if files_dict:
            fdesc = (
                f"{desc}\n"
                f"{ref}\n\n"
                f"Files:\n"
                f"{all_files_str}"
            )
        else:
            fdesc = f"{desc}\n{ref}"

        findings[sev].append({
            "title": cd["metadata"]["description"],
            "description": fdesc,
            "section": "code",
        })

    # Permissions
    dang_perms = []
    fmt_perm = ""

    for pm, meta in data["permissions"].items():
        status = meta["status"]
        description = meta.get("description")

        if status == "dangerous":
            info = meta.get("info")

            if not info:
                info = meta.get("reason")

            dang_perms.append(
                f"{pm} ({status}): "
                f"{info} - {description}"
            )

    if dang_perms:
        fmt_perm += "\n\n".join(dang_perms)

        findings["hotspot"].append({
            "title": (
                f"Found {len(dang_perms)} "
                "critical permission(s)"
            ),
            "description": (
                "Ensure that these permissions "
                "are required by the application.\n\n"
                f"{fmt_perm}"
            ),
            "section": "permissions",
        })

    # File Analysis
    cert_files = None
    cfp = []

    for fa in data.get("file_analysis", []):
        if isinstance(fa, str):
            continue

        if "Cert" in fa.get("finding", ""):
            cfp = fa["files"]
            break

        if "Cert" in fa.get("issue", ""):
            cert_files = fa["files"]
            break

    if cert_files:
        for f in cert_files:
            cfp.append(f["file_path"])

    if cfp:
        fcerts = "\n".join(cfp)

        findings["hotspot"].append({
            "title": (
                f"Found {len(cfp)} "
                "certificate/key file(s)"
            ),
            "description": (
                "Ensure that these files "
                "does not contain any "
                "private information or "
                "sensitive key materials.\n\n"
                f"{fcerts}"
            ),
            "section": "files",
        })

    # Malicious Domains
    for domain, value in data["domains"].items():
        if value["bad"] == "yes":
            findings["high"].append({
                "title": (
                    f"Malicious domain found - {domain}"
                ),
                "description": str(
                    value["geolocation"]
                ),
                "section": "domains",
            })

        if value.get("ofac") and value["ofac"] is True:
            country = ""

            if value["geolocation"].get("country_long"):
                country = value["geolocation"].get(
                    "country_long"
                )
            elif value["geolocation"].get("region"):
                country = value["geolocation"].get(
                    "region"
                )
            elif value["geolocation"].get("city"):
                country = value["geolocation"].get(
                    "city"
                )

            findings["hotspot"].append({
                "title": (
                    "App may communicate to a server "
                    f"({domain}) in OFAC sanctioned country "
                    f"({country})"
                ),
                "description": str(
                    value["geolocation"]
                ),
                "section": "domains",
            })

    # Firebase
    for fb in data["firebase_urls"]:
        findings[fb["severity"]].append({
            "title": fb["title"],
            "description": fb["description"],
            "section": "firebase",
        })

    # Trackers
    if "trackers" in data["trackers"]:
        findings["total_trackers"] = (
            data["trackers"]["total_trackers"]
        )

        t = len(data["trackers"]["trackers"])

        findings["trackers"] = t

        if t > 4:
            sev = (
                "hotspot"
                if settings.EFR_01 == "1"
                else "high"
            )

            findings[sev].append({
                "title": (
                    "Application contains Privacy Trackers"
                ),
                "description": (
                    f"This app has more than {t} privacy trackers."
                    " Trackers can track device or users and "
                    "are privacy concerns for end users."
                ),
                "section": "trackers",
            })

        elif t > 0:
            sev = (
                "hotspot"
                if settings.EFR_01 == "1"
                else "warning"
            )

            findings[sev].append({
                "title": (
                    "Application contains Privacy Trackers"
                ),
                "description": (
                    f"This app has {t} privacy trackers."
                    " Trackers can track device or users and "
                    "are privacy concerns for end users."
                ),
                "section": "trackers",
            })

        else:
            findings["secure"].append({
                "title": (
                    "This application has no privacy trackers"
                ),
                "description": (
                    "This application does not include any user "
                    "or device trackers. Unable to find trackers "
                    "during static analysis."
                ),
                "section": "trackers",
            })

    # Possible Hardcoded Secrets
    secrets = data["secrets"]

    if len(secrets) > 1:
        sec = "\n".join(secrets)

        sev = (
            "hotspot"
            if settings.EFR_01 == "1"
            else "warning"
        )

        findings[sev].append({
            "title": (
                "This app may contain hardcoded secrets"
            ),
            "description": (
                "The following secrets were identified from the app. "
                "Ensure that these are not secrets or private information.\n"
                f"{sec}"
            ),
            "section": "secrets",
        })

    high = len(findings.get("high", []))
    warn = len(findings.get("warning", []))
    sec = len(findings.get("secure", []))

    total = high + warn + sec

    score = 0

    if total > 0:
        score = int(
            100
            - (
                (
                    (high * 1)
                    + (warn * 0.5)
                    - (sec * 0.2)
                )
                / total
            )
            * 100
        )

    if score > 100:
        score = 100

    if score < 0:
        score = 0

    findings["security_score"] = score

    findings["app_name"] = data.get(
        "app_name",
        "",
    )

    findings["file_name"] = data.get(
        "file_name",
        "",
    )

    findings["hash"] = data["md5"]


def get_android_dashboard(context, from_ctx=False):
    """Get Android AppSec Dashboard."""

    findings = {
        "high": [],
        "warning": [],
        "info": [],
        "secure": [],
        "hotspot": [],
        "total_trackers": None,
    }

    if from_ctx:
        data = context
    else:
        data = adb(context)

        if not data:
            return findings

    # Certificate Analysis
    if (
        data.get("certificate_analysis")
        and "certificate_findings"
        in data["certificate_analysis"]
    ):
        for i in data["certificate_analysis"][
            "certificate_findings"
        ]:
            if i[0] == "info":
                continue

            findings[i[0]].append({
                "title": i[2],
                "description": i[1],
                "section": "certificate",
            })

    # Network Security
    if (
        data.get("network_security")
        and "network_findings"
        in data["network_security"]
    ):
        for n in data["network_security"][
            "network_findings"
        ]:
            desc = "\n".join(n["scope"])
            desc = f"Scope:\n{desc}\n\n"

            title_parts = n["description"].split(
                ".",
                1,
            )

            if len(title_parts) > 1:
                desc += title_parts[1].strip()
                title = title_parts[0]
            else:
                title = n["description"]

            findings[n["severity"]].append({
                "title": title,
                "description": desc,
                "section": "network",
            })

    # Manifest Analysis
    if (
        data.get("manifest_analysis")
        and "manifest_findings"
        in data["manifest_analysis"]
    ):
        for m in data["manifest_analysis"][
            "manifest_findings"
        ]:
            if m["severity"] == "info":
                continue

            title = m["title"].replace(
                "<strong>",
                "",
            )

            title = title.replace(
                "</strong>",
                "",
            )

            fmt = title.split(
                "<br>",
                1,
            )

            if len(fmt) > 1:
                desc = (
                    fmt[1].replace("<br>", "")
                    + "\n"
                    + m["description"]
                )
            else:
                desc = m["description"]

            findings[m["severity"]].append({
                "title": fmt[0],
                "description": desc,
                "section": "manifest",
            })

    common_fields(findings, data)

    findings["version_name"] = data.get(
        "version_name",
        "",
    )

    return findings


def get_ios_dashboard(context, from_ctx=False):
    """Get iOS AppSec Dashboard."""

    findings = {
        "high": [],
        "warning": [],
        "info": [],
        "secure": [],
        "hotspot": [],
        "total_trackers": None,
    }

    if from_ctx:
        data = context
    else:
        data = idb(context)

        if not data:
            return findings

    # Transport Security
    if (
        data.get("ats_analysis")
        and "ats_findings"
        in data["ats_analysis"]
    ):
        for n in data["ats_analysis"][
            "ats_findings"
        ]:
            findings[n["severity"]].append({
                "title": n["issue"],
                "description": n["description"],
                "section": "network",
            })

    # Binary Code Analysis
    if (
        data.get("binary_analysis")
        and "findings"
        in data["binary_analysis"]
    ):
        for issue, cd in data[
            "binary_analysis"
        ]["findings"].items():

            if cd["severity"] == "good":
                sev = "secure"
            else:
                sev = cd["severity"]

            findings[sev].append({
                "title": issue,
                "description": str(
                    cd["detailed_desc"]
                ),
                "section": "binary",
            })

    # Macho Analysis
    ma = data["macho_analysis"]

    if ma:
        nx = ma["nx"]

        if nx["severity"] in {
            "high",
            "warning",
        }:
            findings[nx["severity"]].append({
                "title": (
                    "NX bit is not set properly "
                    "for this application"
                ),
                "description": nx["description"],
                "section": "macho",
            })

        pie = ma["pie"]

        if pie["severity"] in {
            "high",
            "warning",
        }:
            findings[pie["severity"]].append({
                "title": (
                    "PIE flag is not configured securely"
                    " for this application binary"
                ),
                "description": pie["description"],
                "section": "macho",
            })

        stack_canary = ma["stack_canary"]

        if stack_canary["severity"] in {
            "high",
            "warning",
        }:
            findings[
                stack_canary["severity"]
            ].append({
                "title": (
                    "Stack Canary is not properly "
                    "configured for this application"
                ),
                "description": (
                    stack_canary["description"]
                ),
                "section": "macho",
            })

        arc = ma["arc"]

        if arc["severity"] in {
            "high",
            "warning",
        }:
            findings[arc["severity"]].append({
                "title": (
                    "Application binary is not compiled "
                    "with ARC flag"
                ),
                "description": arc["description"],
                "section": "macho",
            })

        rpath = ma["rpath"]

        if rpath["severity"] in {
            "high",
            "warning",
        }:
            findings[rpath["severity"]].append({
                "title": (
                    "Application binary has rpath set"
                ),
                "description": rpath["description"],
                "section": "macho",
            })

        symbol = ma["symbol"]

        if symbol["severity"] in {
            "high",
            "warning",
        }:
            findings[
                symbol["severity"]
            ].append({
                "title": (
                    "Application binary does not "
                    "have symbols stripped"
                ),
                "description": (
                    symbol["description"]
                ),
                "section": "macho",
            })

    common_fields(findings, data)

    findings["version_name"] = data.get(
        "app_version",
        "",
    )

    return findings


@login_required
def appsec_dashboard(request, checksum, api=False):
    """Provide data for AppSec dashboard."""

    try:
        if not is_md5(checksum):
            return print_n_send_error_response(
                request,
                "Invalid Hash",
                api,
            )

        # --------------------------------------------------------------
        # Android
        # --------------------------------------------------------------
        android_static_db = (
            StaticAnalyzerAndroid.objects.filter(
                MD5=checksum
            ).first()
        )

        # --------------------------------------------------------------
        # iOS
        # --------------------------------------------------------------
        ios_static_db = (
            StaticAnalyzerIOS.objects.filter(
                MD5=checksum
            ).first()
        )

        # --------------------------------------------------------------
        # Windows / EXE
        # --------------------------------------------------------------
        windows_static_db = (
            StaticAnalyzerWindows.objects.filter(
                MD5=checksum
            ).first()
        )

        if android_static_db:
            context = get_android_dashboard(
                [android_static_db]
            )

        elif ios_static_db:
            context = get_ios_dashboard(
                [ios_static_db]
            )

        elif windows_static_db:
            context = get_windows_dashboard(
                windows_static_db
            )

        else:
            if api:
                return {
                    "not_found": (
                        "Report not found or supported"
                    )
                }

            msg = "Report not found or supported"

            return print_n_send_error_response(
                request,
                msg,
                api,
            )

        # --------------------------------------------------------------
        # Common dashboard metadata
        # --------------------------------------------------------------
        context["version"] = settings.MOBSF_VER

        context["title"] = "AppSec Scorecard"

        context["efr01"] = (
            True
            if settings.EFR_01 == "1"
            else False
        )

        # --------------------------------------------------------------
        # Windows-specific metadata
        # --------------------------------------------------------------
        if windows_static_db:
            context["platform"] = "Windows"

            context["file_type"] = "EXE"

            context["static_only"] = True

            context["execution_performed"] = False

            context["analysis_type"] = (
                "Windows PE Static Analysis"
            )

            context["sha256"] = (
                getattr(
                    windows_static_db,
                    "SHA256",
                    "",
                )
                or ""
            )

            context["sha1"] = (
                getattr(
                    windows_static_db,
                    "SHA1",
                    "",
                )
                or ""
            )

            context["architecture"] = (
                getattr(
                    windows_static_db,
                    "ARCHITECTURE",
                    "",
                )
                or ""
            )

            context["compiler_version"] = (
                getattr(
                    windows_static_db,
                    "COMPILER_VERSION",
                    "",
                )
                or ""
            )

            context["publisher_name"] = (
                getattr(
                    windows_static_db,
                    "PUBLISHER_NAME",
                    "",
                )
                or ""
            )

            context["size"] = (
                getattr(
                    windows_static_db,
                    "SIZE",
                    "",
                )
                or ""
            )

            context["risk_level"] = context.get(
                "risk",
                "",
            )

        if api:
            return context

        return render(
            request,
            "static_analysis/appsec_dashboard.html",
            context,
        )

    except Exception as exp:
        logger.exception(
            "Error Generating Application Security Dashboard"
        )

        msg = str(exp)

        exp_doc = getattr(
            exp,
            "__doc__",
            None,
        )

        if api:
            return print_n_send_error_response(
                request,
                msg,
                True,
                exp_doc,
            )

        return print_n_send_error_response(
            request,
            msg,
            False,
            exp_doc,
        )