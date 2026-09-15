# -*- coding: utf_8 -*-
"""Windows Analysis Module."""

import base64
import configparser
import json
import logging
import os
import platform
import re
import subprocess
import xmlrpc.client
from os.path import expanduser

import rsa
from lxml import etree

from django.conf import settings
from django.shortcuts import render
from django.utils.html import escape

from mobsf.MobSF.utils import (
    append_scan_status,
    file_size,
    get_config_loc,
    is_md5,
    print_n_send_error_response,
)
from mobsf.MobSF.views.home import update_scan_timestamp
import mobsf.MalwareAnalyzer.views.VirusTotal as VirusTotal

from mobsf.StaticAnalyzer.models import (
    RecentScansDB,
    StaticAnalyzerWindows,
)

from mobsf.StaticAnalyzer.tools.strings import strings_util

from mobsf.StaticAnalyzer.views.common.shared_func import (
    hash_gen,
    unzip,
)

from mobsf.StaticAnalyzer.views.windows.db_interaction import (
    get_context_from_analysis,
    get_context_from_db_entry,
    save_or_update,
)

from mobsf.StaticAnalyzer.views.windows.exe_analyzer import analyze_exe

from mobsf.MobSF.views.authentication import login_required

from mobsf.MobSF.views.authorization import (
    Permissions,
    has_permission,
)

logger = logging.getLogger(__name__)

# Only used when xmlrpc is used
proxy = None

# Used to store the local config if windows analysis happens local
config = None


##############################################################
# Windows Static Analysis
##############################################################


@login_required
def staticanalyzer_windows(request, checksum, api=False):
    """Analyse a Windows APPX or standalone EXE file."""

    try:
        logger.info('Windows Static Analysis Started')

        rescan = False
        app_dic = {}

        if api:
            re_scan = request.POST.get('re_scan', 0)
        else:
            re_scan = request.GET.get('rescan', 0)

        if re_scan == '1':
            rescan = True

        # --------------------------------------------------
        # Validate MD5
        # --------------------------------------------------

        if not is_md5(checksum):
            return print_n_send_error_response(
                request,
                'Invalid Hash',
                api,
            )

        # --------------------------------------------------
        # Locate uploaded scan
        # --------------------------------------------------

        robj = RecentScansDB.objects.filter(MD5=checksum)

        if not robj.exists():
            return print_n_send_error_response(
                request,
                'The file is not uploaded/available',
                api,
            )

        typ = str(robj[0].SCAN_TYPE or '').lower()
        filename = robj[0].FILE_NAME

        if typ not in settings.WINDOWS_EXTS:
            return print_n_send_error_response(
                request,
                'File type not supported',
                api,
            )

        # --------------------------------------------------
        # Common application information
        # --------------------------------------------------

        app_dic['app_name'] = filename
        app_dic['md5'] = checksum
        app_dic['app_dir'] = os.path.join(
            settings.UPLD_DIR,
            checksum + '/',
        )

        app_dic['tools_dir'] = os.path.join(
            settings.BASE_DIR,
            'StaticAnalyzer/tools/windows/',
        )

        # ==================================================
        # STANDALONE EXE ANALYSIS
        # ==================================================

        if typ == 'exe':
            return _analyze_standalone_exe(
                request=request,
                checksum=checksum,
                filename=filename,
                app_dic=app_dic,
                rescan=rescan,
                api=api,
            )

        # ==================================================
        # EXISTING APPX ANALYSIS
        # ==================================================

        db_entry = StaticAnalyzerWindows.objects.filter(
            MD5=checksum,
        )

        if db_entry.exists() and not rescan:
            logger.info(
                'Analysis is already Done. '
                'Fetching data from the DB...'
            )

            context = get_context_from_db_entry(db_entry)

        else:
            if not has_permission(
                request,
                Permissions.SCAN,
                api,
            ):
                return print_n_send_error_response(
                    request,
                    'Permission Denied',
                    False,
                )

            append_scan_status(
                checksum,
                'init',
            )

            msg = 'Windows Binary Analysis Started'
            logger.info(msg)
            append_scan_status(
                checksum,
                msg,
            )

            app_dic['app_path'] = os.path.join(
                app_dic['app_dir'],
                checksum + '.appx',
            )

            # --------------------------------------------------
            # APPX ANALYSIS
            # --------------------------------------------------

            app_dic['size'] = str(
                file_size(
                    app_dic['app_path'],
                ),
            ) + 'MB'

            # Generate hashes
            app_dic['sha1'], app_dic['sha256'] = hash_gen(
                checksum,
                app_dic['app_path'],
            )

            # Extract APPX
            logger.info('Extracting APPX')

            app_dic['files'] = unzip(
                checksum,
                app_dic['app_path'],
                app_dic['app_dir'],
            )

            xml_dic = _parse_xml(
                checksum,
                app_dic['app_dir'],
            )

            bin_an_dic = _binary_analysis(
                app_dic,
            )

            # --------------------------------------------------
            # Save APPX results
            # --------------------------------------------------

            logger.info('Connecting to DB')

            if rescan:
                logger.info('Updating Database...')

                save_or_update(
                    'update',
                    app_dic,
                    xml_dic,
                    bin_an_dic,
                )

                update_scan_timestamp(
                    checksum,
                )

            else:
                logger.info('Saving to Database')

                save_or_update(
                    'save',
                    app_dic,
                    xml_dic,
                    bin_an_dic,
                )

            context = get_context_from_analysis(
                app_dic,
                xml_dic,
                bin_an_dic,
            )

            context['virus_total'] = None

        # --------------------------------------------------
        # VirusTotal for APPX
        # --------------------------------------------------

        context['virus_total'] = None

        if settings.VT_ENABLED:
            vt = VirusTotal.VirusTotal(
                checksum,
            )

            context['virus_total'] = vt.get_result(
                os.path.join(
                    app_dic['app_dir'],
                    checksum,
                ) + '.appx',
            )

        template = 'static_analysis/windows_binary_analysis.html'

        if api:
            return context

        return render(
            request,
            template,
            context,
        )

    except Exception as exception:
        msg = 'Error Performing Static Analysis'

        logger.exception(msg)

        append_scan_status(
            checksum,
            msg,
            repr(exception),
        )

        return print_n_send_error_response(
            request,
            repr(exception),
            api,
            exception.__doc__,
        )


##############################################################
# Standalone EXE Analysis
##############################################################


def _find_uploaded_exe(app_dir, checksum, filename):
    """
    Locate the uploaded EXE.

    MobSF normally stores uploaded files using the checksum
    as the filename. We first check checksum.exe and then
    fall back to the original filename.
    """

    candidates = [
        os.path.join(
            app_dir,
            checksum + '.exe',
        ),
        os.path.join(
            app_dir,
            filename,
        ),
    ]

    # Also search the upload directory in case the upload
    # subsystem preserved another filename.
    try:
        for name in os.listdir(app_dir):
            full_path = os.path.join(
                app_dir,
                name,
            )

            if (
                os.path.isfile(full_path)
                and name.lower().endswith('.exe')
            ):
                candidates.append(full_path)

    except OSError:
        pass

    seen = set()

    for path in candidates:
        if path in seen:
            continue

        seen.add(path)

        if os.path.isfile(path):
            return path

    return None


def _normalize_exe_finding(finding):
    """
    Normalize an EXE analyzer finding into a format that
    ASAF/MobSF frontend code can consume.
    """

    if not isinstance(finding, dict):
        return {
            'rule_id': 'EXE_ANALYSIS',
            'status': 'Info',
            'severity': 'INFO',
            'title': 'EXE Static Analysis Finding',
            'desc': str(finding),
            'info': '',
        }

    item = dict(finding)

    severity = str(
        item.get('severity')
        or item.get('level')
        or item.get('status')
        or 'INFO'
    ).upper()

    if severity in ('CRITICAL', 'HIGH'):
        status = 'Insecure'
        severity = 'HIGH'

    elif severity in (
        'MEDIUM',
        'WARNING',
        'WARN',
    ):
        status = 'Insecure'
        severity = 'WARNING'

    elif severity in (
        'LOW',
        'INFO',
        'INFORMATION',
    ):
        status = 'Info'
        severity = 'INFO'

    elif severity in (
        'SECURE',
        'PASS',
        'SAFE',
    ):
        status = 'Secure'
        severity = 'SECURE'

    else:
        status = item.get(
            'status',
            'Info',
        )

    item['status'] = status
    item['severity'] = severity

    if not item.get('rule_id'):
        item['rule_id'] = (
            item.get('id')
            or item.get('rule')
            or item.get('title')
            or 'EXE_ANALYSIS'
        )

    if not item.get('title'):
        item['title'] = (
            item.get('name')
            or item.get('rule_id')
            or 'EXE Static Analysis Finding'
        )

    if not item.get('desc'):
        item['desc'] = (
            item.get('description')
            or item.get('message')
            or item.get('title')
            or ''
        )

    if not item.get('info'):
        item['info'] = str(
            item.get('details')
            or item.get('evidence')
            or ''
        )

    return item


def _normalize_exe_analysis(analysis):
    """
    Normalize the standalone EXE analyzer result.

    The helper deliberately accepts several possible result
    structures so changes in exe_analyzer.py do not break
    the MobSF Windows pipeline.
    """

    if not isinstance(analysis, dict):
        analysis = {
            'pe': False,
            'score': 0,
            'risk': 'UNKNOWN',
            'findings': [],
        }

    result = dict(analysis)

    findings = result.get('findings')

    if not isinstance(findings, list):
        findings = []

        for key in (
            'warnings',
            'issues',
            'results',
        ):
            value = result.get(key)

            if isinstance(value, list):
                findings.extend(value)

    normalized_findings = []

    for finding in findings:
        normalized_findings.append(
            _normalize_exe_finding(finding),
        )

    result['findings'] = normalized_findings

    # Compatibility aliases
    if 'score' not in result:
        result['score'] = result.get(
            'security_score',
            0,
        )

    if 'risk' not in result:
        result['risk'] = result.get(
            'risk_level',
            'UNKNOWN',
        )

    result['analysis_type'] = (
        'STATIC PE ANALYSIS'
    )

    result['execution_performed'] = False

    result['static_only'] = True

    return result


def _build_exe_warning_list(analysis):
    """
    Convert analyzer findings into the BINARY_WARNINGS
    structure used by StaticAnalyzerWindows.
    """

    warnings = []

    findings = analysis.get(
        'findings',
        [],
    )

    for finding in findings:
        severity = str(
            finding.get(
                'severity',
                'INFO',
            ),
        ).upper()

        if severity == 'HIGH':
            status = 'Insecure'
        elif severity == 'WARNING':
            status = 'Warning'
        elif severity == 'SECURE':
            status = 'Secure'
        else:
            status = 'Info'

        warnings.append({
            'rule_id': finding.get(
                'rule_id',
                'EXE_ANALYSIS',
            ),
            'status': status,
            'severity': severity,
            'title': finding.get(
                'title',
                'EXE Static Analysis Finding',
            ),
            'info': finding.get(
                'info',
                '',
            ),
            'desc': finding.get(
                'desc',
                '',
            ),
        })

    return warnings


def _extract_exe_value(analysis, *keys, default=''):
    """
    Safely extract a value from the analyzer result.
    """

    for key in keys:
        value = analysis.get(key)

        if value not in (
            None,
            '',
            [],
            {},
        ):
            return value

    return default


def _json_text(value):
    """
    Convert complex EXE analysis data into JSON text for
    the existing TextField columns.
    """

    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            default=str,
        )
    except Exception:
        return json.dumps(
            str(value),
            ensure_ascii=False,
        )


def _architecture_from_analysis(analysis):
    """
    Extract architecture in a human-readable form.
    """

    value = _extract_exe_value(
        analysis,
        'architecture',
        'arch',
        default='UNKNOWN',
    )

    value = str(value)

    if value.lower() in (
        'x64',
        'amd64',
        'pe32+',
        '64',
        'x86-64',
    ):
        return 'x64 / PE32+'

    if value.lower() in (
        'x86',
        'i386',
        'i686',
        '32',
        'pe32',
    ):
        return 'x86 / PE32'

    return value


def _analyze_standalone_exe(
    request,
    checksum,
    filename,
    app_dic,
    rescan=False,
    api=False,
):
    """
    Perform deep static analysis of a standalone EXE.

    IMPORTANT:
    The uploaded executable is never executed by this function.
    """

    try:
        # --------------------------------------------------
        # Permission
        # --------------------------------------------------

        if not has_permission(
            request,
            Permissions.SCAN,
            api,
        ):
            return print_n_send_error_response(
                request,
                'Permission Denied',
                api,
            )

        append_scan_status(
            checksum,
            'init',
        )

        append_scan_status(
            checksum,
            'EXE Static PE Analysis Started',
        )

        logger.info(
            'Standalone EXE analysis started: %s',
            filename,
        )

        # --------------------------------------------------
        # Locate EXE
        # --------------------------------------------------

        exe_path = _find_uploaded_exe(
            app_dic['app_dir'],
            checksum,
            filename,
        )

        if not exe_path:
            msg = (
                'Uploaded EXE could not be located in '
                f'{app_dic["app_dir"]}'
            )

            logger.error(msg)

            append_scan_status(
                checksum,
                msg,
            )

            return print_n_send_error_response(
                request,
                msg,
                api,
            )

        app_dic['app_path'] = exe_path

        append_scan_status(
            checksum,
            'EXE file located',
        )

        # --------------------------------------------------
        # Basic file information
        # --------------------------------------------------

        size_bytes = os.path.getsize(
            exe_path,
        )

        app_dic['size'] = (
            str(round(
                size_bytes / (
                    1024 * 1024
                ),
                2,
            ))
            + 'MB'
        )

        append_scan_status(
            checksum,
            'Reading EXE binary buffer',
        )

        # --------------------------------------------------
        # Run standalone analyzer
        # --------------------------------------------------

        append_scan_status(
            checksum,
            'Parsing DOS/PE/COFF headers',
        )

        append_scan_status(
            checksum,
            'Analyzing PE sections and permissions',
        )

        append_scan_status(
            checksum,
            'Calculating section entropy',
        )

        append_scan_status(
            checksum,
            'Analyzing imports and suspicious APIs',
        )

        append_scan_status(
            checksum,
            'Extracting strings and network indicators',
        )

        append_scan_status(
            checksum,
            'Checking PE security mitigations',
        )

        append_scan_status(
            checksum,
            'Checking TLS callbacks and overlay',
        )

        append_scan_status(
            checksum,
            'Checking packer and obfuscation heuristics',
        )

        # --------------------------------------------------
        # IMPORTANT:
        # analyze_exe performs static analysis only.
        # It does NOT execute the EXE.
        # --------------------------------------------------

        analysis = analyze_exe(
            exe_path,
        )

        analysis = _normalize_exe_analysis(
            analysis,
        )

        # --------------------------------------------------
        # Hashes
        # --------------------------------------------------

        hashes = analysis.get(
            'hashes',
            {},
        )

        if not isinstance(hashes, dict):
            hashes = {}

        sha1 = (
            hashes.get('sha1')
            or analysis.get('sha1')
            or ''
        )

        sha256 = (
            hashes.get('sha256')
            or analysis.get('sha256')
            or ''
        )

        # --------------------------------------------------
        # Build findings
        # --------------------------------------------------

        findings = analysis.get(
            'findings',
            [],
        )

        warnings = _build_exe_warning_list(
            analysis,
        )

        # --------------------------------------------------
        # Extract common metadata
        # --------------------------------------------------

        architecture = _architecture_from_analysis(
            analysis,
        )

        compiler_version = _extract_exe_value(
            analysis,
            'compiler_version',
            'compiler',
            default='',
        )

        target_os = _extract_exe_value(
            analysis,
            'target_os',
            'operating_system',
            'os',
            default='Windows',
        )

        app_version = _extract_exe_value(
            analysis,
            'version',
            'file_version',
            'product_version',
            default='',
        )

        publisher = _extract_exe_value(
            analysis,
            'publisher',
            'company_name',
            'company',
            default='',
        )

        # --------------------------------------------------
        # Add report metadata to analyzer result
        # --------------------------------------------------

        analysis['file_name'] = filename
        analysis['file_path'] = exe_path
        analysis['file_size_bytes'] = size_bytes
        analysis['md5'] = (
            checksum
        )
        analysis['sha1'] = sha1
        analysis['sha256'] = sha256

        analysis['architecture'] = architecture

        analysis['compiler_version'] = (
            compiler_version
        )

        analysis['target_os'] = (
            target_os
        )

        analysis['app_version'] = (
            app_version
        )

        analysis['publisher'] = (
            publisher
        )

        analysis['finding_count'] = len(
            findings,
        )

        # --------------------------------------------------
        # Store using EXISTING StaticAnalyzerWindows model.
        #
        # No new model and no migration required.
        # --------------------------------------------------

        append_scan_status(
            checksum,
            'Saving EXE analysis results',
        )

        db_values = {
            'FILE_NAME': filename,
            'APP_NAME': filename,
            'PUBLISHER_NAME': str(
                publisher,
            ),
            'SIZE': str(
                app_dic['size'],
            ),
            'MD5': checksum,
            'SHA1': str(
                sha1,
            ),
            'SHA256': str(
                sha256,
            ),
            'APP_VERSION': str(
                app_version,
            ),
            'ARCHITECTURE': str(
                architecture,
            ),
            'COMPILER_VERSION': str(
                compiler_version,
            ),
            'VISUAL_STUDIO_VERSION': '',
            'VISUAL_STUDIO_EDITION': '',
            'TARGET_OS': str(
                target_os,
            ),
            'APPX_DLL_VERSION': '',
            'PROJ_GUID': '',
            'OPTI_TOOL': '',
            'TARGET_RUN': '',
            'FILES': _json_text([
                filename,
            ]),
            'STRINGS': _json_text(
                _extract_exe_value(
                    analysis,
                    'strings',
                    default=[],
                ),
            ),
            'BINARY_ANALYSIS': _json_text(
                analysis,
            ),
            'BINARY_WARNINGS': _json_text(
                warnings,
            ),
        }

        db_obj, created = (
            StaticAnalyzerWindows.objects.update_or_create(
                MD5=checksum,
                defaults=db_values,
            )
        )

        logger.info(
            'Standalone EXE results saved. '
            'Created=%s MD5=%s',
            created,
            checksum,
        )

        if rescan:
            update_scan_timestamp(
                checksum,
            )

        # --------------------------------------------------
        # Mark scan complete
        # --------------------------------------------------

        score = analysis.get(
            'score',
            0,
        )

        risk = str(
            analysis.get(
                'risk',
                'UNKNOWN',
            ),
        ).upper()

        append_scan_status(
            checksum,
            'EXE Static PE Analysis Completed',
        )

        append_scan_status(
            checksum,
            'EXE Security Score: '
            f'{score}',
        )

        append_scan_status(
            checksum,
            'EXE Risk Level: '
            f'{risk}',
        )

        # --------------------------------------------------
        # Build API/UI context
        # --------------------------------------------------

        context = _build_exe_context(
            analysis=analysis,
            warnings=warnings,
            app_dic=app_dic,
            checksum=checksum,
            filename=filename,
        )

        context['virus_total'] = None

        # --------------------------------------------------
        # VirusTotal
        #
        # VT receives the EXE path only when enabled.
        # This does NOT execute the EXE.
        # --------------------------------------------------

        if settings.VT_ENABLED:
            try:
                vt = VirusTotal.VirusTotal(
                    checksum,
                )

                context['virus_total'] = vt.get_result(
                    exe_path,
                )

            except Exception:
                logger.exception(
                    'VirusTotal EXE lookup failed',
                )

        # --------------------------------------------------
        # API response
        # --------------------------------------------------

        if api:
            return context

        # --------------------------------------------------
        # Normal UI response
        # --------------------------------------------------

        template = (
            'static_analysis/windows_binary_analysis.html'
        )

        return render(
            request,
            template,
            context,
        )

    except Exception as exception:
        msg = (
            'Error Performing EXE Static Analysis'
        )

        logger.exception(msg)

        append_scan_status(
            checksum,
            msg,
            repr(exception),
        )

        return print_n_send_error_response(
            request,
            repr(exception),
            api,
            exception.__doc__,
        )


def _build_exe_context(
    analysis,
    warnings,
    app_dic,
    checksum,
    filename,
):
    """
    Build a context compatible with the existing Windows
    analysis template and API layer.
    """

    findings = analysis.get(
        'findings',
        [],
    )

    high = []
    warning = []
    info = []
    secure = []

    for finding in findings:
        severity = str(
            finding.get(
                'severity',
                'INFO',
            ),
        ).upper()

        if severity == 'HIGH':
            high.append(finding)

        elif severity == 'WARNING':
            warning.append(finding)

        elif severity == 'SECURE':
            secure.append(finding)

        else:
            info.append(finding)

    score = analysis.get(
        'score',
        0,
    )

    risk = str(
        analysis.get(
            'risk',
            'UNKNOWN',
        ),
    ).upper()

    context = {
        'app_name': filename,
        'file_name': filename,
        'md5': checksum,

        'sha1': analysis.get(
            'sha1',
            '',
        ),

        'sha256': analysis.get(
            'sha256',
            '',
        ),

        'size': app_dic.get(
            'size',
            '',
        ),

        'architecture': analysis.get(
            'architecture',
            'UNKNOWN',
        ),

        'app_version': analysis.get(
            'app_version',
            '',
        ),

        'compiler_version': analysis.get(
            'compiler_version',
            '',
        ),

        'target_os': analysis.get(
            'target_os',
            'Windows',
        ),

        'publisher': analysis.get(
            'publisher',
            '',
        ),

        'score': score,
        'security_score': score,

        'risk': risk,
        'risk_level': risk,

        'analysis_type': (
            'STATIC PE ANALYSIS'
        ),

        'static_only': True,

        'execution_performed': False,

        'pe_analysis': analysis,

        'exe_analysis': analysis,

        'binary_analysis': analysis,

        'findings': findings,

        'warnings': warnings,

        'high': high,

        'warning': warning,

        'info': info,

        'secure': secure,

        'finding_counts': {
            'high': len(high),
            'warning': len(warning),
            'info': len(info),
            'secure': len(secure),
            'total': len(findings),
        },

        'virus_total': None,
    }

    # Compatibility with existing MobSF Windows template
    context['app_dic'] = app_dic
    context['bin_an_dic'] = {
        'bin': filename,
        'bin_name': filename,
        'results': warnings,
        'warnings': warnings,
        'strings': analysis.get(
            'strings',
            [],
        ),
    }

    context['xml_dic'] = {
        'version': analysis.get(
            'app_version',
            '',
        ),
        'arch': analysis.get(
            'architecture',
            '',
        ),
        'app_name': filename,
        'pub_name': analysis.get(
            'publisher',
            '',
        ),
        'compiler_version': analysis.get(
            'compiler_version',
            '',
        ),
        'visual_studio_version': '',
        'visual_studio_edition': '',
        'target_os': analysis.get(
            'target_os',
            'Windows',
        ),
        'appx_dll_version': '',
        'proj_guid': '',
        'opti_tool': '',
        'target_run': '',
    }

    return context


##############################################################
# Existing Windows VM Support
##############################################################


def _get_token():
    """Get authentication token for Windows VM XMLRPC client."""

    challenge = proxy.get_challenge()

    priv_key = rsa.PrivateKey.load_pkcs1(
        open(
            settings.WINDOWS_VM_SECRET,
        ).read(),
    )

    signature = rsa.sign(
        challenge.encode('ascii'),
        priv_key,
        'SHA-512',
    )

    sig_b64 = base64.b64encode(
        signature,
    )

    return sig_b64


def _binary_analysis(app_dic):
    """Start binary analysis for APPX."""

    msg = 'Starting Binary Analysis'

    logger.info(msg)

    append_scan_status(
        app_dic['md5'],
        msg,
    )

    bin_an_dic = {}

    # Init optional sections
    bin_an_dic['results'] = []
    bin_an_dic['warnings'] = []

    # Search for exe
    for file_name in app_dic['files']:
        if file_name.endswith('.exe'):
            bin_an_dic['bin'] = file_name
            bin_an_dic['bin_name'] = file_name.replace(
                '.exe',
                '',
            )
            break

    if not bin_an_dic.get('bin_name'):
        logger.error(
            'No executable in appx',
        )

        return bin_an_dic

    bin_path = os.path.join(
        app_dic['app_dir'],
        bin_an_dic['bin'],
    )

    # Execute strings command
    bin_an_dic['strings'] = ''

    # Make unique
    str_list = list(
        set(
            strings_util(bin_path),
        ),
    )

    str_list = [
        escape(s)
        for s in str_list
    ]

    bin_an_dic['strings'] = str_list

    # Search for unsafe functions
    pattern = re.compile(
        '(alloca|gets|memcpy|printf|scanf|sprintf|sscanf|'
        'strcat|StrCat|strcpy|StrCpy|strlen|StrLen|strncat|'
        'StrNCat|strncpy|StrNCpy|strtok|swprintf|vsnprintf|'
        'vsprintf|vswprintf|wcscat|wcscpy|wcslen|wcsncat|'
        'wcsncpy|wcstok|wmemcpy)',
    )

    for elem in str_list:
        if pattern.match(elem[5:-5]):
            result = {
                'rule_id': 'Possible Insecure Function',
                'status': 'Insecure',
                'desc': (
                    'Possible Insecure '
                    'Function detected: {}'
                ).format(
                    elem[5:-5],
                ),
            }

            bin_an_dic['results'].append(
                result,
            )

    # Execute BinSkim/BinScope if VM available
    if (
        platform.system() != 'Windows'
        or 'CI' in os.environ
    ):
        if settings.WINDOWS_VM_IP:
            msg = 'Windows VM configured'

            logger.info(msg)

            append_scan_status(
                app_dic['md5'],
                msg,
            )

            global proxy

            proxy = xmlrpc.client.ServerProxy(
                'http://{}:{}'.format(
                    settings.WINDOWS_VM_IP,
                    settings.WINDOWS_VM_PORT,
                ),
            )

            name = _upload_sample(
                bin_path,
            )

            bin_an_dic = binskim(
                app_dic['md5'],
                name,
                bin_an_dic,
            )

            bin_an_dic = binscope(
                app_dic['md5'],
                name,
                bin_an_dic,
            )

        else:
            msg = (
                f'Windows VM not configured in '
                f'{get_config_loc()}. '
                'Skipping Binskim and Binscope analysis'
            )

            logger.warning(msg)

            append_scan_status(
                app_dic['md5'],
                msg,
            )

            warning = {
                'rule_id': 'VM',
                'status': 'Info',
                'info': '',
                'desc': (
                    'VM is not configured. Please read '
                    'the readme.md in MobSF/install/windows.'
                ),
            }

            bin_an_dic['results'].append(
                warning,
            )

    else:
        msg = 'Running Analysis on Windows host'

        logger.info(msg)

        append_scan_status(
            app_dic['md5'],
            msg,
        )

        global config

        config = configparser.ConfigParser()

        config.read(
            expanduser('~')
            + '\\MobSF\\Config\\config.txt',
        )

        bin_an_dic = binskim(
            app_dic['md5'],
            bin_path,
            bin_an_dic,
            run_local=True,
            app_dir=app_dic['app_dir'],
        )

        bin_an_dic = binscope(
            app_dic['md5'],
            bin_path,
            bin_an_dic,
            run_local=True,
            app_dir=app_dic['app_dir'],
        )

    return bin_an_dic


def _upload_sample(bin_path):
    """Upload sample to Windows VM."""

    logger.info(
        'Uploading sample.',
    )

    with open(
        bin_path,
        'rb',
    ) as handle:
        binary_data = xmlrpc.client.Binary(
            handle.read(),
        )

    name = proxy.upload_file(
        binary_data,
        _get_token(),
    )

    return name


def binskim(
    checksum,
    name,
    bin_an_dic,
    run_local=False,
    app_dir=None,
):
    """Run BinSkim analysis."""

    msg = 'Running binskim.'

    logger.info(msg)

    append_scan_status(
        checksum,
        msg,
    )

    if run_local:
        bin_path = os.path.join(
            app_dir,
            bin_an_dic['bin'],
        )

        if platform.machine().endswith('64'):
            binskim_path = config['binskim']['file_x64']
        else:
            binskim_path = config['binskim']['file_x86']

        command = 'analyze'
        path = bin_path
        output_p = '-o'
        output_d = bin_path + '_binskim'
        verbose = '--verbose'
        policy_p = '--config'
        force = '--force'
        policy_d = 'default'

        params = [
            binskim_path,
            command,
            path,
            verbose,
            output_p,
            output_d,
            policy_p,
            policy_d,
            force,
        ]

        pipe = subprocess.Popen(
            subprocess.list2cmdline(params),
        )

        pipe.wait()

        out_file = open(
            output_d,
        )

        output = json.loads(
            out_file.read(),
        )

    else:
        response = proxy.binskim(
            name,
            _get_token(),
        )

        output = json.loads(
            response,
        )

    bin_an_dic = parse_binskim(
        bin_an_dic,
        output,
    )

    return bin_an_dic


def parse_binskim(
    bin_an_dic,
    output,
):
    """Parse BinSkim output."""

    try:
        output['runs'][0]['rules']

        return parse_binskim_old(
            bin_an_dic,
            output,
        )

    except Exception:
        return parse_binskim_sarif(
            bin_an_dic,
            output,
        )


def get_short_desc(
    rules,
    rule_id,
):
    """Get short description from SARIF."""

    for item in rules:
        if item['id'] == rule_id:
            return item[
                'shortDescription'
            ]['text']

    return rule_id


def parse_binskim_sarif(
    bin_an_dic,
    output,
):
    """Parse new BinSkim SARIF output."""

    current_run = output['runs'][0]

    rules = current_run[
        'tool'
    ]['driver']['rules']

    if 'results' in current_run:
        for res in current_run['results']:

            if res['level'] != 'pass':
                if len(
                    res['message']['arguments'],
                ) > 2:
                    info = (
                        '{}, {}'
                    ).format(
                        res['message']['arguments'][1],
                        res['message']['arguments'][2],
                    )
                else:
                    info = ''

                result = {
                    'rule_id': res['ruleId'],
                    'status': 'Insecure',
                    'info': info,
                    'desc': get_short_desc(
                        rules,
                        res['ruleId'],
                    ),
                }

            else:
                result = {
                    'rule_id': res['ruleId'],
                    'status': 'Secure',
                    'info': '',
                    'desc': get_short_desc(
                        rules,
                        res['ruleId'],
                    ),
                }

            bin_an_dic['results'].append(
                result,
            )

    else:
        logger.warning(
            'binskim has no results.',
        )

        warning = {
            'rule_id': 'No Binskim-Results',
            'status': 'Info',
            'info': '',
            'desc': 'No results from Binskim.',
        }

        bin_an_dic['warnings'].append(
            warning,
        )

    return bin_an_dic


def parse_binskim_old(
    bin_an_dic,
    output,
):
    """Parse old BinSkim output."""

    current_run = output['runs'][0]

    if 'results' in current_run:
        rules = output['runs'][0]['rules']

        for res in current_run['results']:

            if res['level'] != 'pass':

                if len(
                    res['formattedRuleMessage']['arguments'],
                ) > 2:
                    info = (
                        '{}, {}'
                    ).format(
                        res[
                            'formattedRuleMessage'
                        ]['arguments'][1],
                        res[
                            'formattedRuleMessage'
                        ]['arguments'][2],
                    )
                else:
                    info = ''

                result = {
                    'rule_id': res['ruleId'],
                    'status': 'Insecure',
                    'info': info,
                    'desc': rules[
                        res['ruleId']
                    ]['shortDescription'],
                }

            else:
                result = {
                    'rule_id': res['ruleId'],
                    'status': 'Secure',
                    'info': '',
                    'desc': rules[
                        res['ruleId']
                    ]['shortDescription'],
                }

            bin_an_dic['results'].append(
                result,
            )

    else:
        logger.warning(
            'binskim has no results.',
        )

        warning = {
            'rule_id': 'No Binskim-Results',
            'status': 'Info',
            'info': '',
            'desc': 'No results from Binskim.',
        }

        bin_an_dic['warnings'].append(
            warning,
        )

    if 'configurationNotifications' in current_run:
        for warn in current_run[
            'configurationNotifications'
        ]:
            warning = {
                'rule_id': warn['ruleId'],
                'status': 'Info',
                'info': '',
                'desc': warn['message'],
            }

            bin_an_dic['warnings'].append(
                warning,
            )

    return bin_an_dic


def binscope(
    checksum,
    name,
    bin_an_dic,
    run_local=False,
    app_dir=None,
):
    """Run BinScope analysis."""

    msg = (
        'Running binscope. '
        'This might take a while.'
    )

    logger.info(msg)

    append_scan_status(
        checksum,
        msg,
    )

    if run_local:
        global config

        bin_path = os.path.join(
            app_dir,
            bin_an_dic['bin'],
        )

        binscope_path = [
            config['binscope']['file'],
        ]

        target = [
            bin_path,
        ]

        out_type = [
            '/Red',
            '/v',
        ]

        output = [
            '/l',
            target[0] + '_binscope',
        ]

        checks = [
            '/Checks',
            'ATLVersionCheck',
            '/Checks',
            'ATLVulnCheck',
            '/Checks',
            'AppContainerCheck',
            '/Checks',
            'CompilerVersionCheck',
            '/Checks',
            'DBCheck',
            '/Checks',
            'DefaultGSCookieCheck',
            '/Checks',
            'ExecutableImportsCheck',
            '/Checks',
            'FunctionPointersCheck',
            '/Checks',
            'GSCheck',
            '/Checks',
            'GSFriendlyInitCheck',
            '/Checks',
            'GSFunctionSafeBuffersCheck',
            '/Checks',
            'HighEntropyVACheck',
            '/Checks',
            'NXCheck',
            '/Checks',
            'RSA32Check',
            '/Checks',
            'SafeSEHCheck',
            '/Checks',
            'SharedSectionCheck',
            '/Checks',
            'VB6Check',
            '/Checks',
            'WXCheck',
        ]

        params = (
            binscope_path
            + target
            + out_type
            + output
            + checks
        )

        p = subprocess.Popen(
            subprocess.list2cmdline(params),
        )

        p.wait()

        f = open(
            output[1],
        )

        response = f.read()

    else:
        response = proxy.binscope(
            name,
            _get_token(),
        )

    res = response[
        response.find('<'):
    ]

    config = etree.XMLParser(
        remove_blank_text=True,
        resolve_entities=False,
    )

    xml_file = etree.XML(
        bytes(
            res,
            'utf-8',
            'ignore',
        ),
        config,
    )

    for item in xml_file.find(
        'items',
    ).getchildren():

        if item.find(
            'issueType',
        ) is not None:

            res = item.find(
                'result',
            ).text

            if res == 'PASS':
                status = 'Secure'

                try:
                    desc = item.find(
                        'Information',
                    ).text

                except AttributeError:
                    desc = (
                        'No description provided '
                        'by analysing tool.'
                    )

            elif res == 'FAIL':
                status = 'Insecure'

                if item.find(
                    'Failure1',
                ) is not None:
                    desc = item.find(
                        'Failure1',
                    ).text

                elif item.find(
                    'Information',
                ) is not None:
                    desc = item.find(
                        'Information',
                    ).text

                elif item.find(
                    'diagnostic',
                ) is not None:
                    status = 'Info'

                    desc = item.find(
                        'diagnostic',
                    ).text

                else:
                    desc = (
                        'No description provided '
                        'by analysing tool.'
                    )

            result = {
                'rule_id': item.find(
                    'issueType',
                ).text,

                'status': status,

                'info': '',

                'desc': desc,
            }

            bin_an_dic[
                'results'
            ].append(
                result,
            )

    return bin_an_dic


##############################################################
# APPX Manifest Parsing
##############################################################


def _parse_xml(
    checksum,
    app_dir,
):
    """Parse AppxManifest for basic information."""

    msg = (
        'Starting Binary Analysis - XML'
    )

    logger.info(msg)

    append_scan_status(
        checksum,
        msg,
    )

    xml_file = os.path.join(
        app_dir,
        'AppxManifest.xml',
    )

    xml_dic = {
        'version': '',
        'arch': '',
        'app_name': '',
        'pub_name': '',
        'compiler_version': '',
        'visual_studio_version': '',
        'visual_studio_edition': '',
        'target_os': '',
        'appx_dll_version': '',
        'proj_guid': '',
        'opti_tool': '',
        'target_run': '',
    }

    try:
        msg = 'Reading AppxManifest'

        logger.info(msg)

        append_scan_status(
            checksum,
            msg,
        )

        config = etree.XMLParser(
            remove_blank_text=True,
            resolve_entities=False,
        )

        xml = etree.XML(
            open(
                xml_file,
                'rb',
            ).read(),
            config,
        )

        for child in xml.getchildren():

            if (
                isinstance(child.tag, str)
                and child.tag.endswith(
                    '}Identity',
                )
            ):
                xml_dic[
                    'version'
                ] = child.get(
                    'Version',
                )

                xml_dic[
                    'arch'
                ] = child.get(
                    'ProcessorArchitecture',
                )

            elif (
                isinstance(child.tag, str)
                and child.tag.endswith(
                    'Properties',
                )
            ):

                for sub_child in child.getchildren():

                    if sub_child.tag.endswith(
                        '}DisplayName',
                    ):
                        xml_dic[
                            'app_name'
                        ] = sub_child.text

                    elif sub_child.tag.endswith(
                        '}PublisherDisplayName',
                    ):
                        xml_dic[
                            'pub_name'
                        ] = sub_child.text

            elif (
                isinstance(child.tag, str)
                and child.tag.endswith(
                    '}Metadata',
                )
            ):
                xml_dic = parse_xml_metadata(
                    xml_dic,
                    child,
                )

    except Exception as exp:
        msg = 'Error Reading AppxManifest'

        logger.exception(msg)

        append_scan_status(
            checksum,
            msg,
            repr(exp),
        )

    return xml_dic


def parse_xml_metadata(
    xml_dic,
    xml_node,
):
    """Return XML Metadata."""

    for child in xml_node.getchildren():

        if child.get('Name') == 'cl.exe':
            xml_dic[
                'compiler_version'
            ] = child.get(
                'Version',
            )

        elif child.get('Name') == 'VisualStudio':
            xml_dic[
                'visual_studio_version'
            ] = child.get(
                'Version',
            )

        elif child.get(
            'Name',
        ) == 'VisualStudioEdition':
            xml_dic[
                'visual_studio_edition'
            ] = child.get(
                'Value',
            )

        elif child.get(
            'Name',
        ) == 'OperatingSystem':
            xml_dic[
                'target_os'
            ] = child.get(
                'Version',
            )

        elif child.get(
            'Name',
        ) == 'Microsoft.Build.AppxPackage.dll':
            xml_dic[
                'appx_dll_version'
            ] = child.get(
                'Version',
            )

        elif child.get(
            'Name',
        ) == 'ProjectGUID':
            xml_dic[
                'proj_guid'
            ] = child.get(
                'Value',
            )

        elif child.get(
            'Name',
        ) == 'OptimizingToolset':
            xml_dic[
                'opti_tool'
            ] = child.get(
                'Value',
            )

        elif child.get(
            'Name',
        ) == 'TargetRuntime':
            xml_dic[
                'target_run'
            ] = child.get(
                'Value',
            )

    return xml_dic