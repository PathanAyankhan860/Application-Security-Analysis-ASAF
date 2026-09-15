# -*- coding: utf_8 -*-
"""MobSF REST API V 1."""

from django.conf import settings
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt

from mobsf.MobSF.utils import (
    get_scan_logs,
    is_md5,
)
from mobsf.MobSF.views.api.api_middleware import (
    make_api_response,
)
from mobsf.MobSF.views.authentication import (
    login_required,
)
from mobsf.MobSF.views.helpers import (
    request_method,
)
from mobsf.MobSF.views.home import (
    RecentScans,
    Upload,
    delete_scan,
    search,
)
from mobsf.StaticAnalyzer.models import (
    RecentScansDB,
)
from mobsf.StaticAnalyzer.views.android.static_analyzer import (
    static_analyzer,
)
from mobsf.StaticAnalyzer.views.android.views import (
    view_source,
)
from mobsf.StaticAnalyzer.views.common.appsec import (
    appsec_dashboard,
)
from mobsf.StaticAnalyzer.views.common.async_task import (
    list_tasks,
)
from mobsf.StaticAnalyzer.views.common.shared_func import (
    compare_apps,
)
from mobsf.StaticAnalyzer.views.common.pdf import (
    pdf,
)
from mobsf.StaticAnalyzer.views.common.suppression import (
    delete_suppression,
    list_suppressions,
    suppress_by_files,
    suppress_by_rule_id,
)
from mobsf.StaticAnalyzer.views.ios.static_analyzer import (
    static_analyzer_ios,
)
from mobsf.StaticAnalyzer.views.ios.views import (
    view_source as ios_view_source,
)
from mobsf.StaticAnalyzer.views.windows import (
    windows,
)


@request_method(["POST"])
@csrf_exempt
def api_upload(request):
    """POST - Upload API."""
    upload = Upload(request)

    resp, code = upload.upload_api()

    return make_api_response(
        resp,
        code,
    )


@request_method(["GET"])
@csrf_exempt
def api_recent_scans(request):
    """GET - get recent scans."""
    scans = RecentScans(request)

    resp = scans.recent_scans()

    if "error" in resp:
        return make_api_response(
            resp,
            500,
        )

    return make_api_response(
        resp,
        200,
    )


@request_method(["POST"])
@csrf_exempt
def api_scan(request):
    """POST - Scan API."""

    if "hash" not in request.POST:
        return make_api_response(
            {"error": "Missing Parameters"},
            422,
        )

    checksum = request.POST["hash"]

    if not is_md5(checksum):
        return make_api_response(
            {"error": "Invalid Checksum"},
            500,
        )

    robj = RecentScansDB.objects.filter(
        MD5=checksum
    )

    if not robj.exists():
        return make_api_response(
            {
                "error": (
                    "The file is not uploaded/available"
                )
            },
            500,
        )

    scan_type = robj[0].SCAN_TYPE

    # --------------------------------------------------------------
    # Android
    # --------------------------------------------------------------
    if scan_type in settings.ANDROID_EXTS:
        resp = static_analyzer(
            request,
            checksum,
            True,
        )

        if "type" in resp:
            resp = static_analyzer_ios(
                request,
                checksum,
                True,
            )

        if "error" in resp:
            return make_api_response(
                resp,
                500,
            )

        return make_api_response(
            resp,
            200,
        )

    # --------------------------------------------------------------
    # iOS
    # --------------------------------------------------------------
    if scan_type in settings.IOS_EXTS:
        resp = static_analyzer_ios(
            request,
            checksum,
            True,
        )

        if "error" in resp:
            return make_api_response(
                resp,
                500,
            )

        return make_api_response(
            resp,
            200,
        )

    # --------------------------------------------------------------
    # Windows APPX / EXE
    # --------------------------------------------------------------
    if scan_type in settings.WINDOWS_EXTS:
        resp = windows.staticanalyzer_windows(
            request,
            checksum,
            True,
        )

        if "error" in resp:
            return make_api_response(
                resp,
                500,
            )

        return make_api_response(
            resp,
            200,
        )

    # --------------------------------------------------------------
    # Unsupported
    # --------------------------------------------------------------
    return make_api_response(
        {
            "error": (
                f"Unsupported scan type: {scan_type}"
            )
        },
        400,
    )


@request_method(["POST"])
@csrf_exempt
def api_scan_logs(request):
    """POST - Get Scan logs."""

    if "hash" not in request.POST:
        return make_api_response(
            {"error": "Missing Parameters"},
            422,
        )

    checksum = request.POST["hash"]

    if not is_md5(checksum):
        return make_api_response(
            {"error": "Invalid Checksum"},
            400,
        )

    resp = get_scan_logs(
        checksum
    )

    if not resp:
        return make_api_response(
            {"error": "No scan logs found"},
            400,
        )

    return make_api_response(
        {"logs": resp},
        200,
    )


@request_method(["POST"])
@csrf_exempt
def api_tasks(request):
    """POST - Get Scan Queue."""

    resp = list_tasks(
        request,
        True,
    )

    if not resp:
        return make_api_response(
            {"error": "Scan queue empty"},
            400,
        )

    return make_api_response(
        resp,
        200,
    )


@request_method(["POST"])
@csrf_exempt
def api_delete_scan(request):
    """POST - Delete a Scan."""

    if "hash" not in request.POST:
        return make_api_response(
            {"error": "Missing Parameters"},
            422,
        )

    checksum = request.POST["hash"]

    if not is_md5(checksum):
        return make_api_response(
            {"error": "Invalid Checksum"},
            400,
        )

    resp = delete_scan(
        request,
        True,
    )

    if "error" in resp:
        return make_api_response(
            resp,
            500,
        )

    return make_api_response(
        resp,
        200,
    )


@request_method(["POST"])
@csrf_exempt
def api_pdf_report(request):
    """Generate and Download PDF."""

    if "hash" not in request.POST:
        return make_api_response(
            {"error": "Missing Parameters"},
            422,
        )

    checksum = request.POST["hash"]

    if not is_md5(checksum):
        return make_api_response(
            {"error": "Invalid scan hash"},
            400,
        )

    resp = pdf(
        request,
        checksum,
        api=True,
    )

    if "error" in resp:
        if resp.get("error") == "Invalid scan hash":
            return make_api_response(
                resp,
                400,
            )

        return make_api_response(
            resp,
            500,
        )

    if "pdf_dat" in resp:
        response = HttpResponse(
            resp["pdf_dat"],
            content_type="application/pdf",
        )

        response["Access-Control-Allow-Origin"] = "*"

        return response

    if resp.get("report") == "Report not Found":
        return make_api_response(
            resp,
            404,
        )

    return make_api_response(
        {"error": "PDF Generation Error"},
        500,
    )


@request_method(["POST"])
@csrf_exempt
def api_json_report(request):
    """Generate JSON Report."""

    if "hash" not in request.POST:
        return make_api_response(
            {"error": "Missing Parameters"},
            422,
        )

    checksum = request.POST["hash"]

    if not is_md5(checksum):
        return make_api_response(
            {"error": "Invalid scan hash"},
            400,
        )

    resp = pdf(
        request,
        checksum,
        api=True,
        jsonres=True,
    )

    if "error" in resp:
        if resp.get("error") == "Invalid scan hash":
            return make_api_response(
                resp,
                400,
            )

        return make_api_response(
            resp,
            500,
        )

    if "report_dat" in resp:
        return make_api_response(
            resp["report_dat"],
            200,
        )

    if resp.get("report") == "Report not Found":
        return make_api_response(
            resp,
            404,
        )

    return make_api_response(
        {"error": "JSON Generation Error"},
        500,
    )


@request_method(["POST"])
@csrf_exempt
def api_search(request):
    """Search by checksum or text."""

    if "query" not in request.POST:
        return make_api_response(
            {"error": "Missing Parameters"},
            422,
        )

    resp = search(
        request,
        api=True,
    )

    if "checksum" in resp:
        request.POST = {
            "hash": resp["checksum"]
        }

        return api_json_report(
            request
        )

    if "error" in resp:
        return make_api_response(
            resp,
            404,
        )

    return make_api_response(
        {"error": "Search result not found"},
        404,
    )


@request_method(["POST"])
@csrf_exempt
def api_view_source(request):
    """View Source for Android & iOS source file."""

    params = {
        "file",
        "type",
        "hash",
    }

    if set(request.POST) < params:
        return make_api_response(
            {"error": "Missing Parameters"},
            422,
        )

    if request.POST["type"] in {
        "eclipse",
        "studio",
        "apk",
        "java",
        "smali",
    }:
        resp = view_source.run(
            request,
            api=True,
        )
    else:
        resp = ios_view_source.run(
            request,
            api=True,
        )

    if "error" in resp:
        return make_api_response(
            resp,
            500,
        )

    return make_api_response(
        resp,
        200,
    )


@request_method(["POST"])
@csrf_exempt
def api_compare(request):
    """Compare 2 apps."""

    params = {
        "hash1",
        "hash2",
    }

    if set(request.POST) < params:
        return make_api_response(
            {"error": "Missing Parameters"},
            422,
        )

    resp = compare_apps(
        request,
        request.POST["hash1"],
        request.POST["hash2"],
        True,
    )

    if "error" in resp:
        return make_api_response(
            resp,
            500,
        )

    return make_api_response(
        resp,
        200,
    )


@request_method(["POST"])
@csrf_exempt
def api_scorecard(request):
    """Generate App Security Score Card."""

    if "hash" not in request.POST:
        return make_api_response(
            {"error": "Missing Parameters"},
            422,
        )

    checksum = request.POST["hash"]

    if not is_md5(checksum):
        return make_api_response(
            {"error": "Invalid scan hash"},
            400,
        )

    # The scorecard is generated by appsec_dashboard().
    #
    # Android, iOS and Windows EXE/APPX are supported there.
    resp = appsec_dashboard(
        request,
        checksum,
        api=True,
    )

    if not isinstance(resp, dict):
        return make_api_response(
            {
                "error": "Invalid scorecard response"
            },
            500,
        )

    if "error" in resp:
        if resp.get("error") == "Invalid scan hash":
            return make_api_response(
                resp,
                400,
            )

        return make_api_response(
            resp,
            500,
        )

    if "not_found" in resp:
        return make_api_response(
            resp,
            404,
        )

    # Normal scorecard response.
    if "hash" in resp:
        return make_api_response(
            resp,
            200,
        )

    # Compatibility with dashboards returning md5.
    if "md5" in resp:
        resp["hash"] = resp["md5"]

        return make_api_response(
            resp,
            200,
        )

    return make_api_response(
        {
            "error": "JSON Generation Error"
        },
        500,
    )


@request_method(["POST"])
@csrf_exempt
def api_suppress_by_rule_id(request):
    """Suppress a rule by ID."""

    params = {
        "rule",
        "type",
        "hash",
    }

    if set(request.POST) < params:
        return make_api_response(
            {"error": "Missing Parameters"},
            422,
        )

    resp = suppress_by_rule_id(
        request,
        True,
    )

    if "error" in resp:
        return make_api_response(
            resp,
            500,
        )

    return make_api_response(
        resp,
        200,
    )


@request_method(["POST"])
@csrf_exempt
def api_suppress_by_files(request):
    """Suppress a rule by files."""

    params = {
        "rule",
        "hash",
    }

    if set(request.POST) < params:
        return make_api_response(
            {"error": "Missing Parameters"},
            422,
        )

    resp = suppress_by_files(
        request,
        True,
    )

    if "error" in resp:
        return make_api_response(
            resp,
            500,
        )

    return make_api_response(
        resp,
        200,
    )


@request_method(["POST"])
@csrf_exempt
def api_list_suppressions(request):
    """View suppressions."""

    if "hash" not in request.POST:
        return make_api_response(
            {"error": "Missing Parameters"},
            422,
        )

    resp = list_suppressions(
        request,
        True,
    )

    if "error" in resp:
        return make_api_response(
            resp,
            500,
        )

    return make_api_response(
        resp,
        200,
    )


@request_method(["POST"])
@csrf_exempt
def api_delete_suppression(request):
    """Delete a suppression."""

    params = {
        "kind",
        "type",
        "rule",
        "hash",
    }

    if set(request.POST) < params:
        return make_api_response(
            {"error": "Missing Parameters"},
            422,
        )

    resp = delete_suppression(
        request,
        True,
    )

    if "error" in resp:
        return make_api_response(
            resp,
            500,
        )

    return make_api_response(
        resp,
        200,
    )