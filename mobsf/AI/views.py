"""HTTP views for the ASAF AI security intelligence layer."""

from django.views.decorators.csrf import csrf_exempt

from mobsf.AI.analyzer import ASAFAnalyzer
from mobsf.MobSF.utils import is_md5
from mobsf.MobSF.views.api.api_middleware import make_api_response
from mobsf.MobSF.views.helpers import request_method


def _required_post(request, fields):
    missing = [field for field in fields if field not in request.POST]
    if missing:
        return f'Missing Parameters: {", ".join(missing)}'
    return ''


def _checksum_or_error(request):
    error = _required_post(request, ('hash',))
    if error:
        return None, error, 422
    checksum = request.POST['hash']
    if not is_md5(checksum):
        return None, 'Invalid scan hash', 400
    return checksum, '', 200


@request_method(['POST'])
@csrf_exempt
def analyze_finding(request):
    """Analyze one existing ASAF finding with AI."""
    checksum, error, status = _checksum_or_error(request)
    if error:
        return make_api_response({'error': error}, status)
    result = ASAFAnalyzer().analyze_finding(
        checksum,
        request.POST.get('category', ''),
        request.POST.get('index', ''),
        request.POST.get('title', ''),
    )
    return make_api_response(result, 200 if result.get('success') else 500)


@request_method(['POST'])
@csrf_exempt
def scan_summary(request):
    """Generate an AI security summary for a completed ASAF scan."""
    checksum, error, status = _checksum_or_error(request)
    if error:
        return make_api_response({'error': error}, status)
    result = ASAFAnalyzer().scan_summary(checksum)
    return make_api_response(result, 200 if result.get('success') else 500)


@request_method(['POST'])
@csrf_exempt
def ask(request):
    """Answer a user question using current ASAF scan data only."""
    checksum, error, status = _checksum_or_error(request)
    if error:
        return make_api_response({'error': error}, status)
    missing = _required_post(request, ('question',))
    if missing:
        return make_api_response({'error': missing}, 422)
    result = ASAFAnalyzer().ask(checksum, request.POST['question'][:1000])
    return make_api_response(result, 200 if result.get('success') else 500)


@request_method(['POST'])
@csrf_exempt
def remediation(request):
    """Generate remediation guidance for one existing ASAF finding."""
    checksum, error, status = _checksum_or_error(request)
    if error:
        return make_api_response({'error': error}, status)
    result = ASAFAnalyzer().remediation(
        checksum,
        request.POST.get('category', ''),
        request.POST.get('index', ''),
        request.POST.get('title', ''),
    )
    return make_api_response(result, 200 if result.get('success') else 500)


@request_method(['POST'])
@csrf_exempt
def report(request):
    """Generate an AI-enhanced security report from ASAF results."""
    checksum, error, status = _checksum_or_error(request)
    if error:
        return make_api_response({'error': error}, status)
    result = ASAFAnalyzer().report(checksum)
    return make_api_response(result, 200 if result.get('success') else 500)
