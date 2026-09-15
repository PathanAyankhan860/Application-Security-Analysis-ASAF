# -*- coding: utf_8 -*-
"""Permission Risk Visualization (SentinelX Feature #4)."""

FRIENDLY_NAMES = {
    'CAMERA': 'Camera',
    'RECORD_AUDIO': 'Microphone',
    'ACCESS_FINE_LOCATION': 'Precise Location',
    'ACCESS_COARSE_LOCATION': 'Approximate Location',
    'ACCESS_BACKGROUND_LOCATION': 'Background Location',
    'READ_CONTACTS': 'Contacts (Read)',
    'WRITE_CONTACTS': 'Contacts (Write)',
    'GET_ACCOUNTS': 'Your Accounts',
    'READ_CALL_LOG': 'Call History (Read)',
    'WRITE_CALL_LOG': 'Call History (Write)',
    'CALL_PHONE': 'Make Phone Calls',
    'READ_PHONE_STATE': 'Phone Status/Identity',
    'READ_SMS': 'SMS Messages (Read)',
    'SEND_SMS': 'Send SMS Messages',
    'RECEIVE_SMS': 'Receive SMS Messages',
    'READ_EXTERNAL_STORAGE': 'Storage (Read Files)',
    'WRITE_EXTERNAL_STORAGE': 'Storage (Write Files)',
    'MANAGE_EXTERNAL_STORAGE': 'All Files Access',
    'READ_MEDIA_IMAGES': 'Photos',
    'READ_MEDIA_VIDEO': 'Videos',
    'READ_MEDIA_AUDIO': 'Music/Audio Files',
    'BODY_SENSORS': 'Body Sensors',
    'ACTIVITY_RECOGNITION': 'Physical Activity',
    'BLUETOOTH': 'Bluetooth',
    'BLUETOOTH_CONNECT': 'Bluetooth Devices',
    'BLUETOOTH_SCAN': 'Find Nearby Bluetooth Devices',
    'NFC': 'NFC (Tap to Pay/Share)',
    'INTERNET': 'Internet Access',
    'ACCESS_NETWORK_STATE': 'Network Status',
    'ACCESS_WIFI_STATE': 'WiFi Status',
    'CHANGE_WIFI_STATE': 'Change WiFi Settings',
    'WAKE_LOCK': 'Keep Device Awake',
    'RECEIVE_BOOT_COMPLETED': 'Run at Startup',
    'FOREGROUND_SERVICE': 'Run Background Tasks',
    'POST_NOTIFICATIONS': 'Send Notifications',
    'REQUEST_INSTALL_PACKAGES': 'Install Other Apps',
    'REQUEST_DELETE_PACKAGES': 'Uninstall Other Apps',
    'QUERY_ALL_PACKAGES': 'See Installed Apps',
    'SYSTEM_ALERT_WINDOW': 'Display Over Other Apps',
    'USE_BIOMETRIC': 'Fingerprint/Face Unlock',
    'USE_FINGERPRINT': 'Fingerprint Unlock',
    'VIBRATE': 'Control Vibration',
    'UPDATE_PACKAGES_WITHOUT_USER_ACTION': 'Update Apps Silently',
    'ENFORCE_UPDATE_OWNERSHIP': 'Manage App Updates',
}


def _friendly_name(short_name):
    """Convert technical permission name to plain English if known."""
    return FRIENDLY_NAMES.get(short_name.upper(), short_name)


def get_permission_chart_data(context):
    """
    Count permissions by status and group permission names by status,
    for pie chart rendering on the report page.
    """
    permissions = context.get('permissions', {})
    if not isinstance(permissions, dict):
        permissions = {}

    counts = {
        'dangerous': 0,
        'normal': 0,
        'signature': 0,
        'signatureOrSystem': 0,
        'unknown': 0,
    }

    groups = {
        'dangerous': [],
        'normal': [],
        'signature': [],
        'signatureOrSystem': [],
        'unknown': [],
    }

    for perm_name, desc in permissions.items():
        if not isinstance(desc, dict):
            continue
        status = desc.get('status', 'unknown')
        if status not in counts:
            status = 'unknown'
        counts[status] += 1
        short_name = perm_name.split('.')[-1]
        groups[status].append({
            'name': perm_name,
            'short_name': short_name,
            'friendly_name': _friendly_name(short_name),
            'info': desc.get('info', ''),
        })

    total = sum(counts.values())

    return {
        'labels': list(counts.keys()),
        'counts': list(counts.values()),
        'total': total,
        'dangerous_count': counts['dangerous'],
        'normal_count': counts['normal'],
        'dangerous_perms': groups['dangerous'],
        'normal_perms': groups['normal'],
        'signature_perms': groups['signature'],
        'signatureOrSystem_perms': groups['signatureOrSystem'],
        'unknown_perms': groups['unknown'],
    }