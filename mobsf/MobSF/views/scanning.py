# -*- coding: utf_8 -*-
"""MobSF File Scanning Helpers."""

import hashlib
import io
import logging
import os

from django.conf import settings
from django.utils import timezone

from mobsf.StaticAnalyzer.models import RecentScansDB
from mobsf.MobSF.security import sanitize_filename

logger = logging.getLogger(__name__)


def add_to_recent_scan(data):
    """Add Entry to Database under Recent Scan."""
    try:
        db_obj = RecentScansDB.objects.filter(MD5=data['hash'])

        if not db_obj.exists():
            new_db_obj = RecentScansDB(
                ANALYZER=data['analyzer'],
                SCAN_TYPE=data['scan_type'],
                FILE_NAME=data['file_name'],
                APP_NAME='',
                PACKAGE_NAME='',
                VERSION_NAME='',
                MD5=data['hash'],
                TIMESTAMP=timezone.now(),
            )
            new_db_obj.save()

    except Exception:
        logger.exception('Adding Scan URL to Database')


def handle_uploaded_file(content, extension):
    """Write uploaded file and return its MD5 checksum."""

    md5 = hashlib.md5()

    # File opened from disk / non-Django upload
    bfr = isinstance(content, io.BufferedReader)

    if bfr:
        while chunk := content.read(8192):
            md5.update(chunk)
    else:
        # Django UploadedFile
        for chunk in content.chunks():
            md5.update(chunk)

    md5sum = md5.hexdigest()

    anal_dir = os.path.join(settings.UPLD_DIR, md5sum)

    if not os.path.exists(anal_dir):
        os.makedirs(anal_dir)

    destination_path = os.path.join(
        anal_dir,
        f'{md5sum}{extension}',
    )

    with open(destination_path, 'wb+') as destination:
        if bfr:
            content.seek(0, 0)

            while chunk := content.read(8192):
                destination.write(chunk)
        else:
            # Reset uploaded file position before writing.
            try:
                content.seek(0)
            except Exception:
                pass

            for chunk in content.chunks():
                destination.write(chunk)

    return md5sum


class Scanning(object):
    """Handle uploaded files and create RecentScansDB entries."""

    def __init__(self, request):
        self.file = request.FILES['file']

        self.file_name = sanitize_filename(
            request.FILES['file'].name
        )

        self.data = {
            'analyzer': 'static_analyzer',
            'status': 'success',
            'hash': '',
            'scan_type': '',
            'file_name': self.file_name,
        }

    def _store(self, extension, scan_type, analyzer=None):
        """
        Store uploaded file and create the RecentScansDB entry.

        This common method keeps all upload types consistent.
        """
        md5 = handle_uploaded_file(self.file, extension)

        self.data['hash'] = md5
        self.data['scan_type'] = scan_type

        if analyzer:
            self.data['analyzer'] = analyzer

        add_to_recent_scan(self.data)

        return self.data

    def scan_apk(self):
        """Android APK."""
        result = self._store(
            '.apk',
            'apk',
        )
        logger.info('Android APK uploaded')
        return result

    def scan_xapk(self):
        """Android XAPK."""
        result = self._store(
            '.xapk',
            'xapk',
        )
        logger.info('Android XAPK uploaded')
        return result

    def scan_apks(self):
        """Android Split APK."""
        result = self._store(
            '.apk',
            'apks',
        )
        logger.info('Android Split APK uploaded')
        return result

    def scan_aab(self):
        """Android App Bundle."""
        result = self._store(
            '.aab',
            'aab',
        )
        logger.info('Android App Bundle uploaded')
        return result

    def scan_jar(self):
        """Java JAR file."""
        result = self._store(
            '.jar',
            'jar',
        )
        logger.info('Java JAR uploaded')
        return result

    def scan_aar(self):
        """Android AAR file."""
        result = self._store(
            '.aar',
            'aar',
        )
        logger.info('Android AAR uploaded')
        return result

    def scan_so(self):
        """Shared object file."""
        result = self._store(
            '.so',
            'so',
        )
        logger.info('Shared Object Library uploaded')
        return result

    def scan_zip(self):
        """Android / iOS zipped source."""
        result = self._store(
            '.zip',
            'zip',
        )
        logger.info('Android/iOS Source code ZIP uploaded')
        return result

    def scan_ipa(self):
        """iOS Binary."""
        result = self._store(
            '.ipa',
            'ipa',
            'static_analyzer_ios',
        )
        logger.info('iOS IPA uploaded')
        return result

    def scan_dylib(self):
        """iOS Dylib."""
        result = self._store(
            '.dylib',
            'dylib',
            'static_analyzer_ios',
        )
        logger.info('iOS dylib uploaded')
        return result

    def scan_a(self):
        """iOS static library."""
        result = self._store(
            '.a',
            'a',
            'static_analyzer_ios',
        )
        logger.info('Static Library uploaded')
        return result

    def scan_appx(self):
        """Windows APPX."""
        result = self._store(
            '.appx',
            'appx',
            'static_analyzer_windows',
        )
        logger.info('Windows APPX uploaded')
        return result

    def scan_exe(self):
        """Windows PE executable."""
        result = self._store(
            '.exe',
            'exe',
            'static_analyzer_windows',
        )
        logger.info('Windows EXE uploaded')
        return result