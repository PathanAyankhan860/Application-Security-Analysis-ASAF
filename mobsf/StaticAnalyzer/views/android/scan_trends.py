# -*- coding: utf_8 -*-
"""Vulnerability Score Trends (SentinelX Feature)."""

import logging

from mobsf.MobSF.utils import python_dict, python_list
from mobsf.StaticAnalyzer.models import StaticAnalyzerAndroid, RecentScansDB
from mobsf.StaticAnalyzer.views.android.risk_score import calculate_risk_score
from mobsf.StaticAnalyzer.views.common.suppression import (
    process_suppression,
    process_suppression_manifest,
)

logger = logging.getLogger(__name__)


def get_scan_trends(context: dict) -> dict:
    """Return historical risk score trends for the current package."""
    trends = []

    package_name = context.get('package_name')
    if not package_name:
        return {'trends': trends}

    try:
        recent_scans = RecentScansDB.objects.filter(
            PACKAGE_NAME=package_name
        ).order_by('TIMESTAMP')

        for scan in recent_scans:
            try:
                sa_entry = StaticAnalyzerAndroid.objects.get(
                    MD5=scan.MD5
                )

                package = sa_entry.PACKAGE_NAME

                code = process_suppression(
                    python_dict(sa_entry.CODE_ANALYSIS),
                    package)

                manifest_analysis = process_suppression_manifest(
                    python_list(sa_entry.MANIFEST_ANALYSIS),
                    package)

                mini_context = {
                    'package_name': package,
                    'manifest_analysis': manifest_analysis,
                    'code_analysis': code,
                    'binary_analysis': python_list(
                        sa_entry.BINARY_ANALYSIS),
                }

                risk_score = calculate_risk_score(mini_context)

                if not isinstance(risk_score, dict):
                    continue

                score = risk_score.get('score')
                grade = risk_score.get('grade')

                if score is None:
                    continue

                if grade is None:
                    grade = ''

                timestamp = getattr(scan, 'TIMESTAMP', None)

                if timestamp:
                    date_str = timestamp.strftime('%Y-%m-%d %H:%M')
                else:
                    date_str = ''

                trends.append({
                    'date': date_str,
                    'score': score,
                    'grade': grade,
                })

            except Exception:
                logger.exception(
                    'Failed to process individual history entry.')
                continue

    except Exception:
        logger.exception(
            'Retrieval of application scan trends failed.')

    return {'trends': trends}