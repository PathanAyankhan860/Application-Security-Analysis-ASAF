"""Tests for the ASAF AI security intelligence layer."""
import json
from unittest.mock import patch

from django.test import TestCase, override_settings

from mobsf.AI.ai_engine import AIEngine
from mobsf.AI.exceptions import AIProviderUnavailable
from mobsf.AI.providers import parse_provider_json
from mobsf.AI.serializers import (
    AI_UNAVAILABLE,
    INSUFFICIENT_EVIDENCE,
    normalize_finding,
    severity_summary,
)


class FakeProvider:
    def __init__(self, payload):
        self.payload = payload

    def generate(self, prompt):
        return json.dumps(self.payload)


class TimeoutProvider:
    def generate(self, prompt):
        raise AIProviderUnavailable('timeout')


class ASAFAITests(TestCase):
    def test_normalize_finding_preserves_asaf_evidence(self):
        finding = normalize_finding(
            'code_analysis',
            '0',
            {
                'title': 'Hardcoded Secret',
                'severity': 'high',
                'file': 'app/src/MainActivity.java',
                'line': '42',
                'evidence': 'API_KEY detected',
            },
        )
        self.assertEqual(finding['title'], 'Hardcoded Secret')
        self.assertEqual(finding['severity'], 'high')
        self.assertEqual(finding['evidence'], 'API_KEY detected')
        self.assertEqual(finding['limitations'], [])

    def test_normalize_finding_marks_insufficient_evidence(self):
        finding = normalize_finding('code_analysis', '0', {})
        self.assertIn(INSUFFICIENT_EVIDENCE, finding['limitations'])

    def test_severity_summary_does_not_reclassify_original_values(self):
        summary = severity_summary([
            {'severity': 'critical'},
            {'severity': 'High'},
            {'severity': 'warning'},
            {'severity': 'info'},
            {'severity': ''},
        ])
        self.assertEqual(summary['critical'], 1)
        self.assertEqual(summary['high'], 1)
        self.assertEqual(summary['medium'], 1)
        self.assertEqual(summary['informational'], 1)
        self.assertEqual(summary['unknown'], 1)

    def test_parse_provider_json_rejects_malformed_response(self):
        with self.assertRaises(Exception):
            parse_provider_json('not json')

    @override_settings(AI_ENABLED=True)
    def test_ai_engine_returns_provider_json(self):
        engine = AIEngine(provider=FakeProvider({'answer': 'ok'}))
        response = engine.generate_json('prompt')
        self.assertTrue(response['success'])
        self.assertTrue(response['ai_generated'])
        self.assertEqual(response['answer'], 'ok')

    def test_ai_engine_falls_back_when_provider_unavailable(self):
        engine = AIEngine(provider=TimeoutProvider())
        response = engine.generate_json('prompt')
        self.assertFalse(response['success'])
        self.assertIn(AI_UNAVAILABLE, response['limitations'])

    @patch('mobsf.AI.analyzer.get_scan_context')
    def test_analyze_missing_finding_returns_insufficient_evidence(self, ctx):
        from mobsf.AI.analyzer import ASAFAnalyzer

        ctx.return_value = {
            'application': {'name': 'Demo'},
            'findings': [],
        }
        response = ASAFAnalyzer(engine=AIEngine(provider=FakeProvider({}))).analyze_finding(
            'a' * 32,
            'code_analysis',
            '0',
        )
        self.assertFalse(response['success'])
        self.assertEqual(response['error'], INSUFFICIENT_EVIDENCE)
