"""AI provider abstraction for ASAF."""
import json
import logging

import requests
from django.conf import settings

from mobsf.AI.exceptions import AIProviderUnavailable, AIResponseError

logger = logging.getLogger(__name__)


class BaseAIProvider:
    """Base class for AI providers."""

    def generate(self, prompt):
        raise NotImplementedError


class OllamaProvider(BaseAIProvider):
    """Local Ollama provider."""

    def __init__(self):
        self.base_url = settings.AI_BASE_URL.rstrip('/')
        self.model = settings.AI_MODEL
        self.timeout = settings.AI_TIMEOUT

    def generate(self, prompt):
        if not self.model:
            raise AIProviderUnavailable('AI model is not configured')
        url = f'{self.base_url}/api/generate'
        payload = {
            'model': self.model,
            'prompt': prompt,
            'stream': False,
            'format': 'json',
        }
        try:
            response = requests.post(url, json=payload, timeout=self.timeout)
            if response.status_code == 429:
                raise AIProviderUnavailable('AI provider rate limit exceeded')
            response.raise_for_status()
            data = response.json()
        except requests.Timeout as exc:
            raise AIProviderUnavailable('AI provider timed out') from exc
        except requests.RequestException as exc:
            raise AIProviderUnavailable('AI provider is unavailable') from exc
        except ValueError as exc:
            raise AIResponseError('AI provider returned invalid JSON') from exc
        text = data.get('response')
        if not text:
            raise AIResponseError('AI provider returned an empty response')
        return text


class ApiLLMProvider(BaseAIProvider):
    """OpenAI-compatible chat-completions provider."""

    def __init__(self):
        self.base_url = settings.AI_BASE_URL.rstrip('/')
        self.api_key = getattr(settings, 'AI_API_KEY', '')
        self.model = settings.AI_MODEL
        self.timeout = settings.AI_TIMEOUT

    def generate(self, prompt):
        if not self.api_key:
            raise AIProviderUnavailable('AI API key is not configured')
        if not self.model:
            raise AIProviderUnavailable('AI model is not configured')
        url = f'{self.base_url}/chat/completions'
        headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json',
        }
        payload = {
            'model': self.model,
            'messages': [{'role': 'user', 'content': prompt}],
            'temperature': 0.2,
            'response_format': {'type': 'json_object'},
        }
        try:
            response = requests.post(
                url,
                headers=headers,
                json=payload,
                timeout=self.timeout,
            )
            if response.status_code == 429:
                raise AIProviderUnavailable('AI provider rate limit exceeded')
            response.raise_for_status()
            data = response.json()
        except requests.Timeout as exc:
            raise AIProviderUnavailable('AI provider timed out') from exc
        except requests.RequestException as exc:
            raise AIProviderUnavailable('AI provider is unavailable') from exc
        except ValueError as exc:
            raise AIResponseError('AI provider returned invalid JSON') from exc
        choices = data.get('choices') or []
        if not choices:
            raise AIResponseError('AI provider returned no choices')
        message = choices[0].get('message') or {}
        text = message.get('content')
        if not text:
            raise AIResponseError('AI provider returned an empty response')
        return text


def get_provider():
    """Return the configured AI provider."""
    if not getattr(settings, 'AI_ENABLED', False):
        raise AIProviderUnavailable('AI is disabled')
    provider = getattr(settings, 'AI_PROVIDER', 'ollama').lower()
    if provider == 'ollama':
        return OllamaProvider()
    if provider in {'api', 'openai', 'generic'}:
        return ApiLLMProvider()
    raise AIProviderUnavailable('Unsupported AI provider')


def parse_provider_json(text):
    """Parse a provider response into a dictionary."""
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise AIResponseError('AI provider returned malformed JSON') from exc
    if not isinstance(data, dict):
        raise AIResponseError('AI provider returned non-object JSON')
    return data
