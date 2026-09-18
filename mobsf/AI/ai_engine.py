"""Core AI engine for ASAF."""
import logging

from mobsf.AI.exceptions import AIError
from mobsf.AI.providers import get_provider, parse_provider_json
from mobsf.AI.serializers import AI_UNAVAILABLE

logger = logging.getLogger(__name__)


class AIEngine:
    """Run prompts against the configured provider and normalize errors."""

    def __init__(self, provider=None):
        self.provider = provider

    def generate_json(self, prompt, fallback=None):
        """Return a structured AI response or a graceful fallback."""
        try:
            provider = self.provider or get_provider()
            data = parse_provider_json(provider.generate(prompt))
            data['success'] = bool(data.get('success', True))
            data['ai_generated'] = True
            data.setdefault('limitations', [])
            return data
        except AIError as exp:
            logger.warning('ASAF AI unavailable: %s', exp)
        except Exception:
            logger.exception('ASAF AI unexpected failure')
        response = {
            'success': False,
            'ai_generated': True,
            'error': AI_UNAVAILABLE,
            'limitations': [AI_UNAVAILABLE],
        }
        if fallback:
            response.update(fallback)
        return response
