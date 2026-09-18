"""Exceptions for the ASAF AI layer."""


class AIError(Exception):
    """Base AI exception."""


class AIProviderUnavailable(AIError):
    """Raised when the configured AI provider is unavailable."""


class AIResponseError(AIError):
    """Raised when an AI provider returns an invalid response."""
