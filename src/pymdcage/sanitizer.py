"""Public Markdown sanitization API."""
from __future__ import annotations

from typing import Any

from .model import MdSanitizeResult
from .policy import normalize_policy
from .scanner import sanitize_source


def sanitize_markdown(source: object, *, policy: Any = None, preset: Any = None, **options: Any) -> MdSanitizeResult:
    """Sanitize Markdown and return rewritten Markdown plus security metadata.

    The operation is deterministic and idempotent for every policy. Dangerous
    link destinations are unlinked, unsafe images are reduced to inert alt
    text, raw HTML and comments are removed, and invisible Unicode controls
    are stripped.
    """

    resolved = normalize_policy(policy, preset=preset, **options)
    return sanitize_source(source, resolved)
