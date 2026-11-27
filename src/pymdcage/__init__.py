"""pymdcage: zero-dependency Markdown security sanitization, auditing, and link extraction."""
from __future__ import annotations

__version__ = "1.0.0"
MDCAGE_VERSION = __version__

from .auditor import audit_markdown, extract_links, is_safe_markdown, validate_markdown
from .errors import CODE, ERROR_CODES, MDCAGE_ERROR_CODES, MdCageError
from .model import MdAuditReport, MdCageFinding, MdCageStats, MdLink, MdSanitizeResult
from .policy import DEFAULT_POLICY, MdPolicy, normalize_policy, preset_policy
from .sanitizer import sanitize_markdown


class MdCage:
    """Reusable policy-bound facade for sanitization, audit, and extraction."""

    def __init__(self, policy=None, preset=None, **options) -> None:
        self.policy = normalize_policy(policy, preset=preset, **options)

    def sanitize(self, source, **overrides) -> MdSanitizeResult:
        return sanitize_markdown(source, policy=self.policy, **overrides)

    def audit(self, source, **overrides) -> MdAuditReport:
        return audit_markdown(source, policy=self.policy, **overrides)

    def validate(self, source, **overrides) -> MdAuditReport:
        return validate_markdown(source, policy=self.policy, **overrides)

    def is_safe(self, source, **overrides) -> bool:
        return is_safe_markdown(source, policy=self.policy, **overrides)

    def extract_links(self, source, **overrides):
        return extract_links(source, policy=self.policy, **overrides)


def create_md_cage(policy=None, preset=None, **options) -> MdCage:
    return MdCage(policy, preset=preset, **options)


__all__ = (
    "__version__",
    "MDCAGE_VERSION",
    "MDCAGE_ERROR_CODES",
    "ERROR_CODES",
    "CODE",
    "DEFAULT_POLICY",
    "MdCageError",
    "MdPolicy",
    "MdAuditReport",
    "MdCageFinding",
    "MdCageStats",
    "MdLink",
    "MdSanitizeResult",
    "MdCage",
    "create_md_cage",
    "sanitize_markdown",
    "audit_markdown",
    "validate_markdown",
    "is_safe_markdown",
    "extract_links",
    "normalize_policy",
    "preset_policy",
)
