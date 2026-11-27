"""Non-mutating Markdown security auditor and extraction facade."""
from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from .errors import MDCAGE_ERROR_CODES as ERROR
from .errors import MdCageError
from .model import MdAuditReport, MdCageFinding, MdCageStats, MdLink
from .policy import normalize_policy
from .scanner import sanitize_source


def _input_size(source: object) -> int:
    if type(source) is str:
        try:
            return len(source.encode("utf-8"))
        except UnicodeEncodeError:
            return len(source)
    if type(source) in (bytes, bytearray):
        return len(source)
    if isinstance(source, memoryview):
        try:
            return int(source.nbytes)
        except (ValueError, TypeError):
            return 0
    return 0


def _finding_from_error(error: MdCageError) -> MdCageFinding:
    details = dict(error.details)
    position = details.pop("position", None)
    line = details.pop("line", None)
    column = details.pop("column", None)
    return MdCageFinding(
        code=error.code,
        message=error.reason,
        position=position if isinstance(position, int) else None,
        line=line if isinstance(line, int) else None,
        column=column if isinstance(column, int) else None,
        severity="critical",
        details=details,
    )


def _report_for_error(error: MdCageError, byte_count: int) -> MdAuditReport:
    stats = MdCageStats(bytes=byte_count, findings=1)
    return MdAuditReport(False, (_finding_from_error(error),), stats, tuple())


def audit_markdown(source: object, *, policy: Any = None, preset: Any = None, **options: Any) -> MdAuditReport:
    """Inspect Markdown without requiring the caller to use the rewritten output.

    A report is safe only when no high or critical severity finding exists and
    the finding cap was not reached. Medium and low findings describe malformed
    or lossy constructs that the sanitizer neutralizes deterministically.
    """

    resolved = normalize_policy(policy, preset=preset, **options)
    byte_count = _input_size(source)
    try:
        result = sanitize_source(source, resolved)
    except MdCageError as error:
        return _report_for_error(error, byte_count)
    unsafe = [finding for finding in result.findings if finding.severity in ("high", "critical")]
    findings_overflowed = result.stats.findings > len(result.findings)
    return MdAuditReport(not unsafe and not findings_overflowed, result.findings, result.stats, result.links)


def is_safe_markdown(source: object, *, policy: Any = None, preset: Any = None, **options: Any) -> bool:
    """Return True when audit finds no high or critical severity issue."""

    return audit_markdown(source, policy=policy, preset=preset, **options).safe


def extract_links(source: object, *, policy: Any = None, preset: Any = None, **options: Any) -> Tuple[MdLink, ...]:
    """Extract inline, reference, image, and autolink destinations.

    Dangerous destinations are included with ``safe=False`` so audit pipelines
    can report them without following or fetching them.
    """

    resolved = normalize_policy(policy, preset=preset, **options)
    return tuple(sanitize_source(source, resolved).links)


def validate_markdown(source: object, *, policy: Any = None, preset: Any = None, **options: Any) -> MdAuditReport:
    """Return a safe audit report or raise the first high-severity failure."""

    report = audit_markdown(source, policy=policy, preset=preset, **options)
    if report.safe:
        return report
    unsafe_findings = [finding for finding in report.findings if finding.severity in ("high", "critical")]
    first = unsafe_findings[0] if unsafe_findings else MdCageFinding(
        ERROR["INVALID_INPUT"],
        "Markdown is unsafe",
        severity="critical",
    )
    details: Dict[str, object] = dict(first.details)
    if first.position is not None:
        details["position"] = first.position
    if first.line is not None:
        details["line"] = first.line
    if first.column is not None:
        details["column"] = first.column
    raise MdCageError(first.code, first.message, details)
