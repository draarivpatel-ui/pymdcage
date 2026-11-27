"""Immutable public result model for pymdcage."""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Dict, Mapping, Optional, Tuple

from ._immutable import harden_frozen_dataclass


@harden_frozen_dataclass
@dataclass(frozen=True)
class MdCageFinding:
    """One machine-readable security or normalization finding."""

    code: str
    message: str
    severity: str = "high"
    position: Optional[int] = None
    line: Optional[int] = None
    column: Optional[int] = None
    kind: Optional[str] = None
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "details", MappingProxyType(dict(self.details)))

    def to_dict(self) -> Dict[str, Any]:
        output: Dict[str, Any] = {
            "code": self.code,
            "message": self.message,
            "severity": self.severity,
        }
        if self.position is not None:
            output["position"] = self.position
        if self.line is not None:
            output["line"] = self.line
        if self.column is not None:
            output["column"] = self.column
        if self.kind is not None:
            output["kind"] = self.kind
        if self.details:
            output["details"] = dict(self.details)
        return output


@harden_frozen_dataclass
@dataclass(frozen=True)
class MdCageStats:
    """Counts collected during parsing and sanitization."""

    bytes: int = 0
    lines: int = 0
    links: int = 0
    images: int = 0
    autolinks: int = 0
    reference_definitions: int = 0
    reference_links: int = 0
    html_tags: int = 0
    html_comments: int = 0
    code_spans: int = 0
    fenced_code_blocks: int = 0
    hidden_characters: int = 0
    max_nesting_observed: int = 0
    findings: int = 0

    def to_dict(self) -> Dict[str, int]:
        return {
            "bytes": self.bytes,
            "lines": self.lines,
            "links": self.links,
            "images": self.images,
            "autolinks": self.autolinks,
            "reference_definitions": self.reference_definitions,
            "reference_links": self.reference_links,
            "html_tags": self.html_tags,
            "html_comments": self.html_comments,
            "code_spans": self.code_spans,
            "fenced_code_blocks": self.fenced_code_blocks,
            "hidden_characters": self.hidden_characters,
            "max_nesting_observed": self.max_nesting_observed,
            "findings": self.findings,
        }


@harden_frozen_dataclass
@dataclass(frozen=True)
class MdLink:
    """A link-like construct discovered in Markdown source."""

    label: str
    url: str
    kind: str
    position: int
    line: int
    column: int
    external: bool
    safe: bool
    title: Optional[str] = None
    code: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        output: Dict[str, Any] = {
            "label": self.label,
            "url": self.url,
            "kind": self.kind,
            "position": self.position,
            "line": self.line,
            "column": self.column,
            "external": self.external,
            "safe": self.safe,
        }
        if self.title is not None:
            output["title"] = self.title
        if self.code is not None:
            output["code"] = self.code
        return output


@harden_frozen_dataclass
@dataclass(frozen=True)
class MdSanitizeResult:
    """Sanitized Markdown plus audit metadata."""

    markdown: str
    changed: bool
    findings: Tuple[MdCageFinding, ...] = field(default_factory=tuple)
    stats: MdCageStats = field(default_factory=MdCageStats)
    links: Tuple[MdLink, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "findings", tuple(self.findings))
        object.__setattr__(self, "links", tuple(self.links))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "markdown": self.markdown,
            "changed": self.changed,
            "findings": [finding.to_dict() for finding in self.findings],
            "stats": self.stats.to_dict(),
            "links": [link.to_dict() for link in self.links],
        }


@harden_frozen_dataclass
@dataclass(frozen=True)
class MdAuditReport:
    """Non-mutating audit report."""

    safe: bool
    findings: Tuple[MdCageFinding, ...] = field(default_factory=tuple)
    stats: MdCageStats = field(default_factory=MdCageStats)
    links: Tuple[MdLink, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "findings", tuple(self.findings))
        object.__setattr__(self, "links", tuple(self.links))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "safe": self.safe,
            "findings": [finding.to_dict() for finding in self.findings],
            "stats": self.stats.to_dict(),
            "links": [link.to_dict() for link in self.links],
        }
