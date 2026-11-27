"""Immutable sanitizer policy objects and validated presets."""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import Any, FrozenSet, Iterable, Mapping, Optional

from ._immutable import harden_frozen_dataclass
from .errors import MDCAGE_ERROR_CODES as ERROR
from .errors import MdCageError

_URI_SCHEME_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789+-.")
_HARD_BLOCKED_SCHEMES = frozenset({"javascript", "vbscript", "data", "file", "blob"})


def _invalid_policy(message: str, field_name: Optional[str] = None) -> MdCageError:
    return MdCageError(ERROR["INVALID_POLICY"], message, {"field": field_name})


def _freeze_schemes(value: Iterable[str]) -> FrozenSet[str]:
    if isinstance(value, str):
        raw_items = (value,)
    else:
        try:
            raw_items = tuple(value)
        except TypeError:
            raise _invalid_policy("allowed_schemes must be an iterable of scheme names", "allowed_schemes")
    schemes = []
    for item in raw_items:
        if type(item) is not str:
            raise _invalid_policy("allowed_schemes entries must be strings", "allowed_schemes")
        scheme = item.strip().lower()
        if not scheme or not ("a" <= scheme[0] <= "z"):
            raise _invalid_policy("allowed_schemes entries must be valid URI schemes", "allowed_schemes")
        if any(character not in _URI_SCHEME_CHARS for character in scheme):
            raise _invalid_policy("allowed_schemes entries must be valid URI schemes", "allowed_schemes")
        if scheme in _HARD_BLOCKED_SCHEMES:
            raise _invalid_policy("dangerous URI schemes cannot be enabled", "allowed_schemes")
        schemes.append(scheme)
    return frozenset(schemes)


def _freeze_hosts(value: Iterable[str]) -> FrozenSet[str]:
    if isinstance(value, str):
        raw_items = (value,)
    else:
        try:
            raw_items = tuple(value)
        except TypeError:
            raise _invalid_policy("allowed_image_hosts must be an iterable of host names", "allowed_image_hosts")
    hosts = []
    for item in raw_items:
        if type(item) is not str:
            raise _invalid_policy("allowed_image_hosts entries must be strings", "allowed_image_hosts")
        host = item.strip().lower().rstrip(".")
        if not host:
            raise _invalid_policy("allowed_image_hosts entries must not be empty", "allowed_image_hosts")
        if len(host) > 253 or any(ord(character) < 0x21 or ord(character) > 0x7E for character in host):
            raise _invalid_policy("allowed_image_hosts entries must be printable ASCII host names", "allowed_image_hosts")
        if any(character in host for character in "/?#@[]"):
            raise _invalid_policy("allowed_image_hosts entries must be host names only", "allowed_image_hosts")
        if host.startswith("*.") and len(host) <= 2:
            raise _invalid_policy("wildcard image hosts must include a suffix", "allowed_image_hosts")
        hosts.append(host)
    return frozenset(hosts)


def _validate_bool(name: str, value: Any) -> bool:
    if type(value) is not bool:
        raise _invalid_policy(name + " must be a boolean", name)
    return value


def _validate_int(name: str, value: Any, minimum: int = 1) -> int:
    if type(value) is not int or value < minimum or value > 4294967295:
        raise _invalid_policy(name + " must be an integer within the supported range", name)
    return value


@harden_frozen_dataclass
@dataclass(frozen=True)
class MdPolicy:
    """Immutable Markdown validation and sanitization policy.

    The default policy is the agent-oriented baseline: raw HTML and external
    images are disabled, reference definitions are unfolded or removed, and
    only http, https, mailto, relative, and fragment destinations are allowed.
    """

    allowed_schemes: FrozenSet[str] = field(default=frozenset({"http", "https", "mailto"}))
    allow_html: bool = False
    allow_external_images: bool = False
    allowed_image_hosts: FrozenSet[str] = field(default=frozenset())
    allow_reference_definitions: bool = False
    allow_autolinks: bool = True
    max_bytes: int = 1048576
    max_output_bytes: int = 1048576
    max_lines: int = 20000
    max_links: int = 2000
    max_reference_defs: int = 500
    max_nesting_depth: int = 32
    max_findings: int = 1024

    def __post_init__(self) -> None:
        object.__setattr__(self, "allowed_schemes", _freeze_schemes(self.allowed_schemes))
        object.__setattr__(self, "allowed_image_hosts", _freeze_hosts(self.allowed_image_hosts))
        for name in (
            "allow_html",
            "allow_external_images",
            "allow_reference_definitions",
            "allow_autolinks",
        ):
            _validate_bool(name, getattr(self, name))
        for name in (
            "max_bytes",
            "max_output_bytes",
            "max_lines",
            "max_links",
            "max_reference_defs",
            "max_nesting_depth",
        ):
            _validate_int(name, getattr(self, name))
        _validate_int("max_findings", self.max_findings, minimum=0)

    def replace(self, **changes: Any) -> "MdPolicy":
        return dataclasses.replace(self, **changes)


DEFAULT_POLICY = MdPolicy()
_POLICY_FIELDS = frozenset(field.name for field in dataclasses.fields(MdPolicy))


def _preset_values(name: str) -> Mapping[str, Any]:
    if name == "strict":
        return {
            "allowed_schemes": frozenset({"https", "mailto"}),
            "allow_html": False,
            "allow_external_images": False,
            "allow_reference_definitions": False,
            "allow_autolinks": False,
        }
    if name == "agent":
        return {
            "allowed_schemes": frozenset({"http", "https", "mailto"}),
            "allow_html": False,
            "allow_external_images": False,
            "allow_reference_definitions": False,
            "allow_autolinks": True,
        }
    if name == "docs":
        return {
            "allowed_schemes": frozenset({"http", "https", "mailto"}),
            "allow_html": False,
            "allow_external_images": True,
            "allow_reference_definitions": True,
            "allow_autolinks": True,
        }
    raise _invalid_policy("unknown preset " + repr(name), "preset")


def preset_policy(name: str) -> MdPolicy:
    """Return a validated immutable policy for a named preset."""

    return DEFAULT_POLICY.replace(**dict(_preset_values(name)))


def normalize_policy(policy: Any = None, preset: Optional[str] = None, **overrides: Any) -> MdPolicy:
    """Return a validated policy from a preset, policy, mapping, and overrides."""

    if preset is not None:
        if type(preset) is not str:
            raise _invalid_policy("preset must be a string", "preset")
        values = dict(_preset_values(preset))
    else:
        values = {}

    if policy is not None:
        if isinstance(policy, MdPolicy):
            for name in _POLICY_FIELDS:
                if preset is None or name not in values:
                    values[name] = getattr(policy, name)
                elif getattr(policy, name) != getattr(DEFAULT_POLICY, name):
                    values[name] = getattr(policy, name)
        elif isinstance(policy, Mapping):
            values.update(dict(policy))
        else:
            raise _invalid_policy("policy must be an MdPolicy, mapping, or None")

    for key in overrides:
        if key not in _POLICY_FIELDS:
            raise _invalid_policy("unknown policy option " + repr(key), key)
    for key in values:
        if key not in _POLICY_FIELDS:
            raise _invalid_policy("unknown policy option " + repr(key), key)
    values.update(overrides)

    if preset is None and isinstance(policy, MdPolicy) and not overrides:
        return policy
    merged = {name: getattr(DEFAULT_POLICY, name) for name in _POLICY_FIELDS}
    merged.update(values)
    return MdPolicy(**merged)


def policy_for_options(policy: Any = None, preset: Optional[str] = None, **options: Any) -> MdPolicy:
    """Compatibility helper used by the public APIs."""

    return normalize_policy(policy, preset=preset, **options)
