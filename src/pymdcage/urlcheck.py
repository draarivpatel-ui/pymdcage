"""Linear URL scheme, image, and SSRF inspection."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Optional, Union
from urllib.parse import unquote, urlsplit

from ._text import canonicalize_url_text
from .errors import MDCAGE_ERROR_CODES as ERROR
from .policy import MdPolicy

_HARD_BLOCKED_SCHEMES = frozenset({"javascript", "vbscript", "data", "file", "blob"})
_LOCAL_HOSTNAMES = frozenset({
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "metadata",
    "metadata.google.internal",
})


@dataclass(frozen=True)
class UrlInspection:
    raw: str
    canonical: str
    safe: bool
    code: Optional[str]
    reason: str
    scheme: str = ""
    external: bool = False
    host: str = ""
    private_host: bool = False
    severity: str = "high"


def _valid_scheme(value: str) -> bool:
    if not value or not ("a" <= value[0].lower() <= "z"):
        return False
    for character in value[1:]:
        lowered = character.lower()
        if not (("a" <= lowered <= "z") or ("0" <= character <= "9") or character in "+-."):
            return False
    return True


def _split_scheme(compact: str) -> str:
    colon = compact.find(":")
    if colon <= 0:
        return ""
    for delimiter in "/?#":
        position = compact.find(delimiter)
        if position != -1 and position < colon:
            return ""
    candidate = compact[:colon]
    if _valid_scheme(candidate):
        return candidate.lower()
    return ""


def _parse_integer_part(part: str) -> Optional[int]:
    if not part:
        return None
    base = 10
    digits = part
    lowered = part.lower()
    if lowered.startswith("0x"):
        base = 16
        digits = part[2:]
        valid = "0123456789abcdefABCDEF"
    elif len(part) > 1 and part.startswith("0"):
        base = 8
        digits = part[1:]
        valid = "01234567"
        if digits == "":
            return 0
    else:
        valid = "0123456789"
    if not digits or any(character not in valid for character in digits):
        return None
    try:
        return int(digits, base)
    except ValueError:
        return None


def _looks_like_numeric_ipv4(host: str) -> bool:
    if not host:
        return False
    stripped = host.rstrip(".")
    if all(character in "0123456789." for character in stripped):
        return True
    return any(part.lower().startswith("0x") for part in stripped.split("."))


def _parse_obfuscated_ipv4(host: str) -> Union[ipaddress.IPv4Address, str, None]:
    stripped = host.rstrip(".").lower()
    parts = stripped.split(".")
    if len(parts) > 4 or not parts or any(part == "" for part in parts):
        return "invalid"
    values = []
    for part in parts:
        value = _parse_integer_part(part)
        if value is None:
            return None if not _looks_like_numeric_ipv4(host) else "invalid"
        values.append(value)
    if len(values) == 4:
        if any(value > 0xFF for value in values):
            return "invalid"
        number = 0
        for value in values:
            number = (number << 8) | value
    else:
        for value in values[:-1]:
            if value > 0xFF:
                return "invalid"
        remaining_bytes = 5 - len(values)
        if values[-1] >= (1 << (8 * remaining_bytes)):
            return "invalid"
        number = 0
        for value in values[:-1]:
            number = (number << 8) | value
        number = (number << (8 * remaining_bytes)) | values[-1]
    if number > 0xFFFFFFFF:
        return "invalid"
    try:
        return ipaddress.IPv4Address(number)
    except ipaddress.AddressValueError:
        return "invalid"


def _ip_is_blocked(address: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> bool:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return _ip_is_blocked(address.ipv4_mapped)
    if address.is_loopback or address.is_private or address.is_link_local:
        return True
    if address.is_multicast or address.is_unspecified or address.is_reserved:
        return True
    return not address.is_global


def _canonicalize_host(host: str) -> Optional[str]:
    """Decode browser-style Unicode and percent-encoded host names for inspection."""

    try:
        decoded = unquote(host, errors="strict")
    except (UnicodeDecodeError, ValueError):
        return None
    if not decoded:
        return ""
    if ":" in decoded:
        return decoded.lower()
    for character in decoded:
        codepoint = ord(character)
        if codepoint <= 0x20 or codepoint == 0x7F or character in "#%/<>:?@[\\]^|":
            return None
    try:
        return decoded.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        return None


def _host_is_private(host: str) -> bool:
    normalized = host.strip().lower().rstrip(".")
    if not normalized:
        return True
    if normalized in _LOCAL_HOSTNAMES or normalized.endswith(".localhost"):
        return True
    if normalized.startswith("[") and normalized.endswith("]"):
        normalized = normalized[1:-1]
    if "%" in normalized:
        normalized = normalized.split("%", 1)[0]
    if ":" in normalized:
        try:
            address = ipaddress.ip_address(normalized)
        except ValueError:
            return True
        return _ip_is_blocked(address)
    parsed_ipv4 = _parse_obfuscated_ipv4(normalized)
    if isinstance(parsed_ipv4, ipaddress.IPv4Address):
        return _ip_is_blocked(parsed_ipv4)
    if parsed_ipv4 == "invalid":
        return True
    return False


def _host_allowed(host: str, policy: MdPolicy) -> bool:
    if not policy.allowed_image_hosts:
        return True
    normalized = host.lower().rstrip(".")
    for allowed in policy.allowed_image_hosts:
        if allowed.startswith("*."):
            suffix = allowed[2:]
            if normalized == suffix or normalized.endswith("." + suffix):
                return True
        elif normalized == allowed:
            return True
    return False


def inspect_url(raw: str, policy: MdPolicy, *, image: bool = False) -> UrlInspection:
    """Inspect a destination after entity, escape, whitespace, and case decoding."""

    compact = canonicalize_url_text(raw)
    scheme_probe = compact.replace("\\", "")
    host_probe = compact.replace("\\", "/")
    scheme = _split_scheme(scheme_probe)

    if not compact:
        return UrlInspection(raw, compact, True, None, "empty destination is inert")
    if compact.startswith("#"):
        return UrlInspection(raw, compact, True, None, "fragment destination is local")
    if scheme in _HARD_BLOCKED_SCHEMES:
        return UrlInspection(
            raw,
            compact,
            False,
            ERROR["DANGEROUS_SCHEME"],
            "dangerous URL scheme is blocked",
            scheme=scheme,
            severity="critical",
        )
    if scheme and scheme not in policy.allowed_schemes:
        return UrlInspection(
            raw,
            compact,
            False,
            ERROR["DISALLOWED_SCHEME"],
            "URL scheme is not allowed by policy",
            scheme=scheme,
        )

    protocol_relative = host_probe.startswith("//")
    if scheme in ("http", "https") or protocol_relative:
        parse_input = host_probe
        if protocol_relative:
            parse_input = "http:" + host_probe
        try:
            parts = urlsplit(parse_input)
            host = parts.hostname or ""
        except ValueError:
            return UrlInspection(
                raw,
                compact,
                False,
                ERROR["MALFORMED_URL"],
                "URL host is malformed",
                scheme=scheme,
                external=True,
                severity="high",
            )
        canonical_host = _canonicalize_host(host)
        if host and canonical_host is None:
            return UrlInspection(
                raw,
                compact,
                False,
                ERROR["MALFORMED_URL"],
                "URL host is malformed",
                scheme=scheme,
                external=True,
                host=host,
                severity="high",
            )
        host = canonical_host or ""
        private_host = bool(host) and _host_is_private(host)
        if image:
            if private_host:
                return UrlInspection(
                    raw,
                    compact,
                    False,
                    ERROR["PRIVATE_IMAGE_HOST"],
                    "image host resolves to a loopback, private, link-local, or otherwise non-public address",
                    scheme=scheme,
                    external=True,
                    host=host,
                    private_host=True,
                    severity="critical",
                )
            if not policy.allow_external_images:
                return UrlInspection(
                    raw,
                    compact,
                    False,
                    ERROR["EXTERNAL_IMAGE"],
                    "external images are disabled by policy",
                    scheme=scheme,
                    external=True,
                    host=host,
                )
            if not host or not _host_allowed(host, policy):
                return UrlInspection(
                    raw,
                    compact,
                    False,
                    ERROR["DISALLOWED_IMAGE_HOST"],
                    "image host is not in the allowed image host list",
                    scheme=scheme,
                    external=True,
                    host=host,
                )
        return UrlInspection(
            raw,
            compact,
            True,
            None,
            "network URL uses an allowed scheme",
            scheme=scheme,
            external=True,
            host=host,
        )

    if host_probe.startswith("\\\\") or host_probe.startswith("//"):
        return UrlInspection(
            raw,
            compact,
            False,
            ERROR["MALFORMED_URL"],
            "ambiguous network-path destination is blocked",
            scheme=scheme,
            external=True,
        )
    return UrlInspection(raw, compact, True, None, "relative or non-network destination is allowed", scheme=scheme)
