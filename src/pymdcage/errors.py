"""Typed errors and stable machine-readable codes for pymdcage."""
from __future__ import annotations

from types import MappingProxyType
from typing import Any, Dict, Mapping, Optional

MDCAGE_ERROR_CODES: Dict[str, str] = {
    "INVALID_INPUT": "PYMDCAGE_INVALID_INPUT",
    "INVALID_POLICY": "PYMDCAGE_INVALID_POLICY",
    "INVALID_UTF8": "PYMDCAGE_INVALID_UTF8",
    "INVALID_UNICODE": "PYMDCAGE_INVALID_UNICODE",
    "INPUT_RELEASED": "PYMDCAGE_INPUT_RELEASED",
    "MAX_BYTES": "PYMDCAGE_MAX_BYTES",
    "MAX_OUTPUT_BYTES": "PYMDCAGE_MAX_OUTPUT_BYTES",
    "MAX_LINES": "PYMDCAGE_MAX_LINES",
    "MAX_LINKS": "PYMDCAGE_MAX_LINKS",
    "MAX_REFERENCE_DEFS": "PYMDCAGE_MAX_REFERENCE_DEFS",
    "MAX_NESTING_DEPTH": "PYMDCAGE_MAX_NESTING_DEPTH",
    "MAX_FINDINGS": "PYMDCAGE_MAX_FINDINGS",
    "DANGEROUS_SCHEME": "PYMDCAGE_DANGEROUS_SCHEME",
    "DISALLOWED_SCHEME": "PYMDCAGE_DISALLOWED_SCHEME",
    "MALFORMED_URL": "PYMDCAGE_MALFORMED_URL",
    "MALFORMED_LINK": "PYMDCAGE_MALFORMED_LINK",
    "RAW_HTML": "PYMDCAGE_RAW_HTML",
    "ACTIVE_HTML": "PYMDCAGE_ACTIVE_HTML",
    "HTML_COMMENT": "PYMDCAGE_HTML_COMMENT",
    "EXTERNAL_IMAGE": "PYMDCAGE_EXTERNAL_IMAGE",
    "DISALLOWED_IMAGE_HOST": "PYMDCAGE_DISALLOWED_IMAGE_HOST",
    "PRIVATE_IMAGE_HOST": "PYMDCAGE_PRIVATE_IMAGE_HOST",
    "HIDDEN_REFERENCE": "PYMDCAGE_HIDDEN_REFERENCE",
    "UNUSED_REFERENCE": "PYMDCAGE_UNUSED_REFERENCE",
    "MALFORMED_REFERENCE": "PYMDCAGE_MALFORMED_REFERENCE",
    "INVISIBLE_UNICODE": "PYMDCAGE_INVISIBLE_UNICODE",
    "UNICODE_TAGS": "PYMDCAGE_UNICODE_TAGS",
    "BIDI_CONTROL": "PYMDCAGE_BIDI_CONTROL",
    "CONTROL_CHARACTER": "PYMDCAGE_CONTROL_CHARACTER",
    "UNPAIRED_SURROGATE": "PYMDCAGE_UNPAIRED_SURROGATE",
    "UNCLOSED_FENCE": "PYMDCAGE_UNCLOSED_FENCE",
    "UNCLOSED_CODE_SPAN": "PYMDCAGE_UNCLOSED_CODE_SPAN",
    "SERIALIZATION_ERROR": "PYMDCAGE_SERIALIZATION_ERROR",
}

CODE = MDCAGE_ERROR_CODES
ERROR_CODES = MDCAGE_ERROR_CODES

for _constant_name, _constant_value in MDCAGE_ERROR_CODES.items():
    globals()[_constant_value] = _constant_value


class MdCageError(ValueError):
    """Security-policy, input-validation, or resource-bound failure.

    ``code`` is stable and machine-readable. ``reason`` is the human-readable
    message without the code prefix. Additional structured values live in the
    immutable ``details`` mapping.
    """

    def __init__(self, code: str, message: str, details: Optional[Mapping[str, Any]] = None) -> None:
        self.code = code
        self.reason = message
        clean_details: Dict[str, Any] = {}
        if details:
            for key, value in details.items():
                if value is not None:
                    clean_details[key] = value
        self.details = MappingProxyType(clean_details)
        reserved_attributes = frozenset({"code", "reason", "details", "args"})
        for key, value in clean_details.items():
            attribute_name = "md_name" if key == "name" else key
            if (
                attribute_name.isidentifier()
                and attribute_name not in reserved_attributes
                and not hasattr(type(self), attribute_name)
            ):
                object.__setattr__(self, attribute_name, value)
        super().__init__(code + ": " + message)

    def to_dict(self) -> Dict[str, Any]:
        output: Dict[str, Any] = {
            "name": type(self).__name__,
            "code": self.code,
            "reason": self.reason,
        }
        for key, value in self.details.items():
            output[key] = value
        return output
