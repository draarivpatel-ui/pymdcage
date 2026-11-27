"""Linear Unicode, entity, and escaping helpers."""
from __future__ import annotations

from html.entities import html5
from typing import Optional, Tuple

_ASCII_PUNCTUATION = frozenset("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~")


def _decode_numeric_entity(text: str, amp: int) -> Optional[Tuple[str, int]]:
    size = len(text)
    index = amp + 2
    if index >= size:
        return None
    base = 10
    if text[index] in "xX":
        base = 16
        index += 1
    start = index
    value = 0
    overflow = False
    while index < size:
        character = text[index]
        if "0" <= character <= "9":
            digit = ord(character) - ord("0")
        elif base == 16 and "a" <= character <= "f":
            digit = ord(character) - ord("a") + 10
        elif base == 16 and "A" <= character <= "F":
            digit = ord(character) - ord("A") + 10
        else:
            break
        if not overflow:
            value = value * base + digit
            if value > 0x10FFFF:
                overflow = True
                value = 0x110000
        index += 1
    if index == start:
        return None
    end = index
    if end < size and text[end] == ";":
        end += 1
    if value <= 0 or value > 0x10FFFF or 0xD800 <= value <= 0xDFFF:
        return None
    return chr(value), end


def _decode_named_entity(text: str, amp: int) -> Optional[Tuple[str, int]]:
    size = len(text)
    maximum = min(size, amp + 34)
    best = None
    end = amp + 2
    while end <= maximum:
        candidate = text[amp + 1:end]
        if candidate in html5:
            best = (html5[candidate], end)
        end += 1
    return best


def decode_entity_at(text: str, amp: int) -> Optional[Tuple[str, int]]:
    """Decode one entity at an ampersand without scanning the whole document."""

    if amp + 2 >= len(text) or text[amp] != "&":
        return None
    if text[amp + 1] == "#":
        return _decode_numeric_entity(text, amp)
    return _decode_named_entity(text, amp)


def decode_html_entities_once(text: str) -> str:
    """Decode one layer of HTML entities with a bounded linear scan."""

    if "&" not in text:
        return text
    output = []
    index = 0
    size = len(text)
    while index < size:
        character = text[index]
        if character != "&" or index + 2 >= size:
            output.append(character)
            index += 1
            continue
        decoded = None
        if text[index + 1] == "#":
            decoded = _decode_numeric_entity(text, index)
        else:
            decoded = _decode_named_entity(text, index)
        if decoded is None:
            output.append(character)
            index += 1
        else:
            output.append(decoded[0])
            index = decoded[1]
    return "".join(output)


def decode_html_entities(text: str, rounds: int = 4) -> str:
    """Decode nested entity layers a fixed small number of times."""

    current = text
    for _round in range(rounds):
        decoded = decode_html_entities_once(current)
        if decoded == current:
            break
        current = decoded
    return current


def percent_decode_ascii(text: str) -> str:
    """Recursively decode ASCII percent escapes in one linear pass.

    Every collapse removes two characters, so recursive decoding cannot
    expand the input or become quadratic even for deeply nested ``%25`` chains.
    """

    if "%" not in text:
        return text
    hexadecimal = "0123456789abcdefABCDEF"
    output = []
    for character in text:
        output.append(character)
        while len(output) >= 3 and output[-3] == "%" and output[-2] in hexadecimal and output[-1] in hexadecimal:
            value = int(output[-2] + output[-1], 16)
            if value >= 0x80:
                break
            output[-3:] = [chr(value)]
    return "".join(output)


def markdown_unescape(text: str) -> str:
    """Remove Markdown backslash escapes before ASCII punctuation."""

    if "\\" not in text:
        return text
    output = []
    index = 0
    size = len(text)
    while index < size:
        character = text[index]
        if character == "\\" and index + 1 < size and text[index + 1] in _ASCII_PUNCTUATION:
            output.append(text[index + 1])
            index += 2
        else:
            output.append(character)
            index += 1
    return "".join(output)


def canonicalize_url_text(text: str) -> str:
    """Decode obfuscation and compact whitespace for security inspection."""

    decoded = decode_html_entities(text)
    decoded = percent_decode_ascii(decoded)
    output = []
    for character in decoded:
        codepoint = ord(character)
        if character.isspace() or codepoint < 0x20 or 0x7F <= codepoint <= 0x9F:
            continue
        output.append(character)
    return "".join(output)


def normalize_reference_label(text: str) -> str:
    """Normalize a Markdown reference label for matching."""

    decoded = markdown_unescape(decode_html_entities(text))
    return " ".join(decoded.strip().split()).casefold()


def escape_markdown_text(text: str) -> str:
    """Render text inert when it is emitted outside a link or image construct."""

    special = frozenset("\\[]()!<>`*_#{}.")
    output = []
    for character in text:
        if character in "\r\n":
            output.append(" ")
        elif character in special:
            output.append("\\" + character)
        else:
            output.append(character)
    return "".join(output)


def decode_visible_text(text: str) -> str:
    """Decode entities and Markdown punctuation escapes for display metadata."""

    return markdown_unescape(decode_html_entities(text)).strip()
