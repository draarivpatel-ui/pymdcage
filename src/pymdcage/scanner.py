"""Iterative linear Markdown security scanner and sanitizer."""
from __future__ import annotations

import bisect
import unicodedata
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any, Deque, Dict, List, Mapping, Optional, Sequence, Tuple

from ._text import (
    decode_entity_at,
    decode_html_entities,
    decode_visible_text,
    escape_markdown_text,
    markdown_unescape,
    normalize_reference_label,
)
from .errors import MDCAGE_ERROR_CODES as ERROR
from .errors import MdCageError
from .model import MdCageFinding, MdCageStats, MdLink, MdSanitizeResult
from .policy import MdPolicy
from .urlcheck import inspect_url


@dataclass
class ReferenceDefinition:
    label: str
    normalized_label: str
    url: str
    title: Optional[str]
    valid: bool
    hidden_comment: bool
    line_index: int
    position: int
    raw: str


@dataclass
class InlineParse:
    end: int
    valid: bool
    destination: str
    title: Optional[str]
    malformed: bool = False
    raw_inside: str = ""


@dataclass
class ReferenceUseParse:
    end: int
    valid: bool
    label: str


@dataclass
class AngleResult:
    end: int
    replacement: Optional[str]
    consume: bool
    html_name: str = ""
    html_closing: bool = False
    html_self_closing: bool = False


class ScanState:
    def __init__(self, policy: MdPolicy, line_starts: Sequence[int]) -> None:
        self.policy = policy
        self.line_starts = tuple(line_starts)
        self.findings: List[MdCageFinding] = []
        self.links: List[MdLink] = []
        self.used_reference_labels = set()
        self.referenced_labels = set()
        self.finding_attempts = 0
        self.finding_overflow = False
        self.counters: Dict[str, int] = {
            "links": 0,
            "images": 0,
            "autolinks": 0,
            "reference_definitions": 0,
            "reference_links": 0,
            "html_tags": 0,
            "html_comments": 0,
            "code_spans": 0,
            "fenced_code_blocks": 0,
            "hidden_characters": 0,
            "max_nesting_observed": 0,
        }

    def location(self, position: int) -> Tuple[int, int]:
        line_index = bisect.bisect_right(self.line_starts, position) - 1
        if line_index < 0:
            line_index = 0
        return line_index + 1, position - self.line_starts[line_index] + 1

    def observe_nesting(self, depth: int) -> None:
        if depth > self.counters["max_nesting_observed"]:
            self.counters["max_nesting_observed"] = depth

    def add_finding(
        self,
        code: str,
        message: str,
        *,
        position: Optional[int] = None,
        severity: str = "high",
        kind: Optional[str] = None,
        details: Optional[Mapping[str, Any]] = None,
    ) -> None:
        self.finding_attempts += 1
        limit = self.policy.max_findings
        if self.finding_overflow:
            return
        line = column = None
        if len(self.findings) < limit:
            if position is not None:
                line, column = self.location(position)
            self.findings.append(
                MdCageFinding(
                    code=code,
                    message=message,
                    severity=severity,
                    position=position,
                    line=line,
                    column=column,
                    kind=kind,
                    details=details or {},
                )
            )
            return
        self.finding_overflow = True
        if limit > 0:
            sentinel_position = self.findings[-1].position if self.findings else position
            sentinel_line = sentinel_column = None
            if sentinel_position is not None:
                sentinel_line, sentinel_column = self.location(sentinel_position)
            self.findings[-1] = MdCageFinding(
                code=ERROR["MAX_FINDINGS"],
                message="finding limit was reached; later findings are omitted",
                severity="high",
                position=sentinel_position,
                line=sentinel_line,
                column=sentinel_column,
                details={"limit": limit},
            )

    def add_link(self, link: MdLink) -> None:
        if len(self.links) >= self.policy.max_links:
            raise MdCageError(
                ERROR["MAX_LINKS"],
                "link count limit exceeded",
                {"limit": self.policy.max_links},
            )
        self.links.append(link)
        self.counters["links"] += 1
        if link.kind == "image":
            self.counters["images"] += 1
        elif link.kind == "autolink":
            self.counters["autolinks"] += 1
        elif link.kind in ("reference", "reference-image"):
            self.counters["reference_links"] += 1

    def build_stats(self, byte_count: int, line_count: int) -> MdCageStats:
        return MdCageStats(
            bytes=byte_count,
            lines=line_count,
            links=self.counters["links"],
            images=self.counters["images"],
            autolinks=self.counters["autolinks"],
            reference_definitions=self.counters["reference_definitions"],
            reference_links=self.counters["reference_links"],
            html_tags=self.counters["html_tags"],
            html_comments=self.counters["html_comments"],
            code_spans=self.counters["code_spans"],
            fenced_code_blocks=self.counters["fenced_code_blocks"],
            hidden_characters=self.counters["hidden_characters"],
            max_nesting_observed=self.counters["max_nesting_observed"],
            findings=self.finding_attempts,
        )


def _invalid_input(message: str, details: Optional[Mapping[str, Any]] = None) -> MdCageError:
    return MdCageError(ERROR["INVALID_INPUT"], message, details)


def coerce_source(source: object, policy: MdPolicy) -> Tuple[str, int]:
    """Validate and decode input without leaking low-level codec or view errors."""

    if type(source) is str:
        text = source
        try:
            byte_count = len(text.encode("utf-8"))
        except UnicodeEncodeError:
            raise MdCageError(
                ERROR["UNPAIRED_SURROGATE"],
                "input contains an unpaired surrogate code point",
            )
        if byte_count > policy.max_bytes:
            raise MdCageError(ERROR["MAX_BYTES"], "input byte limit exceeded", {"limit": policy.max_bytes})
        return text, byte_count

    if type(source) is bytes:
        byte_count = len(source)
        if byte_count > policy.max_bytes:
            raise MdCageError(ERROR["MAX_BYTES"], "input byte limit exceeded", {"limit": policy.max_bytes})
        try:
            return source.decode("utf-8", "strict"), byte_count
        except UnicodeDecodeError:
            raise MdCageError(ERROR["INVALID_UTF8"], "input is not valid UTF-8")

    if type(source) is bytearray:
        byte_count = len(source)
        if byte_count > policy.max_bytes:
            raise MdCageError(ERROR["MAX_BYTES"], "input byte limit exceeded", {"limit": policy.max_bytes})
        copied = bytes(source)
        try:
            return copied.decode("utf-8", "strict"), byte_count
        except UnicodeDecodeError:
            raise MdCageError(ERROR["INVALID_UTF8"], "input is not valid UTF-8")

    if isinstance(source, memoryview):
        try:
            byte_count = int(source.nbytes)
        except (ValueError, TypeError):
            raise MdCageError(ERROR["INPUT_RELEASED"], "memoryview was released before it could be inspected")
        if byte_count > policy.max_bytes:
            raise MdCageError(ERROR["MAX_BYTES"], "input byte limit exceeded", {"limit": policy.max_bytes})
        try:
            copied = source.tobytes()
        except (ValueError, TypeError):
            raise MdCageError(ERROR["INPUT_RELEASED"], "memoryview was released before it could be copied")
        try:
            return copied.decode("utf-8", "strict"), byte_count
        except UnicodeDecodeError:
            raise MdCageError(ERROR["INVALID_UTF8"], "input is not valid UTF-8")

    raise _invalid_input("source must be str, bytes, bytearray, or memoryview", {"type": type(source).__name__})


def split_lines(text: str) -> List[str]:
    lines = []
    start = 0
    index = 0
    size = len(text)
    while index < size:
        character = text[index]
        if character == "\n" or character == "\r":
            end = index + 1
            if character == "\r" and end < size and text[end] == "\n":
                end += 1
            lines.append(text[start:end])
            start = end
            index = end
        else:
            index += 1
    if start < size:
        lines.append(text[start:])
    if not lines and text == "":
        return []
    return lines


def line_body(line: str) -> str:
    body = line[:-1] if line.endswith("\n") else line
    if body.endswith("\r"):
        body = body[:-1]
    return body


def _line_starts(text: str) -> List[int]:
    starts = [0]
    index = 0
    size = len(text)
    while index < size:
        character = text[index]
        if character == "\n" or character == "\r":
            end = index + 1
            if character == "\r" and end < size and text[end] == "\n":
                end += 1
            if end < size:
                starts.append(end)
            index = end
        else:
            index += 1
    return starts


def _hidden_category(character: str) -> Optional[str]:
    codepoint = ord(character)
    if 0xD800 <= codepoint <= 0xDFFF:
        return "surrogate"
    if 0xE0000 <= codepoint <= 0xE007F:
        return "unicode_tags"
    if 0x202A <= codepoint <= 0x202E or 0x2066 <= codepoint <= 0x2069 or codepoint in (0x200E, 0x200F, 0x061C):
        return "bidi"
    if (
        0x0600 <= codepoint <= 0x0605
        or 0x0890 <= codepoint <= 0x0891
        or 0x200B <= codepoint <= 0x200D
        or 0x2060 <= codepoint <= 0x206F
        or 0xFE00 <= codepoint <= 0xFE0F
        or 0xFFF9 <= codepoint <= 0xFFFB
        or 0xE0100 <= codepoint <= 0xE01EF
        or 0x13430 <= codepoint <= 0x1343F
        or 0x1BCA0 <= codepoint <= 0x1BCA3
        or 0x1D173 <= codepoint <= 0x1D17A
        or codepoint in (0x00AD, 0x034F, 0x06DD, 0x070F, 0x08E2, 0x115F, 0x1160, 0x180E, 0x3164, 0xFEFF, 0xFFA0, 0x110BD, 0x110CD)
    ):
        return "invisible"
    if unicodedata.category(character) == "Cf":
        return "invisible"
    if (codepoint < 0x20 and character not in "\n\r\t") or 0x7F <= codepoint <= 0x9F:
        return "control"
    return None


def strip_hidden_unicode(text: str) -> Tuple[str, Dict[str, Tuple[int, int]]]:
    """Strip literal or entity-encoded invisible/control characters linearly."""

    output = []
    events: Dict[str, Tuple[int, int]] = {}

    def record(category: str, position: int) -> None:
        if category in events:
            count, first = events[category]
            events[category] = (count + 1, first)
        else:
            events[category] = (1, position)

    index = 0
    size = len(text)
    while index < size:
        character = text[index]
        if character == "&":
            decoded_entity = decode_entity_at(text, index)
            if decoded_entity is not None:
                decoded, end = decoded_entity
                categories = [_hidden_category(decoded_character) for decoded_character in decoded]
                hidden_categories = [category for category in categories if category is not None]
                if hidden_categories:
                    record(hidden_categories[0], index)
                    index = end
                    continue
        category = _hidden_category(character)
        if category is None:
            output.append(character)
        else:
            record(category, index)
        index += 1
    return "".join(output), events


def _skip_spaces(text: str, index: int) -> int:
    size = len(text)
    while index < size and text[index] in " \t":
        index += 1
    return index


def _scan_reference_title(body: str, index: int) -> Tuple[bool, Optional[str], int]:
    if index >= len(body):
        return True, None, index
    opener = body[index]
    if opener in "\"'":
        closer = opener
    elif opener == "(":
        closer = ")"
    else:
        return False, None, index
    index += 1
    start = index
    escaped = False
    while index < len(body):
        character = body[index]
        if escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == closer:
            title = body[start:index]
            end = _skip_spaces(body, index + 1)
            return end == len(body), title, end
        index += 1
    return False, None, len(body)


def parse_reference_definition(line: str, line_index: int, position: int) -> Optional[ReferenceDefinition]:
    """Parse the common one-line Markdown reference definition form."""

    body = line_body(line)
    indent = 0
    while indent < len(body) and body[indent] == " ":
        indent += 1
    if indent > 3 or indent >= len(body) or body[indent] != "[":
        return None

    index = indent + 1
    label_start = index
    escaped = False
    closing = -1
    while index < len(body) and index - label_start <= 999:
        character = body[index]
        if escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == "]":
            closing = index
            break
        index += 1
    if closing == -1 or closing + 1 >= len(body) or body[closing + 1] != ":":
        return None

    raw_label = body[label_start:closing]
    normalized = normalize_reference_label(raw_label)
    index = _skip_spaces(body, closing + 2)
    valid = bool(normalized)
    destination = ""
    title = None

    if index >= len(body):
        valid = False
    elif body[index] == "<":
        end_angle = body.find(">", index + 1)
        if end_angle == -1:
            destination = body[index + 1:]
            index = len(body)
            valid = False
        else:
            destination = body[index + 1:end_angle]
            index = end_angle + 1
    else:
        destination_start = index
        while index < len(body) and body[index] not in " \t":
            index += 1
        destination = body[destination_start:index]
        if not destination:
            valid = False

    before_title = index
    index = _skip_spaces(body, index)
    if index < len(body):
        if index == before_title:
            valid = False
        title_valid, title, end = _scan_reference_title(body, index)
        valid = valid and title_valid
        index = end

    hidden_comment = normalized in ("//", "comment", "comments") and destination.startswith("#")
    return ReferenceDefinition(
        label=raw_label,
        normalized_label=normalized,
        url=destination,
        title=title,
        valid=valid,
        hidden_comment=hidden_comment,
        line_index=line_index,
        position=position,
        raw=line,
    )


def _fence_marker(line: str) -> Optional[Tuple[str, int, int]]:
    body = line_body(line)
    indent = 0
    while indent < len(body) and body[indent] == " ":
        indent += 1
    if indent > 3 or indent >= len(body) or body[indent] not in "`~":
        return None
    marker = body[indent]
    index = indent
    while index < len(body) and body[index] == marker:
        index += 1
    length = index - indent
    if length < 3:
        return None
    if marker == "`" and "`" in body[index:]:
        return None
    return marker, length, indent


def _is_closing_fence(line: str, marker: str, opening_length: int) -> bool:
    parsed = _fence_marker(line)
    if parsed is None:
        return False
    marker_seen, length, indent = parsed
    if marker_seen != marker or length < opening_length:
        return False
    body = line_body(line)
    index = indent + length
    while index < len(body):
        if body[index] not in " \t":
            return False
        index += 1
    return True


def _expanded_indent(body: str) -> Tuple[int, int]:
    indent = 0
    index = 0
    while index < len(body) and body[index] in " \t":
        if body[index] == "\t":
            indent = ((indent // 4) + 1) * 4
        else:
            indent += 1
        index += 1
    return indent, index


def _block_rest(body: str) -> Optional[str]:
    indent, index = _expanded_indent(body)
    if indent > 3:
        return None
    return body[index:]


def _tag_opens_line(rest: str, tag: str) -> bool:
    lowered = rest.lower()
    prefix = "<" + tag
    if not lowered.startswith(prefix):
        return False
    if len(rest) == len(prefix):
        return True
    following = rest[len(prefix)]
    return following.isspace() or following in "/>"


def _html_block_start(line: str) -> Optional[Tuple[Optional[str], bool]]:
    """Return a conservative HTML block terminator and blank-line flag."""

    body = line_body(line)
    rest = _block_rest(body)
    if rest is None or not rest.startswith("<") or len(rest) < 2:
        return None
    lowered = rest.lower()
    if lowered.startswith("<!--"):
        return "-->", False
    if lowered.startswith("<![cdata["):
        return "]]>", False
    if lowered.startswith("<?"):
        return "?>", False
    if len(rest) > 2 and rest.startswith("<!") and rest[2].isalpha():
        return ">", False
    for tag in ("script", "pre", "style", "textarea"):
        if _tag_opens_line(rest, tag):
            return "</" + tag, False
    if rest[1].isalpha() or (rest[1] == "/" and len(rest) > 2 and rest[2].isalpha()):
        return None, True
    return None


def _atomic_inline_boundary(line: str) -> bool:
    """Return true for one-line blocks that never continue inline text on later lines."""

    body = line_body(line)
    rest = _block_rest(body)
    if rest is None or not rest:
        return False
    hash_count = 0
    while hash_count < len(rest) and rest[hash_count] == "#":
        hash_count += 1
    if 1 <= hash_count <= 6 and (hash_count == len(rest) or rest[hash_count] in " \t"):
        return True
    compact = rest.replace(" ", "").replace("\t", "")
    if len(compact) >= 3 and compact[0] in "*-_" and all(character == compact[0] for character in compact):
        return True
    return bool(compact) and all(character == "=" for character in compact)


def _is_hard_inline_boundary(line: str) -> bool:
    """Return true for lines that cannot be inside the preceding inline paragraph."""

    body = line_body(line)
    stripped = body.strip(" \t")
    if not stripped:
        return True
    rest = _block_rest(body)
    if rest is None or not rest:
        return False

    if _atomic_inline_boundary(line):
        return True

    if rest.startswith(">"):
        return True
    if rest[0] in "-+*" and (len(rest) == 1 or rest[1] in " \t"):
        return True
    digit_count = 0
    while digit_count < len(rest) and rest[digit_count].isdigit() and digit_count < 9:
        digit_count += 1
    if digit_count and digit_count < len(rest) and rest[digit_count] in ".)":
        after_marker = digit_count + 1
        if after_marker == len(rest) or rest[after_marker] in " \t":
            return True

    return _html_block_start(line) is not None


def classify_lines(text: str, policy: MdPolicy) -> Tuple[List[str], List[str], List[ReferenceDefinition], List[int], int, Optional[int]]:
    lines = split_lines(text)
    if len(lines) > policy.max_lines:
        raise MdCageError(ERROR["MAX_LINES"], "input line limit exceeded", {"limit": policy.max_lines})
    offsets = []
    offset = 0
    for line in lines:
        offsets.append(offset)
        offset += len(line)

    kinds: List[str] = []
    references: List[ReferenceDefinition] = []
    fence_positions: List[Tuple[int, int]] = []
    in_fence = False
    fence_marker = ""
    fence_length = 0
    fence_open_index = -1
    in_html_block = False
    html_terminator: Optional[str] = None
    html_end_on_blank = False

    for index, line in enumerate(lines):
        if in_fence:
            kinds.append("fence")
            if _is_closing_fence(line, fence_marker, fence_length):
                in_fence = False
            continue

        body = line_body(line)
        blank = not body.strip(" \t")
        if in_html_block:
            kinds.append("text")
            if html_end_on_blank:
                ends_here = blank
            else:
                ends_here = html_terminator is not None and html_terminator in body.lower()
            if ends_here:
                in_html_block = False
                html_terminator = None
                html_end_on_blank = False
            continue

        html_start = _html_block_start(line)
        if html_start is not None:
            kinds.append("text")
            terminator, end_on_blank = html_start
            if end_on_blank or terminator is None or terminator not in body.lower():
                in_html_block = True
                html_terminator = terminator
                html_end_on_blank = end_on_blank
            continue

        marker = _fence_marker(line)
        if marker is not None:
            kinds.append("fence")
            in_fence = True
            fence_marker, fence_length, _indent = marker
            fence_open_index = index
            fence_positions.append((index, offsets[index]))
            continue
        reference = parse_reference_definition(line, index, offsets[index])
        if reference is not None:
            if len(references) >= policy.max_reference_defs:
                raise MdCageError(
                    ERROR["MAX_REFERENCE_DEFS"],
                    "reference definition limit exceeded",
                    {"limit": policy.max_reference_defs},
                )
            references.append(reference)
            kinds.append("reference")
        else:
            kinds.append("text")

    unclosed = offsets[fence_open_index] if in_fence and fence_open_index >= 0 else None
    return lines, kinds, references, offsets, len(fence_positions), unclosed


def scan_reference_title_text(title: Optional[str]) -> Optional[str]:
    if title is None:
        return None
    return decode_visible_text(title)


def _compute_code_ranges(text: str) -> Tuple[List[Tuple[int, int]], List[int]]:
    """Compute inline code spans independently for blank-line-separated blocks."""

    line_offset = 0
    block_index = 0
    in_blank_run = True
    runs_by_block: Dict[int, List[Tuple[int, int, int]]] = defaultdict(list)
    for line in split_lines(text):
        body = line_body(line)
        stripped = body.strip(" \t")
        if not stripped:
            in_blank_run = True
        else:
            if in_blank_run:
                block_index += 1
                in_blank_run = False
            indented_code = body.startswith("\t") or body.startswith("    ")
            index = 0
            while not indented_code and index < len(body):
                if body[index] != "`":
                    index += 1
                    continue
                start = index
                while index < len(body) and body[index] == "`":
                    index += 1
                runs_by_block[block_index].append((line_offset + start, line_offset + index, index - start))
        line_offset += len(line)

    ranges: List[Tuple[int, int]] = []
    unmatched: List[int] = []
    for block in sorted(runs_by_block):
        runs = runs_by_block[block]
        consumed = [False] * len(runs)
        queues: Dict[int, Deque[int]] = defaultdict(deque)
        for index, run in enumerate(runs):
            queues[run[2]].append(index)
        for index, run in enumerate(runs):
            if consumed[index]:
                continue
            queue = queues[run[2]]
            while queue and (queue[0] <= index or consumed[queue[0]]):
                queue.popleft()
            if queue:
                closing_index = queue.popleft()
                closing = runs[closing_index]
                ranges.append((run[0], closing[1]))
                for consumed_index in range(index, closing_index + 1):
                    consumed[consumed_index] = True
            else:
                consumed[index] = True
                unmatched.append(run[0])
    ranges.sort()
    return ranges, sorted(unmatched)


def _consume_parenthetical(text: str, opening: int) -> int:
    depth = 1
    index = opening + 1
    escaped = False
    size = len(text)
    while index < size:
        character = text[index]
        if escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    return size


def parse_inline_link(text: str, opening: int, policy: MdPolicy, state: ScanState) -> InlineParse:
    """Parse and consume a parenthesized inline destination exactly once."""

    size = len(text)
    index = opening + 1
    while index < size and text[index] in " \t\r\n":
        index += 1
    if index >= size:
        return InlineParse(size, False, "", None, True, text[opening + 1:size])

    destination = ""
    malformed = False
    if text[index] == "<":
        index += 1
        destination_start = index
        closed = False
        escaped = False
        while index < size:
            character = text[index]
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == ">":
                destination = text[destination_start:index]
                index += 1
                closed = True
                break
            elif character in "\r\n" or character == "<":
                malformed = True
            index += 1
        if not closed:
            malformed = True
    else:
        destination_start = index
        depth = 0
        escaped = False
        while index < size:
            character = text[index]
            if escaped:
                escaped = False
                index += 1
                continue
            if character == "\\":
                escaped = True
                index += 1
                continue
            if character.isspace():
                break
            if character == "(":
                depth += 1
                state.observe_nesting(depth)
                if depth > policy.max_nesting_depth:
                    raise MdCageError(
                        ERROR["MAX_NESTING_DEPTH"],
                        "link destination nesting limit exceeded",
                        {"limit": policy.max_nesting_depth},
                    )
            elif character == ")":
                if depth == 0:
                    break
                depth -= 1
            index += 1
        destination = text[destination_start:index]
        if not destination:
            malformed = True

    while index < size and text[index] in " \t\r\n":
        index += 1

    title = None
    if index < size and text[index] in "\"'(":
        opener = text[index]
        closer = ")" if opener == "(" else opener
        index += 1
        title_start = index
        escaped = False
        closed = False
        while index < size:
            character = text[index]
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == closer:
                title = text[title_start:index]
                index += 1
                closed = True
                break
            index += 1
        if not closed:
            malformed = True
        while index < size and text[index] in " \t\r\n":
            index += 1

    if index < size and text[index] == ")" and not malformed:
        return InlineParse(index + 1, True, destination, title, False)
    end = _consume_parenthetical(text, opening)
    inside_end = end - 1 if end <= size and end > opening + 1 and text[end - 1:end] == ")" else end
    return InlineParse(end, False, destination, title, True, text[opening + 1:inside_end])


def parse_reference_use(text: str, opening: int) -> ReferenceUseParse:
    """Parse the second bracket of a full or collapsed reference use."""

    index = opening + 1
    start = index
    escaped = False
    size = len(text)
    while index < size:
        character = text[index]
        if escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == "]":
            return ReferenceUseParse(index + 1, True, text[start:index])
        index += 1
    return ReferenceUseParse(size, False, text[start:])


def display_url(raw: str) -> str:
    return markdown_unescape(decode_html_entities(raw)).strip()


def angle_destination(url: str) -> str:
    output = ["<"]
    for character in url:
        codepoint = ord(character)
        if character.isspace() or character in "<>\\" or codepoint < 0x20 or codepoint == 0x7F:
            for byte in character.encode("utf-8"):
                output.append("%{:02X}".format(byte))
        else:
            output.append(character)
    output.append(">")
    return "".join(output)


def escaped_link_title(title: Optional[str]) -> str:
    if title is None:
        return ""
    decoded = scan_reference_title_text(title) or ""
    escaped = []
    for character in decoded:
        if character in "\r\n":
            escaped.append(" ")
        elif character in ('\\', '"'):
            escaped.append('\\' + character)
        else:
            escaped.append(character)
    return ' "' + "".join(escaped) + '"'


def plain_label(raw: str) -> str:
    return escape_markdown_text(decode_visible_text(raw))


def _record_url_link(
    state: ScanState,
    *,
    label: str,
    raw_url: str,
    title: Optional[str],
    kind: str,
    position: int,
    inspection: Any,
) -> None:
    line, column = state.location(position)
    state.add_link(
        MdLink(
            label=decode_visible_text(label),
            url=display_url(raw_url),
            kind=kind,
            position=position,
            line=line,
            column=column,
            external=inspection.external,
            safe=inspection.safe,
            title=scan_reference_title_text(title),
            code=inspection.code,
        )
    )


def _replace_construct(
    out: List[str],
    opener_piece: int,
    replacement: str,
) -> None:
    del out[opener_piece:]
    if replacement:
        out.append(replacement)


def _css_unescape(text: str) -> str:
    """Decode CSS escape sequences used to hide url(), expression(), and schemes."""

    output = []
    index = 0
    size = len(text)
    hexadecimal = "0123456789abcdefABCDEF"
    while index < size:
        if text[index] != "\\":
            output.append(text[index])
            index += 1
            continue
        index += 1
        if index >= size:
            break
        character = text[index]
        if character in "\r\n\f":
            if character == "\r" and index + 1 < size and text[index + 1] == "\n":
                index += 2
            else:
                index += 1
            continue
        if character in hexadecimal:
            start = index
            digits = 0
            while index < size and digits < 6 and text[index] in hexadecimal:
                index += 1
                digits += 1
            value = int(text[start:index], 16)
            if index < size and text[index] in " \t\r\n\f":
                if text[index] == "\r" and index + 1 < size and text[index + 1] == "\n":
                    index += 2
                else:
                    index += 1
            if value <= 0 or value > 0x10FFFF or 0xD800 <= value <= 0xDFFF:
                output.append("\ufffd")
            else:
                output.append(chr(value))
            continue
        output.append(character)
        index += 1
    return "".join(output)


def _scan_html_attributes(raw: str, policy: MdPolicy) -> Tuple[str, bool, str, bool, bool]:
    """Return name, activity, reason, closing flag, and self-closing flag."""

    size = len(raw)
    index = 1
    closing = False
    if index < size and raw[index] == "/":
        closing = True
        index += 1
    name_start = index
    while index < size and (raw[index].isalnum() or raw[index] in ":-"):
        index += 1
    name = raw[name_start:index].lower()
    active_tags = frozenset({
        "script", "iframe", "svg", "math", "style", "form", "object", "embed",
        "meta", "link", "base", "applet", "frame", "frameset", "input", "button",
        "textarea", "select", "audio", "video", "source", "track", "template",
    })
    self_closing = raw.rstrip().endswith("/>")
    if name in active_tags:
        return name, True, "active HTML element", closing, self_closing

    while index < size:
        while index < size and raw[index].isspace():
            index += 1
        if index >= size or raw[index] == ">":
            break
        if raw[index] == "/":
            if index + 1 < size and raw[index + 1] == ">":
                break
            index += 1
            continue
        attr_start = index
        while index < size and not raw[index].isspace() and raw[index] not in "=/>":
            index += 1
        attr_name = raw[attr_start:index].lower()
        while index < size and raw[index].isspace():
            index += 1
        value = ""
        if index < size and raw[index] == "=":
            index += 1
            while index < size and raw[index].isspace():
                index += 1
            if index < size and raw[index] in "\"'":
                quote = raw[index]
                index += 1
                value_start = index
                while index < size and raw[index] != quote:
                    index += 1
                value = raw[value_start:index]
                if index < size:
                    index += 1
            else:
                value_start = index
                while index < size and not raw[index].isspace() and raw[index] != ">":
                    index += 1
                value = raw[value_start:index]
        if attr_name.startswith("on") and attr_name != "on":
            return name, True, "event handler attribute", closing, self_closing
        if attr_name == "style":
            decoded_style = decode_html_entities(value).lower()
            without_comments = []
            comment_index = 0
            while comment_index < len(decoded_style):
                if decoded_style.startswith("/*", comment_index):
                    comment_end = decoded_style.find("*/", comment_index + 2)
                    if comment_end == -1:
                        break
                    comment_index = comment_end + 2
                    continue
                without_comments.append(decoded_style[comment_index])
                comment_index += 1
            unescaped_style = _css_unescape("".join(without_comments))
            compact = "".join(unescaped_style.split()).replace("\\", "")
            if "expression(" in compact or "javascript:" in compact or "vbscript:" in compact or "url(" in compact or "@import" in compact or "behavior:" in compact:
                return name, True, "dangerous style attribute", closing, self_closing
        if attr_name == "srcdoc":
            return name, True, "srcdoc HTML payload attribute", closing, self_closing
        if attr_name in ("href", "src", "action", "formaction", "poster", "background", "data", "xlink:href", "data-src", "dynsrc", "lowsrc"):
            inspection = inspect_url(value, policy, image=(name == "img" or attr_name in ("src", "poster", "background")))
            if not inspection.safe:
                return name, True, inspection.reason, closing, self_closing
        if attr_name == "srcset" and name in ("img", "source"):
            for candidate in value.split(","):
                candidate_url = candidate.strip().split(None, 1)[0] if candidate.strip() else ""
                if not candidate_url:
                    continue
                inspection = inspect_url(candidate_url, policy, image=True)
                if not inspection.safe:
                    return name, True, inspection.reason, closing, self_closing
    return name, False, "", closing, self_closing


def scan_html_tag(text: str, start: int, offset: int, policy: MdPolicy, state: ScanState) -> AngleResult:
    size = len(text)
    index = start + 1
    quote = None
    end = -1
    while index < size:
        character = text[index]
        if quote is not None:
            if character == quote:
                quote = None
        elif character in "\"'":
            quote = character
        elif character == ">":
            end = index + 1
            break
        elif character == "<":
            end = index
            break
        index += 1
    if end == -1:
        end = size
    raw = text[start:end]
    state.counters["html_tags"] += 1
    name, active, reason, closing, self_closing = _scan_html_attributes(raw, policy)
    position = offset + start
    if active:
        state.add_finding(
            ERROR["ACTIVE_HTML"],
            "active raw HTML was stripped: " + reason,
            position=position,
            severity="critical" if name in ("script", "iframe", "object", "embed", "svg", "math") else "high",
            kind="html",
            details={"tag": name},
        )
        return AngleResult(end, "", True, html_name=name, html_closing=closing, html_self_closing=self_closing)
    if not policy.allow_html:
        state.add_finding(
            ERROR["RAW_HTML"],
            "raw HTML is disabled by policy and was stripped",
            position=position,
            severity="high",
            kind="html",
            details={"tag": name},
        )
        return AngleResult(end, "", True, html_name=name, html_closing=closing, html_self_closing=self_closing)
    return AngleResult(end, None, True, html_name=name, html_closing=closing, html_self_closing=self_closing)


def _scheme_prefix(text: str, start: int) -> int:
    index = start + 1
    size = len(text)
    if index >= size or not text[index].isalpha():
        return -1
    scan = index + 1
    limit = min(size, index + 32)
    while scan < limit:
        character = text[scan]
        if character == ":":
            return scan
        if not (character.isalnum() or character in "+-."):
            return -1
        scan += 1
    return -1


def _valid_email_autolink(value: str) -> bool:
    if not value or any(character.isspace() for character in value) or value.count("@") != 1:
        return False
    local, domain = value.split("@", 1)
    if not local or not domain or domain.startswith(".") or domain.endswith("."):
        return False
    return all(character not in "<>()[]\\,;:" for character in value)


def scan_angle(text: str, start: int, offset: int, policy: MdPolicy, state: ScanState) -> AngleResult:
    size = len(text)
    position = offset + start

    if text.startswith("<!--", start):
        close = text.find("-->", start + 4)
        end = size if close == -1 else close + 3
        state.counters["html_comments"] += 1
        state.add_finding(
            ERROR["HTML_COMMENT"],
            "HTML comment was stripped because comments can hide instructions from rendered output",
            position=position,
            severity="high",
            kind="comment",
        )
        return AngleResult(end, "", True)

    if text.startswith("<!", start) or text.startswith("<?", start):
        close = text.find(">", start + 2)
        end = size if close == -1 else close + 1
        state.counters["html_tags"] += 1
        state.add_finding(
            ERROR["RAW_HTML"],
            "markup declaration or processing instruction was stripped",
            position=position,
            severity="high",
            kind="html",
        )
        return AngleResult(end, "", True)

    colon = _scheme_prefix(text, start)
    if colon != -1:
        close = text.find(">", colon + 1)
        end = size if close == -1 else close + 1
        content_end = end - 1 if close != -1 else end
        content = text[start + 1:content_end]
        malformed = close == -1 or any(character.isspace() or character in "<>" for character in content)
        if malformed:
            state.add_finding(
                ERROR["MALFORMED_LINK"],
                "malformed autolink-like construct was neutralized",
                position=position,
                severity="medium",
                kind="autolink",
            )
            return AngleResult(end, escape_markdown_text(content), True)
        inspection = inspect_url(content, policy, image=False)
        line, column = state.location(position)
        state.add_link(
            MdLink(
                label=content,
                url=display_url(content),
                kind="autolink",
                position=position,
                line=line,
                column=column,
                external=inspection.external,
                safe=inspection.safe and policy.allow_autolinks,
                code=inspection.code,
            )
        )
        exact = text[start:end]
        if not inspection.safe:
            state.add_finding(
                inspection.code or ERROR["DANGEROUS_SCHEME"],
                inspection.reason,
                position=position,
                severity=inspection.severity,
                kind="autolink",
            )
            return AngleResult(end, escape_markdown_text(content), True)
        if not policy.allow_autolinks:
            state.add_finding(
                ERROR["DISALLOWED_SCHEME"],
                "autolinks are disabled by policy",
                position=position,
                severity="high",
                kind="autolink",
            )
            return AngleResult(end, escape_markdown_text(content), True)
        return AngleResult(end, exact, True)

    if start + 1 < size and text[start + 1] not in "/!" and not text[start + 1].isspace():
        probe = start + 1
        while probe < size and not text[probe].isspace() and text[probe] not in "<>":
            probe += 1
        candidate = text[start + 1:probe] if probe < size and text[probe] == ">" else ""
        if candidate and "@" in candidate and _valid_email_autolink(candidate):
            end = probe + 1
            inspection = inspect_url("mailto:" + candidate, policy, image=False)
            line, column = state.location(position)
            state.add_link(
                MdLink(
                    label=candidate,
                    url="mailto:" + candidate,
                    kind="autolink",
                    position=position,
                    line=line,
                    column=column,
                    external=False,
                    safe=inspection.safe and policy.allow_autolinks,
                    code=inspection.code,
                )
            )
            exact = text[start:end]
            if not inspection.safe or not policy.allow_autolinks:
                state.add_finding(
                    inspection.code or ERROR["DISALLOWED_SCHEME"],
                    inspection.reason if not inspection.safe else "autolinks are disabled by policy",
                    position=position,
                    severity="high",
                    kind="autolink",
                )
                return AngleResult(end, escape_markdown_text(candidate), True)
            return AngleResult(end, exact, True)

    tag_start = start + 1
    if tag_start < size and text[tag_start] == "/":
        tag_start += 1
    if tag_start < size and text[tag_start].isalpha():
        return scan_html_tag(text, start, offset, policy, state)
    return AngleResult(start + 1, None, False)


def scan_inline_segment(text: str, offset: int, policy: MdPolicy, references: Mapping[str, ReferenceDefinition], state: ScanState) -> str:
    """Scan one non-fenced segment with a single forward-moving cursor."""

    ranges, unmatched = _compute_code_ranges(text)
    state.counters["code_spans"] += len(ranges)
    if unmatched:
        state.add_finding(
            ERROR["UNCLOSED_CODE_SPAN"],
            "one or more backtick runs did not form a complete inline code span",
            position=offset + unmatched[0],
            severity="low",
            kind="code",
            details={"count": len(unmatched)},
        )

    out: List[str] = []
    stack: List[Tuple[int, int, int, bool, int]] = []
    html_stack: List[Tuple[str, bool]] = []
    void_html_tags = frozenset({
        "area", "base", "br", "col", "embed", "hr", "img", "input", "link",
        "meta", "param", "source", "track", "wbr",
    })
    range_index = 0
    index = 0
    size = len(text)
    expansion_bytes = 0
    mutation_count = 0

    while index < size:
        while range_index < len(ranges) and index > ranges[range_index][0]:
            range_index += 1
        if range_index < len(ranges) and index == ranges[range_index][0]:
            end = ranges[range_index][1]
            out.append(text[index:end])
            index = end
            range_index += 1
            continue

        character = text[index]
        if character == "\\":
            if index + 1 < size:
                out.append(text[index:index + 2])
                index += 2
            else:
                out.append(character)
                index += 1
            continue

        if character == "<":
            angle = scan_angle(text, index, offset, policy, state)
            if angle.consume:
                exact = text[index:angle.end]
                replacement = angle.replacement
                if replacement is None:
                    replacement = exact
                if angle.html_name:
                    ancestor_removed = any(removed for _, removed in html_stack)
                    removed = replacement == "" or ancestor_removed
                    if angle.html_closing:
                        if html_stack and html_stack[-1][0] == angle.html_name:
                            _, opening_removed = html_stack.pop()
                            if opening_removed:
                                replacement = ""
                        elif replacement != "" and not angle.html_name.startswith(("!", "?")):
                            # An unmatched closing tag cannot reopen active markup, but keeping
                            # it would leave structurally corrupt HTML in the sanitized output.
                            replacement = ""
                    elif not angle.html_self_closing and angle.html_name not in void_html_tags:
                        if len(html_stack) < 256:
                            html_stack.append((angle.html_name, removed))
                        elif ancestor_removed:
                            replacement = ""
                    if removed and not angle.html_closing:
                        replacement = ""
                if replacement != exact:
                    mutation_count += 1
                    out.append(replacement)
                else:
                    out.append(exact)
                index = angle.end
                continue

        if character == "!" and index + 1 < size and text[index + 1] == "[":
            out.append("![")
            stack.append((index, len(out) - 1, len(out), True, mutation_count))
            state.observe_nesting(len(stack))
            if len(stack) > policy.max_nesting_depth:
                raise MdCageError(
                    ERROR["MAX_NESTING_DEPTH"],
                    "bracket nesting limit exceeded",
                    {"limit": policy.max_nesting_depth},
                )
            index += 2
            continue

        if character == "[":
            out.append("[")
            stack.append((index, len(out) - 1, len(out), False, mutation_count))
            state.observe_nesting(len(stack))
            if len(stack) > policy.max_nesting_depth:
                raise MdCageError(
                    ERROR["MAX_NESTING_DEPTH"],
                    "bracket nesting limit exceeded",
                    {"limit": policy.max_nesting_depth},
                )
            index += 1
            continue

        if character == "]" and stack:
            opener_position, opener_piece, content_piece, is_image, opener_mutation_count = stack.pop()
            label_start = opener_position + (2 if is_image else 1)
            label_length = index - label_start
            label_raw: Optional[str] = None
            end = index + 1
            construct = None
            inline_parse: Optional[InlineParse] = None
            reference_parse: Optional[ReferenceUseParse] = None
            reference: Optional[ReferenceDefinition] = None
            reference_label = ""

            if end < size and text[end] == "(":
                label_raw = text[label_start:index]
                inline_parse = parse_inline_link(text, end, policy, state)
                end = inline_parse.end
                construct = "image" if is_image else "inline"
            elif end < size and text[end] == "[":
                reference_parse = parse_reference_use(text, end)
                end = reference_parse.end
                if reference_parse.valid:
                    raw_ref_label = reference_parse.label
                    if not raw_ref_label and label_length <= 999:
                        label_raw = text[label_start:index]
                        raw_ref_label = label_raw
                    if raw_ref_label:
                        reference_label = normalize_reference_label(raw_ref_label)
                        reference = references.get(reference_label)
                        if reference is not None and label_raw is None:
                            label_raw = text[label_start:index]
                    if reference is not None:
                        construct = "reference-image" if is_image else "reference"
                else:
                    label_raw = text[label_start:index]
                    construct = "reference-image" if is_image else "reference"
            elif references and label_length <= 999:
                label_raw = text[label_start:index]
                reference_label = normalize_reference_label(label_raw)
                reference = references.get(reference_label)
                if reference is not None:
                    construct = "reference-image" if is_image else "reference"

            if label_raw is None:
                label_raw = ""

            if construct is not None:
                exact = text[opener_position:end]
                position = offset + opener_position
                replacement = exact

                if inline_parse is not None:
                    if inline_parse.valid:
                        inspection = inspect_url(inline_parse.destination, policy, image=is_image)
                        _record_url_link(
                            state,
                            label=label_raw,
                            raw_url=inline_parse.destination,
                            title=inline_parse.title,
                            kind=construct,
                            position=position,
                            inspection=inspection,
                        )
                        if not inspection.safe:
                            state.add_finding(
                                inspection.code or ERROR["DANGEROUS_SCHEME"],
                                inspection.reason,
                                position=position,
                                severity=inspection.severity,
                                kind=construct,
                            )
                            replacement = plain_label(label_raw)
                    else:
                        obfuscation_inspection = inspect_url(inline_parse.raw_inside, policy, image=is_image)
                        if not obfuscation_inspection.safe:
                            state.add_finding(
                                obfuscation_inspection.code or ERROR["DANGEROUS_SCHEME"],
                                obfuscation_inspection.reason,
                                position=position,
                                severity=obfuscation_inspection.severity,
                                kind=construct,
                            )
                        else:
                            state.add_finding(
                                ERROR["MALFORMED_LINK"],
                                "malformed inline link construct was neutralized",
                                position=position,
                                severity="medium",
                                kind=construct,
                            )
                        replacement = plain_label(label_raw)
                elif reference is not None:
                    state.referenced_labels.add(reference.normalized_label)
                    inspection = inspect_url(reference.url, policy, image=is_image)
                    _record_url_link(
                        state,
                        label=label_raw,
                        raw_url=reference.url,
                        title=reference.title,
                        kind=construct,
                        position=position,
                        inspection=inspection,
                    )
                    if not reference.valid:
                        state.add_finding(
                            ERROR["MALFORMED_REFERENCE"],
                            "malformed reference definition was neutralized",
                            position=offset + reference.position,
                            severity="medium",
                            kind=construct,
                        )
                        replacement = plain_label(label_raw)
                    elif reference.hidden_comment:
                        state.add_finding(
                            ERROR["HIDDEN_REFERENCE"],
                            "hidden reference-comment definition was removed",
                            position=offset + reference.position,
                            severity="high",
                            kind="reference",
                        )
                        replacement = plain_label(label_raw)
                    elif not inspection.safe:
                        state.add_finding(
                            inspection.code or ERROR["DANGEROUS_SCHEME"],
                            inspection.reason,
                            position=position,
                            severity=inspection.severity,
                            kind=construct,
                        )
                        replacement = plain_label(label_raw)
                    elif not policy.allow_reference_definitions:
                        prefix = "!" if is_image else ""
                        replacement = (
                            prefix
                            + "["
                            + plain_label(label_raw)
                            + "]("
                            + angle_destination(display_url(reference.url))
                            + escaped_link_title(reference.title)
                            + ")"
                        )
                    else:
                        state.used_reference_labels.add(reference.normalized_label)
                elif reference_parse is not None and reference_parse.valid:
                    replacement = exact
                elif reference_parse is not None and not reference_parse.valid:
                    state.add_finding(
                        ERROR["MALFORMED_LINK"],
                        "malformed reference link construct was neutralized",
                        position=position,
                        severity="medium",
                        kind=construct,
                    )
                    replacement = plain_label(label_raw)

                if replacement == exact and mutation_count != opener_mutation_count:
                    replacement = plain_label(label_raw)
                if replacement != exact:
                    mutation_count += 1
                replacement_bytes = len(replacement.encode("utf-8"))
                exact_bytes = len(exact.encode("utf-8"))
                if replacement_bytes > exact_bytes:
                    expansion_bytes += replacement_bytes - exact_bytes
                    if expansion_bytes > policy.max_output_bytes:
                        raise MdCageError(
                            ERROR["MAX_OUTPUT_BYTES"],
                            "sanitized output byte limit exceeded",
                            {"limit": policy.max_output_bytes},
                        )
                _replace_construct(out, opener_piece, replacement)
                index = end
                continue

        out.append(character)
        index += 1

    return "".join(out)


def build_reference_map(references: Sequence[ReferenceDefinition]) -> Dict[str, ReferenceDefinition]:
    mapping: Dict[str, ReferenceDefinition] = {}
    for reference in references:
        if reference.normalized_label and reference.normalized_label not in mapping:
            mapping[reference.normalized_label] = reference
    return mapping


def _line_pieces(lines: Sequence[str], kinds: Sequence[str]) -> List[Tuple[str, str, int]]:
    pieces: List[Tuple[str, str, int]] = []
    current: List[str] = []
    current_start = 0

    def flush() -> None:
        nonlocal current
        if current:
            pieces.append(("text", "".join(current), current_start))
            current = []

    for index, line in enumerate(lines):
        kind = kinds[index]
        if kind == "text":
            blank = not line_body(line).strip(" \t")
            if blank:
                flush()
                pieces.append(("text", line, index))
                continue
            if _is_hard_inline_boundary(line):
                flush()
                if _atomic_inline_boundary(line):
                    pieces.append(("text", line, index))
                    continue
                current_start = index
                current.append(line)
                continue
            if not current:
                current_start = index
            current.append(line)
        else:
            flush()
            pieces.append((kind, line, index))
    flush()
    return pieces


def _sanitize_text_once(text: str, byte_count: int, policy: MdPolicy) -> MdSanitizeResult:
    """Run one linear sanitizer pass over validated UTF-8 text."""

    cleaned, hidden_events = strip_hidden_unicode(text)
    line_starts = _line_starts(cleaned)
    state = ScanState(policy, line_starts)

    hidden_total = 0
    for category, event in sorted(hidden_events.items()):
        count, first_position = event
        hidden_total += count
        if category == "unicode_tags":
            code = ERROR["UNICODE_TAGS"]
            message = "Unicode Tags block characters were stripped"
            severity = "critical"
        elif category == "bidi":
            code = ERROR["BIDI_CONTROL"]
            message = "bidirectional override or isolate control characters were stripped"
            severity = "critical"
        elif category == "control":
            code = ERROR["CONTROL_CHARACTER"]
            message = "control characters were stripped"
            severity = "high"
        else:
            code = ERROR["INVISIBLE_UNICODE"]
            message = "invisible Unicode characters were stripped"
            severity = "high"
        state.add_finding(
            code,
            message,
            position=first_position,
            severity=severity,
            kind="unicode",
            details={"count": count, "category": category},
        )
    state.counters["hidden_characters"] = hidden_total

    lines, kinds, references, offsets, fence_block_count, unclosed_fence_position = classify_lines(cleaned, policy)
    state.counters["reference_definitions"] = len(references)
    state.counters["fenced_code_blocks"] = fence_block_count
    if unclosed_fence_position is not None:
        state.add_finding(
            ERROR["UNCLOSED_FENCE"],
            "fenced code block was not closed; the remainder is still preserved as code",
            position=unclosed_fence_position,
            severity="medium",
            kind="code",
        )

    reference_map = build_reference_map(references)
    pieces = _line_pieces(lines, kinds)
    processed: List[Tuple[str, str, int]] = []
    piece_offsets: Dict[int, int] = {}
    running_offset = 0
    for index, line in enumerate(lines):
        piece_offsets[index] = running_offset
        running_offset += len(line)

    for kind, content, first_line in pieces:
        if kind == "text":
            processed.append((kind, scan_inline_segment(content, piece_offsets[first_line], policy, reference_map, state), first_line))
        else:
            processed.append((kind, content, first_line))

    output_parts: List[str] = []
    reference_by_line = {reference.line_index: reference for reference in references}
    seen_reference_labels = set()
    for kind, content, first_line in processed:
        if kind != "reference":
            output_parts.append(content)
            continue
        reference = reference_by_line.get(first_line)
        if reference is None:
            continue
        position = piece_offsets[first_line]
        keep = False
        is_duplicate_reference = reference.normalized_label in seen_reference_labels
        seen_reference_labels.add(reference.normalized_label)
        if reference.hidden_comment:
            state.add_finding(
                ERROR["HIDDEN_REFERENCE"],
                "hidden reference-comment definition was removed",
                position=position,
                severity="high",
                kind="reference",
            )
        elif is_duplicate_reference:
            state.add_finding(
                ERROR["MALFORMED_REFERENCE"],
                "duplicate reference definition was removed because only the first definition is reachable",
                position=position,
                severity="high",
                kind="reference",
            )
        elif not reference.valid:
            state.add_finding(
                ERROR["MALFORMED_REFERENCE"],
                "malformed reference definition was removed",
                position=position,
                severity="medium",
                kind="reference",
            )
        elif reference.normalized_label not in state.referenced_labels:
            state.add_finding(
                ERROR["UNUSED_REFERENCE"],
                "unused reference definition was removed because it can carry invisible instructions",
                position=position,
                severity="high",
                kind="reference",
            )
        elif reference.normalized_label not in state.used_reference_labels:
            if not policy.allow_reference_definitions:
                state.add_finding(
                    ERROR["UNUSED_REFERENCE"],
                    "reference definition was unfolded or removed by policy",
                    position=position,
                    severity="low",
                    kind="reference",
                )
        else:
            inspection = inspect_url(reference.url, policy, image=False)
            if inspection.safe:
                keep = True
            else:
                state.add_finding(
                    inspection.code or ERROR["DANGEROUS_SCHEME"],
                    inspection.reason,
                    position=position,
                    severity=inspection.severity,
                    kind="reference",
                )
        if keep:
            output_parts.append(content)

    output = "".join(output_parts)
    try:
        output_bytes = len(output.encode("utf-8"))
    except UnicodeEncodeError:
        raise MdCageError(ERROR["SERIALIZATION_ERROR"], "sanitized output could not be encoded as UTF-8")
    if output_bytes > policy.max_output_bytes:
        raise MdCageError(
            ERROR["MAX_OUTPUT_BYTES"],
            "sanitized output byte limit exceeded",
            {"limit": policy.max_output_bytes},
        )

    stats = state.build_stats(byte_count, len(lines))
    return MdSanitizeResult(
        markdown=output,
        changed=(output != text),
        findings=tuple(state.findings),
        stats=stats,
        links=tuple(state.links),
    )


def sanitize_text(text: str, byte_count: int, policy: MdPolicy) -> MdSanitizeResult:
    """Sanitize to a stable fixpoint with a constant, fail-closed pass bound."""

    first = _sanitize_text_once(text, byte_count, policy)
    current = first.markdown
    if current == text or not any(marker in current for marker in "<[`"):
        return first
    stable = True
    for _pass in range(8):
        current_bytes = len(current.encode("utf-8"))
        reparsed = _sanitize_text_once(current, current_bytes, policy)
        if reparsed.markdown == current:
            break
        current = reparsed.markdown
    else:
        stable = False

    if not stable:
        current = escape_markdown_text(current)
        if len(current.encode("utf-8")) > policy.max_output_bytes:
            raise MdCageError(
                ERROR["MAX_OUTPUT_BYTES"],
                "sanitized output byte limit exceeded",
                {"limit": policy.max_output_bytes},
            )

    return MdSanitizeResult(
        markdown=current,
        changed=(current != text),
        findings=first.findings,
        stats=first.stats,
        links=first.links,
    )


def sanitize_source(source: object, policy: MdPolicy) -> MdSanitizeResult:
    text, byte_count = coerce_source(source, policy)
    return sanitize_text(text, byte_count, policy)
