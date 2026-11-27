"""Command-line interface for pymdcage."""
from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from typing import Any, Optional, Sequence, Tuple

from . import MDCAGE_VERSION
from .auditor import audit_markdown, extract_links
from .errors import MDCAGE_ERROR_CODES as ERROR
from .errors import MdCageError
from .model import MdAuditReport, MdCageFinding, MdCageStats
from .policy import DEFAULT_POLICY
from .sanitizer import sanitize_markdown

_BIDI_CONTROLS = frozenset({
    0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
    0x2066, 0x2067, 0x2068, 0x2069,
})


class _UsageError(Exception):
    pass


def neutralize_terminal(value: Any) -> str:
    """Render terminal control, newline, and bidi characters inert."""

    output = []
    for character in str(value):
        codepoint = ord(character)
        if character == "\n":
            output.append("\\n")
        elif character == "\r":
            output.append("\\r")
        elif character == "\t":
            output.append("\\t")
        elif codepoint < 0x20 or 0x7F <= codepoint <= 0x9F:
            output.append("\\x{:02x}".format(codepoint))
        elif codepoint in _BIDI_CONTROLS:
            output.append("\\u{:04x}".format(codepoint))
        else:
            output.append(character)
    return "".join(output)


def _stderr(value: str) -> None:
    sys.stderr.write(neutralize_terminal(value) + "\n")


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise _UsageError(message)

    def print_usage(self, file: Any = None) -> None:
        if file is None:
            file = sys.stderr if self.prog else sys.stdout
        super().print_usage(file)


def _positive_int(value: str) -> int:
    if not value or any(character < "0" or character > "9" for character in value):
        raise argparse.ArgumentTypeError("must be a positive integer")
    parsed = int(value, 10)
    if parsed < 1 or parsed > 4294967295:
        raise argparse.ArgumentTypeError("must be within the supported integer range")
    return parsed


def _build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="pymdcage",
        description="Strict zero-dependency Markdown security sanitizer, auditor, and link extractor.",
    )
    parser.add_argument("--version", action="store_true", help="print the pymdcage version")
    subparsers = parser.add_subparsers(dest="command", parser_class=_Parser)
    for command in ("audit", "sanitize", "extract-links"):
        sub = subparsers.add_parser(command, help=command + " a Markdown document")
        sub.add_argument("input", help="input file, or - for standard input")
        sub.add_argument("--json", action="store_true", help="emit machine-readable JSON")
        sub.add_argument("--preset", choices=("strict", "agent", "docs"), help="use a named security preset")
        sub.add_argument("--max-bytes", type=_positive_int, default=DEFAULT_POLICY.max_bytes, help="maximum input bytes")
        if command == "sanitize":
            sub.add_argument("--out", help="output file, or - for standard output")
    return parser


def _read_all_from_fd(fd: int, max_bytes: int) -> Tuple[bool, int, Optional[bytes]]:
    chunks = []
    total = 0
    while True:
        wanted = min(65536, max_bytes - total + 1)
        if wanted <= 0:
            return True, total + 1, None
        chunk = os.read(fd, wanted)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            return True, total, None
        chunks.append(chunk)
    return False, total, b"".join(chunks)


def _read_input(input_path: str, max_bytes: int) -> Tuple[bool, int, Optional[bytes]]:
    if input_path == "-":
        return _read_all_from_fd(0, max_bytes)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd: Optional[int] = None
    try:
        path_stat = os.lstat(input_path)
        if not stat.S_ISREG(path_stat.st_mode):
            raise OSError("input is not a regular file")
        fd = os.open(input_path, flags)
        open_stat = os.fstat(fd)
        if not stat.S_ISREG(open_stat.st_mode):
            raise OSError("input is not a regular file")
        if (path_stat.st_dev, path_stat.st_ino) != (open_stat.st_dev, open_stat.st_ino):
            raise OSError("input changed while opening")
        if open_stat.st_size > max_bytes:
            return True, open_stat.st_size, None
        return _read_all_from_fd(fd, max_bytes)
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def _write_output(output_path: Optional[str], data: str) -> None:
    encoded = data.encode("utf-8")
    if output_path in (None, "-"):
        sys.stdout.write(data)
        if not data.endswith("\n"):
            sys.stdout.write("\n")
        return
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(output_path, flags, 0o666)
    try:
        view = memoryview(encoded)
        while view:
            written = os.write(fd, view)
            view = view[written:]
    finally:
        os.close(fd)


def _error_finding(error: MdCageError) -> MdCageFinding:
    return MdCageFinding(
        error.code,
        error.reason,
        severity="critical",
        details=dict(error.details),
    )


def _error_report(error: MdCageError, byte_count: int) -> MdAuditReport:
    return MdAuditReport(False, (_error_finding(error),), MdCageStats(bytes=byte_count, findings=1), tuple())


def _print_json(value: Any) -> None:
    sys.stdout.write(json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n")


def _print_report(report: MdAuditReport) -> None:
    sys.stdout.write("safe: " + ("true" if report.safe else "false") + "\n")
    sys.stdout.write("findings: " + str(report.stats.findings) + "\n")
    for finding in report.findings:
        location = ""
        if finding.line is not None and finding.column is not None:
            location = " at line " + str(finding.line) + ", column " + str(finding.column)
        sys.stdout.write(
            neutralize_terminal(finding.severity + " " + finding.code + location + ": " + finding.message) + "\n"
        )


def _input_error_report(byte_count: int) -> MdAuditReport:
    error = MdCageError(ERROR["MAX_BYTES"], "input byte limit exceeded", {"limit": "see --max-bytes"})
    return _error_report(error, byte_count)


def run(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except _UsageError as error:
        _stderr("pymdcage: " + str(error))
        return 2

    if args.version:
        sys.stdout.write("pymdcage " + MDCAGE_VERSION + "\n")
        return 0
    if not args.command:
        _stderr("pymdcage: a command is required")
        return 2

    try:
        too_large, byte_count, data = _read_input(args.input, args.max_bytes)
    except OSError as error:
        _stderr("pymdcage: cannot read input: " + str(error))
        return 2

    options = {"preset": args.preset, "max_bytes": args.max_bytes}
    if too_large or data is None:
        report = _input_error_report(byte_count)
        if args.json:
            _print_json(report.to_dict())
        else:
            _print_report(report)
        return 1

    try:
        if args.command == "audit":
            report = audit_markdown(data, **options)
            if args.json:
                _print_json(report.to_dict())
            else:
                _print_report(report)
            return 0 if report.safe else 1

        if args.command == "extract-links":
            links = extract_links(data, **options)
            if args.json:
                _print_json({"links": [link.to_dict() for link in links]})
            else:
                for link in links:
                    sys.stdout.write(neutralize_terminal(link.kind + "\t" + link.url) + "\n")
            return 0 if all(link.safe for link in links) else 1

        result = sanitize_markdown(data, **options)
        output_path = getattr(args, "out", None)
        if args.json and output_path == "-":
            _stderr("pymdcage: --json cannot be combined with sanitize --out -")
            return 2
        if not args.json or output_path not in (None, "-"):
            try:
                _write_output(output_path, result.markdown)
            except OSError as error:
                _stderr("pymdcage: cannot write output: " + str(error))
                return 2
        unsafe = [finding for finding in result.findings if finding.severity in ("high", "critical")]
        safe = not unsafe and not (result.stats.findings > len(result.findings))
        if args.json:
            payload = result.to_dict()
            payload["safe"] = safe
            _print_json(payload)
        return 0 if safe else 1
    except MdCageError as error:
        report = _error_report(error, byte_count)
        if args.json:
            _print_json(report.to_dict())
        else:
            _print_report(report)
        return 1


def main(argv: Optional[Sequence[str]] = None) -> int:
    return run(argv)
