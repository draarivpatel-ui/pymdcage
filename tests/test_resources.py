"""Resource-limit, immutability, recursion-safety, and linear-time tests."""
from __future__ import annotations

import time
import unittest

from pymdcage import CODE, MdCageError, audit_markdown, sanitize_markdown


class ResourceLimitTests(unittest.TestCase):
    def test_max_bytes_str(self):
        with self.assertRaises(MdCageError) as caught:
            sanitize_markdown("abcd", max_bytes=3)
        self.assertEqual(caught.exception.code, CODE["MAX_BYTES"])

    def test_max_bytes_bytes(self):
        with self.assertRaises(MdCageError):
            sanitize_markdown(b"abcd", max_bytes=3)

    def test_max_bytes_bytearray_checked_before_copy(self):
        data = bytearray(b"abcd")
        with self.assertRaises(MdCageError) as caught:
            sanitize_markdown(data, max_bytes=3)
        self.assertEqual(caught.exception.code, CODE["MAX_BYTES"])

    def test_max_bytes_memoryview_checked_before_copy(self):
        view = memoryview(b"abcd")
        with self.assertRaises(MdCageError) as caught:
            sanitize_markdown(view, max_bytes=3)
        self.assertEqual(caught.exception.code, CODE["MAX_BYTES"])

    def test_max_lines(self):
        with self.assertRaises(MdCageError) as caught:
            sanitize_markdown("a\nb\n", max_lines=1)
        self.assertEqual(caught.exception.code, CODE["MAX_LINES"])

    def test_max_links(self):
        with self.assertRaises(MdCageError) as caught:
            sanitize_markdown("[a](x) [b](y)", max_links=1)
        self.assertEqual(caught.exception.code, CODE["MAX_LINKS"])

    def test_max_reference_defs(self):
        source = "[a]: x\n[b]: y\n"
        with self.assertRaises(MdCageError) as caught:
            sanitize_markdown(source, max_reference_defs=1)
        self.assertEqual(caught.exception.code, CODE["MAX_REFERENCE_DEFS"])

    def test_max_bracket_nesting(self):
        source = "[" * 40 + "]" * 40
        with self.assertRaises(MdCageError) as caught:
            sanitize_markdown(source, max_nesting_depth=10)
        self.assertEqual(caught.exception.code, CODE["MAX_NESTING_DEPTH"])

    def test_max_destination_nesting(self):
        source = "[x](" + "(" * 20 + ")"
        with self.assertRaises(MdCageError) as caught:
            sanitize_markdown(source, max_nesting_depth=5)
        self.assertEqual(caught.exception.code, CODE["MAX_NESTING_DEPTH"])

    def test_max_output_bytes(self):
        with self.assertRaises(MdCageError) as caught:
            sanitize_markdown("abcdef", max_output_bytes=3)
        self.assertEqual(caught.exception.code, CODE["MAX_OUTPUT_BYTES"])

    def test_max_output_bytes_after_unfolding(self):
        source = "[x][r]\n\n[r]: https://example.com/" + "a" * 100 + "\n"
        with self.assertRaises(MdCageError) as caught:
            sanitize_markdown(source, max_output_bytes=20)
        self.assertEqual(caught.exception.code, CODE["MAX_OUTPUT_BYTES"])

    def test_max_findings_sentinel_replaces_last(self):
        result = sanitize_markdown("<!--a--><!--b-->", max_findings=1)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].code, CODE["MAX_FINDINGS"])
        self.assertGreater(result.stats.findings, len(result.findings))

    def test_audit_fails_closed_when_findings_truncated(self):
        report = audit_markdown("<!--a--><!--b-->", max_findings=1)
        self.assertFalse(report.safe)

    def test_stats_are_counted(self):
        result = sanitize_markdown("```\nx\n```\n`a` [x](y) <!--c-->")
        self.assertEqual(result.stats.fenced_code_blocks, 1)
        self.assertEqual(result.stats.code_spans, 1)
        self.assertEqual(result.stats.links, 1)
        self.assertEqual(result.stats.html_comments, 1)

    def test_empty_input_stats(self):
        result = sanitize_markdown("")
        self.assertEqual(result.stats.bytes, 0)
        self.assertEqual(result.stats.lines, 0)


class NoRecursionTests(unittest.TestCase):
    def test_deep_brackets_do_not_use_recursion(self):
        source = "[" * 1000 + "x" + "]" * 1000
        result = sanitize_markdown(source, max_nesting_depth=2000)
        self.assertIn("x", result.markdown)

    def test_deep_parentheses_do_not_use_recursion(self):
        source = "[x](" + "(" * 500 + ")"
        with self.assertRaises(MdCageError):
            sanitize_markdown(source, max_nesting_depth=100)

    def test_many_lines_do_not_use_recursion(self):
        source = "line\n" * 1000
        result = sanitize_markdown(source)
        self.assertEqual(result.markdown, source)


class LinearTimeTests(unittest.TestCase):
    def _ratio(self, small, large, **options):
        def run(source):
            start = time.perf_counter()
            try:
                sanitize_markdown(
                    source,
                    max_bytes=300000,
                    max_output_bytes=300000,
                    max_links=50000,
                    max_findings=10,
                    **options,
                )
            except MdCageError:
                pass
            return time.perf_counter() - start
        small_time = min(run(small) for _ in range(2))
        large_time = min(run(large) for _ in range(2))
        if small_time < 0.001:
            small_time = 0.001
        return large_time / small_time

    def test_angle_html_scan_scales_linearly_on_100k_chars(self):
        small = "<a " * 17000
        large = "<a " * 34000
        self.assertGreaterEqual(len(large), 100000)
        self.assertLess(self._ratio(small, large), 3.0)

    def test_bracket_scan_scales_linearly_on_100k_chars(self):
        small = "[" * 25000 + "]" * 25000
        large = "[" * 50000 + "]" * 50000
        self.assertGreaterEqual(len(large), 100000)
        self.assertLess(self._ratio(small, large, max_nesting_depth=100000), 8.0)

    def test_backtick_scan_scales_linearly_on_100k_chars(self):
        small = "`a" * 25000
        large = "`a" * 50000
        self.assertGreaterEqual(len(large), 100000)
        self.assertLess(self._ratio(small, large), 3.0)

    def test_comment_scan_scales_linearly_on_100k_chars(self):
        small = "<!--x-->" * 6250
        large = "<!--x-->" * 12500
        self.assertGreaterEqual(len(large), 100000)
        self.assertLess(self._ratio(small, large), 3.0)

    def test_link_scan_scales_linearly_on_100k_chars(self):
        small = "[x](y) " * 7200
        large = "[x](y) " * 14400
        self.assertGreaterEqual(len(large), 100000)
        self.assertLess(self._ratio(small, large), 3.0)

    def test_hidden_unicode_scan_scales_linearly_on_100k_chars(self):
        small = "a\u200b" * 25000
        large = "a\u200b" * 50000
        self.assertGreaterEqual(len(large), 100000)
        self.assertLess(self._ratio(small, large), 3.0)


if __name__ == "__main__":
    unittest.main()
