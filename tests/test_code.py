"""Fenced and inline code preservation tests."""
from __future__ import annotations

import unittest

from helpers import add_generated_tests
from pymdcage import CODE, audit_markdown, sanitize_markdown

PRESERVED_CODE_CASES = [
    "`code`",
    "``code``",
    "`` `code` ``",
    "`[x](javascript:alert(1))`",
    "`<script>alert(1)</script>`",
    "`<!-- comment -->`",
    "before `[x](javascript:alert(1))` after",
    "`multi\nline [x](javascript:alert(1))`",
    "````\ncode\n````\n",
    "```\n[x](javascript:alert(1))\n```\n",
    "~~~\n[x](javascript:alert(1))\n~~~\n",
    "```python\n<script>alert(1)</script>\n```\n",
    "   ```\ncode\n   ```\n",
    "````\n```\n````\n",
]


class GeneratedCodePreservationTests(unittest.TestCase):
    pass


def _code_body(self, source):
    result = sanitize_markdown(source)
    self.assertEqual(result.markdown, source, source)
    self.assertTrue(audit_markdown(source).safe, (source, [finding.code for finding in result.findings]))


add_generated_tests(GeneratedCodePreservationTests, "code_preserved", PRESERVED_CODE_CASES, _code_body)


class FenceTests(unittest.TestCase):
    def test_unclosed_fence_is_preserved_but_reported(self):
        source = "```\n[x](javascript:alert(1))\n"
        result = sanitize_markdown(source)
        self.assertEqual(result.markdown, source)
        self.assertTrue(any(finding.code == CODE["UNCLOSED_FENCE"] for finding in result.findings))

    def test_closing_fence_must_use_same_marker(self):
        source = "```\n[x](javascript:alert(1))\n~~~\n"
        result = sanitize_markdown(source)
        self.assertEqual(result.markdown, source)
        self.assertTrue(any(finding.code == CODE["UNCLOSED_FENCE"] for finding in result.findings))

    def test_closing_fence_must_be_long_enough(self):
        source = "````\n[x](javascript:alert(1))\n```\n"
        result = sanitize_markdown(source)
        self.assertEqual(result.markdown, source)
        self.assertTrue(any(finding.code == CODE["UNCLOSED_FENCE"] for finding in result.findings))

    def test_longer_closing_fence_is_valid(self):
        source = "```\ncode\n````\n"
        self.assertEqual(sanitize_markdown(source).markdown, source)

    def test_closing_fence_with_trailing_spaces_is_valid(self):
        source = "```\ncode\n```   \n"
        self.assertEqual(sanitize_markdown(source).markdown, source)

    def test_closing_fence_with_info_does_not_close(self):
        source = "```\n[x](javascript:alert(1))\n``` text\n"
        result = sanitize_markdown(source)
        self.assertEqual(result.markdown, source)
        self.assertTrue(any(finding.code == CODE["UNCLOSED_FENCE"] for finding in result.findings))

    def test_indented_backticks_are_not_used_to_hide_links(self):
        source = "    ```\n[x](javascript:alert(1))\n    ```\n"
        result = sanitize_markdown(source)
        self.assertNotIn("](javascript:", result.markdown)

    def test_backtick_in_info_is_not_used_to_hide_links(self):
        source = "``` ````\n[x](javascript:alert(1))\n```\n"
        result = sanitize_markdown(source)
        self.assertNotIn("](javascript:", result.markdown)

    def test_fence_stats(self):
        result = sanitize_markdown("```\nx\n```\n")
        self.assertEqual(result.stats.fenced_code_blocks, 1)


class InlineCodeTests(unittest.TestCase):
    def test_single_unmatched_backtick_is_low_severity(self):
        result = sanitize_markdown("a ` b")
        self.assertEqual(result.markdown, "a ` b")
        self.assertTrue(any(finding.code == CODE["UNCLOSED_CODE_SPAN"] for finding in result.findings))
        self.assertTrue(audit_markdown("a ` b").safe)

    def test_later_matching_backtick_protects_code(self):
        source = "before `[x](javascript:alert(1))` after"
        result = sanitize_markdown(source)
        self.assertEqual(result.markdown, source)

    def test_text_after_closed_code_is_scanned(self):
        source = "`code` [x](javascript:alert(1))"
        result = sanitize_markdown(source)
        self.assertEqual(result.markdown, "`code` x")

    def test_text_before_closed_code_is_scanned(self):
        source = "[x](javascript:alert(1)) `code`"
        result = sanitize_markdown(source)
        self.assertEqual(result.markdown, "x `code`")

    def test_different_length_backticks_do_not_close(self):
        source = "``code` [x](javascript:alert(1))"
        result = sanitize_markdown(source)
        self.assertNotIn("](javascript:", result.markdown)

    def test_backtick_run_inside_longer_span_is_literal(self):
        source = "`` ` `` [x](javascript:alert(1))"
        result = sanitize_markdown(source)
        self.assertNotIn("](javascript:", result.markdown)

    def test_code_span_stats(self):
        result = sanitize_markdown("`a` and ``b``")
        self.assertEqual(result.stats.code_spans, 2)

    def test_multiline_inline_code_preserves_newline(self):
        source = "before `one\ntwo` after"
        self.assertEqual(sanitize_markdown(source).markdown, source)

    def test_blank_line_separates_inline_code_blocks(self):
        source = "`unclosed\n\n[x](javascript:alert(1))`"
        result = sanitize_markdown(source)
        self.assertNotIn("](javascript:", result.markdown)


if __name__ == "__main__":
    unittest.main()
