"""Link, reference, autolink, entity, and obfuscation security tests."""
from __future__ import annotations

import unittest

from helpers import add_generated_tests
from pymdcage import CODE, audit_markdown, extract_links, is_safe_markdown, sanitize_markdown

DANGEROUS_URLS = [
    "javascript:alert(1)",
    "JavaScript:alert(1)",
    "jAvAsCrIpT:alert(1)",
    "vbscript:msgbox(1)",
    "VBScript:msgbox(1)",
    "data:text/html;base64,xx",
    "DATA:text/html,xx",
    "file:///etc/passwd",
    "FILE:///etc/passwd",
    "blob:https://example.com/id",
    "BLOB:https://example.com/id",
    "java&#x73;cript:alert(1)",
    "jav&#97;script:alert(1)",
    "javascript&#x3a;alert(1)",
    "javascript&#58;alert(1)",
    "&#x6a;avascript:alert(1)",
    "&#106;avascript:alert(1)",
    "&Tab;javascript:alert(1)",
    "java&Tab;script:alert(1)",
    "javascript&colon;alert(1)",
    "java&NewLine;script:alert(1)",
    "j\\avascript:alert(1)",
    "jav\\ascript:alert(1)",
    "javascript\\:alert(1)",
    "%6Aavascript:alert(1)",
    "%6a%61vascript:alert(1)",
    "javascript%3Aalert(1)",
    "javascript%3aalert(1)",
    "%256Aavascript%253Aalert(1)",
    "java&#x00073;cript&#x000003A;alert(1)",
    "javascript&#x0000000003A;alert(1)",
]

INLINE_TEMPLATES = [
    "[x]({})",
    "![x]({})",
    "[x](<{}>)",
    "[x]({} \"title\")",
]


class GeneratedDangerousInlineTests(unittest.TestCase):
    pass


def _dangerous_cases():
    for url in DANGEROUS_URLS:
        for template in INLINE_TEMPLATES:
            yield template.format(url)


def _dangerous_body(self, source):
    result = sanitize_markdown(source)
    report = audit_markdown(source)
    self.assertFalse(report.safe, source)
    self.assertTrue(result.changed, source)
    self.assertNotIn("](", result.markdown, source)
    self.assertTrue(
        any(finding.code in (CODE["DANGEROUS_SCHEME"], CODE["DISALLOWED_SCHEME"]) for finding in result.findings),
        (source, [finding.code for finding in result.findings]),
    )


add_generated_tests(GeneratedDangerousInlineTests, "dangerous_inline", list(_dangerous_cases()), _dangerous_body)


class GeneratedDangerousReferenceTests(unittest.TestCase):
    pass


def _reference_cases():
    for url in DANGEROUS_URLS:
        yield "[x][r]\n\n[r]: " + url + "\n"


def _reference_body(self, source):
    result = sanitize_markdown(source)
    self.assertFalse(audit_markdown(source).safe, source)
    self.assertNotIn("[r]:", result.markdown)
    self.assertTrue(any(finding.code == CODE["DANGEROUS_SCHEME"] for finding in result.findings))
    links = extract_links(source)
    self.assertEqual(len(links), 1)
    self.assertFalse(links[0].safe)


add_generated_tests(GeneratedDangerousReferenceTests, "dangerous_reference", list(_reference_cases()), _reference_body)


WHITESPACE_OBFUSCATION = [
    "[x]( javascript:alert(1))",
    "[x](\tjavascript:alert(1))",
    "[x](java\tscript:alert(1))",
    "[x](java script:alert(1))",
    "[x](java\nscript:alert(1))",
    "[x](javascript :alert(1))",
    "[x](javascript: alert(1))",
    "[x](javascript:\talert(1))",
    "[x](jav\rascript:alert(1))",
    "[x](j a v a s c r i p t:alert(1))",
    "[x](< javascript:alert(1)>)",
    "[x](<java\tscript:alert(1)>)",
]


class GeneratedWhitespaceObfuscationTests(unittest.TestCase):
    pass


def _whitespace_body(self, source):
    result = sanitize_markdown(source)
    self.assertFalse(audit_markdown(source).safe, source)
    self.assertEqual(result.markdown, "x", source)
    self.assertTrue(any(finding.code == CODE["DANGEROUS_SCHEME"] for finding in result.findings), source)


add_generated_tests(GeneratedWhitespaceObfuscationTests, "whitespace_obfuscation", WHITESPACE_OBFUSCATION, _whitespace_body)


DANGEROUS_AUTOLINKS = [
    "<javascript:alert(1)>",
    "<JavaScript:alert(1)>",
    "<vbscript:msgbox(1)>",
    "<data:text/html,xx>",
    "<file:///etc/passwd>",
    "<blob:https://example.com/id>",
    "<ftp://example.com/x>",
    "<ssh://example.com/x>",
]


class GeneratedDangerousAutolinkTests(unittest.TestCase):
    pass


def _autolink_body(self, source):
    result = sanitize_markdown(source)
    self.assertFalse(audit_markdown(source).safe, source)
    self.assertNotEqual(result.markdown, source)
    self.assertFalse(result.markdown.startswith("<"), source)
    self.assertEqual(len(result.links), 1)
    self.assertFalse(result.links[0].safe)


add_generated_tests(GeneratedDangerousAutolinkTests, "dangerous_autolink", DANGEROUS_AUTOLINKS, _autolink_body)


SAFE_INLINE_LINKS = [
    "[x](https://example.com)",
    "[x](http://example.com)",
    "[x](mailto:user@example.com)",
    "[x](#fragment)",
    "[x](/absolute/path)",
    "[x](relative/path)",
    "[x](./relative)",
    "[x](../relative)",
    "[x](path?q=1&v=2)",
    "[x](path#fragment)",
    "[x](<https://example.com/a b>)",
    "[x](https://example.com/a(b))",
    "[x](https://example.com/a\\(b)",
    "[x](https://example.com \"title\")",
    "[x](https://example.com 'title')",
    "[x](https://example.com (title))",
    "[a *b* c](https://example.com)",
    "[x y z](relative)",
    "![x](image.png)",
    "![x](/images/image.png)",
    "![x](#local)",
    "[x](HTTPS://example.com)",
    "[x](MailTo:user@example.com)",
    "[x](&#x68;ttps://example.com)",
    "[x](ht&#116;ps://example.com)",
    "[x](\\#fragment)",
    "[x](a%20b)",
    "[x](<relative with spaces>)",
    "[](https://example.com)",
    "![](image.png)",
]


class GeneratedSafeInlineTests(unittest.TestCase):
    pass


def _safe_body(self, source):
    result = sanitize_markdown(source)
    self.assertEqual(result.markdown, source, source)
    self.assertTrue(audit_markdown(source).safe, (source, [finding.code for finding in result.findings]))
    self.assertEqual(len(result.links), 1, source)
    self.assertTrue(result.links[0].safe, source)


add_generated_tests(GeneratedSafeInlineTests, "safe_inline", SAFE_INLINE_LINKS, _safe_body)


DISALLOWED_SCHEMES = [
    "ftp://example.com",
    "ssh://example.com",
    "tel:+15555550100",
    "sms:+15555550100",
    "about:blank",
    "chrome://settings",
    "view-source:https://example.com",
    "ws://example.com",
    "wss://example.com",
    "custom:thing",
]


class GeneratedDisallowedSchemeTests(unittest.TestCase):
    pass


def _disallowed_body(self, url):
    source = "[x](" + url + ")"
    result = sanitize_markdown(source)
    self.assertFalse(audit_markdown(source).safe, source)
    self.assertEqual(result.markdown, "x")
    self.assertEqual(result.findings[0].code, CODE["DISALLOWED_SCHEME"])


add_generated_tests(GeneratedDisallowedSchemeTests, "disallowed_scheme", DISALLOWED_SCHEMES, _disallowed_body)


REFERENCE_CASES = [
    ("[x][r]\n\n[r]: https://example.com\n", "docs", True),
    ("[x][R]\n\n[r]: https://example.com\n", "docs", True),
    ("[x][]\n\n[x]: https://example.com\n", "docs", True),
    ("[shortcut]\n\n[shortcut]: https://example.com\n", "docs", True),
    ("![i][r]\n\n[r]: image.png\n", "docs", True),
    ("[x][missing]\n", "docs", True),
    ("[missing]\n", "docs", True),
    ("[x][r]\n\n[r]: <https://example.com/a b> \"title\"\n", "docs", True),
    ("[x][r]\n\n[r]: https://example.com 'title'\n", "docs", True),
    ("[x][r]\n\n[r]: https://example.com (title)\n", "docs", True),
]


class ReferenceBehaviorTests(unittest.TestCase):
    def test_reference_cases_are_stable_in_docs_preset(self):
        for source, preset, expected_safe in REFERENCE_CASES:
            with self.subTest(source=source):
                result = sanitize_markdown(source, preset=preset)
                self.assertEqual(sanitize_markdown(result.markdown, preset=preset).markdown, result.markdown)
                self.assertEqual(audit_markdown(source, preset=preset).safe, expected_safe)

    def test_reference_is_unfolded_by_default(self):
        source = "[x][r]\n\n[r]: https://example.com\n"
        result = sanitize_markdown(source)
        self.assertIn("[x](<https://example.com>)", result.markdown)
        self.assertNotIn("[r]:", result.markdown)
        self.assertEqual(sanitize_markdown(result.markdown).markdown, result.markdown)

    def test_image_reference_is_unfolded_as_image(self):
        source = "![i][r]\n\n[r]: image.png\n"
        result = sanitize_markdown(source)
        self.assertIn("![i](<image.png>)", result.markdown)

    def test_unused_reference_is_removed(self):
        source = "visible\n\n[unused]: https://example.com\n"
        result = sanitize_markdown(source)
        self.assertNotIn("unused]:", result.markdown)
        self.assertTrue(any(finding.code == CODE["UNUSED_REFERENCE"] for finding in result.findings))

    def test_duplicate_reference_uses_first_definition(self):
        source = "[x][r]\n\n[r]: https://one.example\n[r]: javascript:alert(1)\n"
        result = sanitize_markdown(source, preset="docs")
        self.assertIn("https://one.example", result.markdown)
        self.assertNotIn("javascript", result.markdown)

    def test_extract_reference_title(self):
        source = "[x][r]\n\n[r]: https://example.com \"the title\"\n"
        links = extract_links(source, preset="docs")
        self.assertEqual(links[0].title, "the title")


MALFORMED_CASES = [
    "[x]()",
    "[x](",
    "[x](   ",
    "[x](not a link)",
    "[x](<unclosed)",
    "[x](<bad\ndest>)",
    "[x](url \"unclosed)",
    "[x](url 'unclosed)",
    "[x](url (unclosed)",
    "[x](url) trailing",
    "[x][unclosed",
    "[x][]",
    "![x]()",
    "![x](",
    "[x]((((((((((",
]


class GeneratedMalformedTests(unittest.TestCase):
    pass


def _malformed_body(self, source):
    result = sanitize_markdown(source)
    self.assertEqual(sanitize_markdown(result.markdown).markdown, result.markdown)
    self.assertNotIn("javascript:", result.markdown.lower())


add_generated_tests(GeneratedMalformedTests, "malformed_neutral", MALFORMED_CASES, _malformed_body)


class LinkModelTests(unittest.TestCase):
    def test_positions_are_one_based_line_and_column(self):
        source = "first\nsecond [x](https://example.com)\n"
        link = extract_links(source)[0]
        self.assertEqual(link.line, 2)
        self.assertEqual(link.column, 8)
        self.assertEqual(link.position, len("first\nsecond "))

    def test_external_flag(self):
        self.assertTrue(extract_links("[x](https://example.com)")[0].external)
        self.assertFalse(extract_links("[x](relative)")[0].external)
        self.assertFalse(extract_links("[x](mailto:user@example.com)")[0].external)

    def test_image_kind(self):
        self.assertEqual(extract_links("![alt](image.png)")[0].kind, "image")

    def test_autolink_kind(self):
        self.assertEqual(extract_links("<https://example.com>")[0].kind, "autolink")

    def test_reference_kind(self):
        self.assertEqual(extract_links("[x][r]\n\n[r]: y\n")[0].kind, "reference")

    def test_safe_email_autolink(self):
        self.assertTrue(is_safe_markdown("<user@example.com>"))
        self.assertEqual(extract_links("<user@example.com>")[0].url, "mailto:user@example.com")

    def test_autolinks_can_be_disabled(self):
        report = audit_markdown("<https://example.com>", preset="strict")
        self.assertFalse(report.safe)

    def test_escaped_opening_bracket_is_literal(self):
        source = "\\[x](javascript:alert(1))"
        self.assertEqual(sanitize_markdown(source).markdown, source)

    def test_escaped_closing_bracket_is_not_a_link(self):
        source = "[x\\](javascript:alert(1))"
        self.assertEqual(sanitize_markdown(source).markdown, source)

    def test_label_entities_are_decoded_in_metadata(self):
        link = extract_links("[a &amp; b](x)")[0]
        self.assertEqual(link.label, "a & b")

    def test_extract_multiple_links_in_order(self):
        links = extract_links("[a](x) [b](y) <https://example.com>")
        self.assertEqual([link.label for link in links], ["a", "b", "https://example.com"])


if __name__ == "__main__":
    unittest.main()
