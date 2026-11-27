"""Raw HTML, SVG smuggling, and active-attribute defense tests."""
from __future__ import annotations

import unittest

from helpers import add_generated_tests
from pymdcage import CODE, audit_markdown, sanitize_markdown

ACTIVE_TAGS = [
    "script", "iframe", "svg", "math", "style", "form", "object", "embed",
    "meta", "link", "base", "applet", "frame", "frameset", "input", "button",
    "textarea", "select", "audio", "video", "source", "track", "template",
]


def _active_cases():
    for tag in ACTIVE_TAGS:
        yield "<" + tag + ">x</" + tag + ">"
        yield "<" + tag.upper() + ">x</" + tag.upper() + ">"
        yield "<" + tag + " type=\"text/plain\">x</" + tag + ">"
        yield "before <" + tag + ">x</" + tag + "> after"


class GeneratedActiveHtmlTests(unittest.TestCase):
    pass


def _active_body(self, source):
    result = sanitize_markdown(source)
    self.assertFalse(audit_markdown(source).safe, source)
    self.assertNotIn("<script", result.markdown.lower())
    self.assertNotIn("<iframe", result.markdown.lower())
    self.assertTrue(any(finding.code in (CODE["ACTIVE_HTML"], CODE["RAW_HTML"]) for finding in result.findings), source)
    self.assertEqual(sanitize_markdown(result.markdown).markdown, result.markdown)


add_generated_tests(GeneratedActiveHtmlTests, "active_html", list(_active_cases()), _active_body)


BENIGN_TAGS = ["b", "strong", "em", "i", "u", "code", "pre", "blockquote", "div", "span", "p", "br", "hr", "small", "kbd"]


class GeneratedBenignHtmlTests(unittest.TestCase):
    pass


def _benign_body(self, tag):
    source = "<" + tag + ">visible</" + tag + ">"
    result = sanitize_markdown(source)
    self.assertNotIn("<" + tag, result.markdown)
    self.assertFalse(audit_markdown(source).safe)
    self.assertTrue(all(finding.code == CODE["RAW_HTML"] for finding in result.findings), source)


add_generated_tests(GeneratedBenignHtmlTests, "benign_html_stripped", BENIGN_TAGS, _benign_body)


EVENT_ATTRIBUTES = [
    "onerror", "onload", "onclick", "onmouseover", "onfocus", "onanimationstart",
    "ontransitionend", "onpointerenter", "onsubmit", "oninput",
]


class GeneratedEventAttributeTests(unittest.TestCase):
    pass


def _event_cases():
    for attribute in EVENT_ATTRIBUTES:
        yield "<img src=\"image.png\" " + attribute + "=\"alert(1)\">"
        yield "<div " + attribute + "=alert(1)>x</div>"


def _event_body(self, source):
    result = sanitize_markdown(source, allow_html=True)
    self.assertFalse(audit_markdown(source, allow_html=True).safe, source)
    self.assertTrue(any(finding.code == CODE["ACTIVE_HTML"] for finding in result.findings), source)
    self.assertNotIn("onerror", result.markdown.lower())
    self.assertNotIn("onload", result.markdown.lower())


add_generated_tests(GeneratedEventAttributeTests, "event_attribute", list(_event_cases()), _event_body)


DANGEROUS_HTML_URL_ATTRIBUTES = [
    "<a href=\"javascript:alert(1)\">x</a>",
    "<a href=javascript:alert(1)>x</a>",
    "<a href=\"vbscript:msgbox(1)\">x</a>",
    "<a href=\"data:text/html,xx\">x</a>",
    "<img src=\"javascript:alert(1)\">",
    "<img src=\"data:image/svg+xml,xx\">",
    "<img poster=\"javascript:alert(1)\">",
    "<div background=\"javascript:alert(1)\">x</div>",
    "<a href=\"java&#x73;cript:alert(1)\">x</a>",
    "<a href=\"jav\\ascript:alert(1)\">x</a>",
]


class GeneratedDangerousHtmlAttributeTests(unittest.TestCase):
    pass


def _dangerous_attr_body(self, source):
    result = sanitize_markdown(source, allow_html=True)
    self.assertFalse(audit_markdown(source, allow_html=True).safe, source)
    self.assertTrue(any(finding.code == CODE["ACTIVE_HTML"] for finding in result.findings), source)
    self.assertNotIn("javascript:", result.markdown.lower())


add_generated_tests(GeneratedDangerousHtmlAttributeTests, "dangerous_html_attribute", DANGEROUS_HTML_URL_ATTRIBUTES, _dangerous_attr_body)


DANGEROUS_STYLES = [
    "<div style=\"width:expression(alert(1))\">x</div>",
    "<div style=\"background:url(javascript:alert(1))\">x</div>",
    "<div style=\"background: url( javascript:alert(1) )\">x</div>",
    "<div style=\"@import url(evil.css)\">x</div>",
    "<div style=\"behavior:url(x.htc)\">x</div>",
    "<div style=\"content:java\\script:alert(1)\">x</div>",
]


class GeneratedDangerousStyleTests(unittest.TestCase):
    pass


def _style_body(self, source):
    result = sanitize_markdown(source, allow_html=True)
    self.assertFalse(audit_markdown(source, allow_html=True).safe, source)
    self.assertTrue(any(finding.code == CODE["ACTIVE_HTML"] for finding in result.findings), source)


add_generated_tests(GeneratedDangerousStyleTests, "dangerous_style", DANGEROUS_STYLES, _style_body)


PRESERVED_WHEN_ALLOWED = [
    "<b>bold</b>",
    "<em>emphasis</em>",
    "<code>code</code>",
    "<pre>preformatted</pre>",
    "<blockquote>quote</blockquote>",
    "<div class=\"note\">note</div>",
    "<span id=\"x\">span</span>",
    "<p>para</p>",
    "<a href=\"https://example.com\">safe</a>",
    "<img src=\"image.png\" alt=\"local\">",
]


class GeneratedAllowedHtmlTests(unittest.TestCase):
    pass


def _allowed_body(self, source):
    result = sanitize_markdown(source, allow_html=True)
    self.assertEqual(result.markdown, source, source)
    self.assertTrue(audit_markdown(source, allow_html=True).safe, source)


add_generated_tests(GeneratedAllowedHtmlTests, "allowed_html_preserved", PRESERVED_WHEN_ALLOWED, _allowed_body)


MALFORMED_HTML_CASES = [
    "<script",
    "<script>",
    "</script",
    "<svg",
    "<iframe src=x",
    "<img src=x onerror=alert(1)",
    "<div",
    "<b",
    "<!",
    "<?php echo 1;",
    "<![CDATA[x]]>",
    "<a href=\"unclosed>",
    "<a href='unclosed>",
    "<x><y>",
]


class GeneratedMalformedHtmlTests(unittest.TestCase):
    pass


def _malformed_html_body(self, source):
    result = sanitize_markdown(source)
    self.assertEqual(sanitize_markdown(result.markdown).markdown, result.markdown)
    self.assertFalse(audit_markdown(source).safe, source)


add_generated_tests(GeneratedMalformedHtmlTests, "malformed_html", MALFORMED_HTML_CASES, _malformed_html_body)


class HtmlBehaviorTests(unittest.TestCase):
    def test_script_content_is_preserved_as_plain_text(self):
        result = sanitize_markdown("<script>alert(1)</script>")
        self.assertEqual(result.markdown, "alert(1)")

    def test_custom_html_element_is_stripped_by_default(self):
        result = sanitize_markdown("<widget data-x=\"1\">x</widget>")
        self.assertEqual(result.markdown, "x")

    def test_html_inside_fence_is_literal(self):
        source = "```\n<script>alert(1)</script>\n```\n"
        result = sanitize_markdown(source)
        self.assertEqual(result.markdown, source)
        self.assertTrue(audit_markdown(source).safe)

    def test_html_inside_inline_code_is_literal(self):
        source = "`<script>alert(1)</script>`"
        result = sanitize_markdown(source)
        self.assertEqual(result.markdown, source)

    def test_angle_bracket_math_text_is_preserved(self):
        source = "1 < 2 and 3 > 2"
        result = sanitize_markdown(source)
        self.assertEqual(result.markdown, source)

    def test_nested_active_svg_is_removed(self):
        result = sanitize_markdown("<svg><script>alert(1)</script></svg>")
        self.assertNotIn("<svg", result.markdown)
        self.assertNotIn("<script", result.markdown)

    def test_malformed_tag_consumption_is_idempotent(self):
        first = sanitize_markdown("<script").markdown
        self.assertEqual(sanitize_markdown(first).markdown, first)

    def test_dangerous_attribute_does_not_leave_closing_tag(self):
        result = sanitize_markdown("<div style=\"background:url(javascript:x)\">x</div>", allow_html=True)
        self.assertEqual(result.markdown, "x")

    def test_mathml_children_in_removed_math_do_not_survive(self):
        result = sanitize_markdown("<math><mtext>x</mtext></math>", allow_html=True)
        self.assertEqual(result.markdown, "x")

    def test_unmatched_benign_closing_tag_is_removed_when_html_allowed(self):
        result = sanitize_markdown("x</b>", allow_html=True)
        self.assertEqual(result.markdown, "x")


if __name__ == "__main__":
    unittest.main()
