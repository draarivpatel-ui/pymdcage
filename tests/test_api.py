"""Public API, policy, immutability, and input validation tests."""
from __future__ import annotations

import dataclasses
import unittest

from pymdcage import (
    CODE,
    DEFAULT_POLICY,
    MdCage,
    MdCageError,
    MdPolicy,
    audit_markdown,
    create_md_cage,
    extract_links,
    is_safe_markdown,
    normalize_policy,
    preset_policy,
    sanitize_markdown,
    validate_markdown,
)


class PublicApiTests(unittest.TestCase):
    def test_safe_text_is_unchanged(self):
        result = sanitize_markdown("plain text")
        self.assertEqual(result.markdown, "plain text")
        self.assertFalse(result.changed)
        self.assertEqual(result.findings, tuple())

    def test_safe_link_is_preserved(self):
        source = "[docs](https://example.com/docs \"title\")"
        result = sanitize_markdown(source)
        self.assertEqual(result.markdown, source)
        self.assertEqual(len(result.links), 1)
        self.assertEqual(result.links[0].url, "https://example.com/docs")
        self.assertEqual(result.links[0].title, "title")
        self.assertTrue(result.links[0].safe)

    def test_dangerous_link_is_unlinked(self):
        result = sanitize_markdown("[click](javascript:alert(1))")
        self.assertEqual(result.markdown, "click")
        self.assertTrue(result.changed)
        self.assertEqual(result.findings[0].code, CODE["DANGEROUS_SCHEME"])
        self.assertFalse(audit_markdown("[click](javascript:alert(1))").safe)

    def test_audit_safe_boolean(self):
        self.assertTrue(is_safe_markdown("hello"))
        self.assertFalse(is_safe_markdown("[x](data:text/html;base64,xx)"))

    def test_validate_returns_safe_report(self):
        report = validate_markdown("hello")
        self.assertTrue(report.safe)

    def test_validate_raises_for_unsafe_input(self):
        with self.assertRaises(MdCageError) as caught:
            validate_markdown("[x](javascript:alert(1))")
        self.assertEqual(caught.exception.code, CODE["DANGEROUS_SCHEME"])

    def test_extract_links_includes_unsafe_links(self):
        links = extract_links("[x](javascript:alert(1))")
        self.assertEqual(len(links), 1)
        self.assertFalse(links[0].safe)
        self.assertEqual(links[0].code, CODE["DANGEROUS_SCHEME"])

    def test_result_to_dict_shape(self):
        data = sanitize_markdown("[x](javascript:alert(1))").to_dict()
        for key in ("markdown", "changed", "findings", "stats", "links"):
            self.assertIn(key, data)

    def test_audit_to_dict_shape(self):
        data = audit_markdown("[x](javascript:alert(1))").to_dict()
        for key in ("safe", "findings", "stats", "links"):
            self.assertIn(key, data)
        self.assertFalse(data["safe"])

    def test_link_to_dict_shape(self):
        data = extract_links("[x](https://example.com)")[0].to_dict()
        for key in ("label", "url", "kind", "position", "line", "column", "external", "safe"):
            self.assertIn(key, data)

    def test_error_to_dict_shape(self):
        try:
            sanitize_markdown("x", max_bytes=0)
        except MdCageError as error:
            data = error.to_dict()
            self.assertEqual(data["code"], CODE["INVALID_POLICY"])
        else:
            self.fail("invalid policy did not raise")

    def test_facade_uses_bound_policy(self):
        cage = MdCage(max_bytes=4)
        with self.assertRaises(MdCageError):
            cage.sanitize("abcdef")

    def test_create_md_cage(self):
        cage = create_md_cage()
        self.assertTrue(cage.is_safe("hello"))
        self.assertEqual(cage.extract_links("[x](y)")[0].url, "y")

    def test_bytes_input(self):
        result = sanitize_markdown(b"[x](javascript:alert(1))")
        self.assertEqual(result.markdown, "x")

    def test_bytearray_input(self):
        result = sanitize_markdown(bytearray(b"[x](javascript:alert(1))"))
        self.assertEqual(result.markdown, "x")

    def test_memoryview_input(self):
        result = sanitize_markdown(memoryview(b"[x](javascript:alert(1))"))
        self.assertEqual(result.markdown, "x")

    def test_released_memoryview_is_typed_error(self):
        view = memoryview(bytearray(b"abc"))
        view.release()
        with self.assertRaises(MdCageError) as caught:
            sanitize_markdown(view)
        self.assertEqual(caught.exception.code, CODE["INPUT_RELEASED"])

    def test_invalid_input_type_is_typed_error(self):
        with self.assertRaises(MdCageError) as caught:
            sanitize_markdown(object())
        self.assertEqual(caught.exception.code, CODE["INVALID_INPUT"])

    def test_invalid_utf8_is_typed_error(self):
        with self.assertRaises(MdCageError) as caught:
            sanitize_markdown(b"\xff")
        self.assertEqual(caught.exception.code, CODE["INVALID_UTF8"])

    def test_unpaired_surrogate_is_typed_error(self):
        with self.assertRaises(MdCageError) as caught:
            sanitize_markdown("\ud800")
        self.assertEqual(caught.exception.code, CODE["UNPAIRED_SURROGATE"])

    def test_unpaired_low_surrogate_is_typed_error(self):
        with self.assertRaises(MdCageError) as caught:
            sanitize_markdown("\udfff")
        self.assertEqual(caught.exception.code, CODE["UNPAIRED_SURROGATE"])

    def test_error_does_not_leak_codec_type(self):
        with self.assertRaises(MdCageError) as caught:
            sanitize_markdown("\ud800")
        self.assertNotIsInstance(caught.exception, UnicodeEncodeError)

    def test_audit_captures_hard_errors_as_critical_report(self):
        report = audit_markdown("abcd", max_bytes=3)
        self.assertFalse(report.safe)
        self.assertEqual(report.findings[0].severity, "critical")
        self.assertEqual(report.findings[0].code, CODE["MAX_BYTES"])


class PolicyTests(unittest.TestCase):
    def test_default_policy_values(self):
        self.assertFalse(DEFAULT_POLICY.allow_html)
        self.assertFalse(DEFAULT_POLICY.allow_external_images)
        self.assertFalse(DEFAULT_POLICY.allow_reference_definitions)
        self.assertTrue(DEFAULT_POLICY.allow_autolinks)

    def test_strict_preset_disallows_http(self):
        report = audit_markdown("[x](http://example.com)", preset="strict")
        self.assertFalse(report.safe)
        self.assertEqual(report.findings[0].code, CODE["DISALLOWED_SCHEME"])

    def test_agent_preset_allows_http_link(self):
        self.assertTrue(is_safe_markdown("[x](http://example.com)", preset="agent"))

    def test_docs_preset_allows_public_external_image(self):
        self.assertTrue(is_safe_markdown("![x](https://example.com/x.png)", preset="docs"))

    def test_preset_policy_objects_are_valid(self):
        for name in ("strict", "agent", "docs"):
            self.assertIsInstance(preset_policy(name), MdPolicy)

    def test_unknown_preset_raises(self):
        with self.assertRaises(MdCageError):
            normalize_policy(preset="unknown")

    def test_unknown_option_raises(self):
        with self.assertRaises(MdCageError):
            normalize_policy(does_not_exist=True)

    def test_dangerous_scheme_cannot_be_enabled(self):
        for scheme in ("javascript", "vbscript", "data", "file", "blob"):
            with self.subTest(scheme=scheme):
                with self.assertRaises(MdCageError):
                    MdPolicy(allowed_schemes=frozenset({scheme}))

    def test_bool_policy_fields_reject_non_bool(self):
        with self.assertRaises(MdCageError):
            MdPolicy(allow_html=1)

    def test_integer_policy_fields_reject_zero(self):
        with self.assertRaises(MdCageError):
            MdPolicy(max_bytes=0)

    def test_max_findings_may_be_zero(self):
        policy = MdPolicy(max_findings=0)
        self.assertEqual(policy.max_findings, 0)

    def test_policy_replace_returns_new_object(self):
        policy = MdPolicy()
        changed = policy.replace(max_bytes=100)
        self.assertEqual(changed.max_bytes, 100)
        self.assertNotEqual(policy.max_bytes, 100)

    def test_mapping_policy_is_accepted(self):
        result = sanitize_markdown("abcd", policy={"max_bytes": 4})
        self.assertEqual(result.markdown, "abcd")

    def test_policy_object_is_accepted(self):
        result = sanitize_markdown("abcd", policy=MdPolicy(max_bytes=4))
        self.assertEqual(result.markdown, "abcd")

    def test_policy_rejects_bad_type(self):
        with self.assertRaises(MdCageError):
            sanitize_markdown("x", policy=object())

    def test_image_host_validation_rejects_path(self):
        with self.assertRaises(MdCageError):
            MdPolicy(allowed_image_hosts=frozenset({"example.com/path"}))

    def test_image_host_validation_rejects_empty(self):
        with self.assertRaises(MdCageError):
            MdPolicy(allowed_image_hosts=frozenset({""}))


class ImmutabilityTests(unittest.TestCase):
    def test_policy_normal_assignment_is_frozen(self):
        policy = MdPolicy()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            policy.max_bytes = 1

    def test_policy_object_setattr_is_blocked(self):
        policy = MdPolicy()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            object.__setattr__(policy, "max_bytes", 1)
        self.assertNotEqual(policy.max_bytes, 1)

    def test_policy_hidden_backing_write_does_not_exist(self):
        policy = MdPolicy()
        object.__setattr__(policy, "_pymdcage_value_max_bytes", 1)
        self.assertNotEqual(policy.max_bytes, 1)

    def test_policy_cannot_be_reinitialized(self):
        policy = MdPolicy()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            policy.__init__(max_bytes=1)

    def test_result_object_setattr_is_blocked(self):
        result = sanitize_markdown("x")
        with self.assertRaises(dataclasses.FrozenInstanceError):
            object.__setattr__(result, "markdown", "bad")
        self.assertEqual(result.markdown, "x")

    def test_report_object_setattr_is_blocked(self):
        report = audit_markdown("x")
        with self.assertRaises(dataclasses.FrozenInstanceError):
            object.__setattr__(report, "safe", False)
        self.assertTrue(report.safe)

    def test_link_object_setattr_is_blocked(self):
        link = extract_links("[x](y)")[0]
        with self.assertRaises(dataclasses.FrozenInstanceError):
            object.__setattr__(link, "url", "javascript:alert(1)")
        self.assertEqual(link.url, "y")

    def test_finding_details_are_immutable(self):
        finding = sanitize_markdown("<!--x-->").findings[0]
        with self.assertRaises(TypeError):
            finding.details["x"] = 1

    def test_result_tuples_are_immutable(self):
        result = sanitize_markdown("<!--x-->")
        self.assertIsInstance(result.findings, tuple)
        with self.assertRaises(AttributeError):
            result.findings.append("x")


class IdempotenceTests(unittest.TestCase):
    def test_dangerous_inline_idempotence(self):
        first = sanitize_markdown("[x](javascript:alert(1))").markdown
        self.assertEqual(sanitize_markdown(first).markdown, first)

    def test_safe_inline_idempotence(self):
        first = sanitize_markdown("[x](https://example.com)").markdown
        self.assertEqual(sanitize_markdown(first).markdown, first)

    def test_image_idempotence(self):
        first = sanitize_markdown("![x](https://example.com/x.png)").markdown
        self.assertEqual(sanitize_markdown(first).markdown, first)

    def test_html_idempotence(self):
        first = sanitize_markdown("<script>alert(1)</script>").markdown
        self.assertEqual(sanitize_markdown(first).markdown, first)

    def test_unicode_idempotence(self):
        first = sanitize_markdown("a\u200bb").markdown
        self.assertEqual(sanitize_markdown(first).markdown, first)

    def test_reference_unfolding_idempotence(self):
        source = "[x][r]\n\n[r]: https://example.com\n"
        first = sanitize_markdown(source).markdown
        self.assertEqual(sanitize_markdown(first).markdown, first)

    def test_reference_preserving_idempotence_docs(self):
        source = "[x][r]\n\n[r]: https://example.com\n"
        first = sanitize_markdown(source, preset="docs").markdown
        self.assertEqual(sanitize_markdown(first, preset="docs").markdown, first)

    def test_malformed_link_idempotence(self):
        first = sanitize_markdown("[x](not a link)").markdown
        self.assertEqual(sanitize_markdown(first).markdown, first)

    def test_autolink_idempotence(self):
        first = sanitize_markdown("<javascript:alert(1)>").markdown
        self.assertEqual(sanitize_markdown(first).markdown, first)

    def test_empty_input_idempotence(self):
        first = sanitize_markdown("").markdown
        self.assertEqual(first, "")
        self.assertEqual(sanitize_markdown(first).markdown, first)


if __name__ == "__main__":
    unittest.main()
