"""Image exfiltration, tracking-pixel, host allowlist, and SSRF tests."""
from __future__ import annotations

import unittest

from helpers import add_generated_tests
from pymdcage import CODE, audit_markdown, sanitize_markdown

PRIVATE_IPV4_HOSTS = [
    "127.0.0.1", "127.1", "127.0.1", "127.0.0.1.", "2130706433", "0x7f000001",
    "0177.0.0.1", "0177.1", "0x7f.1", "0x7f.0.0.1", "%31%32%37.0.0.1",
    "10.0.0.1", "10.1", "10.255.255.255", "172.16.0.1", "172.31.255.255",
    "192.168.0.1", "192.168.255.255", "169.254.169.254", "169.254.1.1",
    "0.0.0.0", "255.255.255.255", "224.0.0.1", "239.255.255.255", "100.64.0.1",
]

PRIVATE_IPV6_HOSTS = [
    "[::1]", "[0:0:0:0:0:0:0:1]", "[::]", "[fc00::1]", "[fd00::1]", "[fe80::1]",
    "[ff02::1]", "[::ffff:127.0.0.1]", "[::ffff:7f00:1]", "[::ffff:169.254.169.254]",
]

PRIVATE_HOSTS = PRIVATE_IPV4_HOSTS + PRIVATE_IPV6_HOSTS + ["localhost", "localhost.", "metadata.google.internal"]


def _private_cases():
    for host in PRIVATE_HOSTS:
        yield host, "https://" + host + "/pixel.png"
        yield host, "//" + host + "/pixel.png"


class GeneratedPrivateImageTests(unittest.TestCase):
    pass


def _private_body(self, case):
    host, url = case
    source = "![leak](" + url + ")"
    result = sanitize_markdown(source, allow_external_images=True)
    self.assertFalse(audit_markdown(source, allow_external_images=True).safe, source)
    self.assertEqual(result.markdown, "leak", source)
    self.assertTrue(any(finding.code == CODE["PRIVATE_IMAGE_HOST"] for finding in result.findings), (source, [finding.code for finding in result.findings]))


add_generated_tests(GeneratedPrivateImageTests, "private_image_host", list(_private_cases()), _private_body)


EXTERNAL_IMAGE_CASES = [
    "https://example.com/pixel.png",
    "http://example.com/pixel.png",
    "//example.com/pixel.png",
    "https://example.com/leak?token=secret",
    "https://example.com:443/pixel.png",
    "https://user@example.com/pixel.png",
    "HTTPS://example.com/pixel.png",
    "https://example.com/pixel.png?width=1&height=1",
]


class GeneratedExternalImageTests(unittest.TestCase):
    pass


def _external_body(self, url):
    source = "![leak](" + url + ")"
    result = sanitize_markdown(source)
    self.assertFalse(audit_markdown(source).safe, url)
    self.assertEqual(result.markdown, "leak")
    self.assertTrue(any(finding.code == CODE["EXTERNAL_IMAGE"] for finding in result.findings), url)
    self.assertEqual(len(result.links), 1)
    self.assertFalse(result.links[0].safe)


add_generated_tests(GeneratedExternalImageTests, "external_image_blocked", EXTERNAL_IMAGE_CASES, _external_body)


class ImagePolicyTests(unittest.TestCase):
    def test_docs_preset_allows_public_image(self):
        source = "![logo](https://example.com/logo.png)"
        self.assertEqual(sanitize_markdown(source, preset="docs").markdown, source)

    def test_exact_allowed_image_host(self):
        source = "![logo](https://cdn.example.com/logo.png)"
        result = sanitize_markdown(source, allow_external_images=True, allowed_image_hosts={"cdn.example.com"})
        self.assertEqual(result.markdown, source)

    def test_disallowed_image_host(self):
        source = "![logo](https://evil.example.com/logo.png)"
        result = sanitize_markdown(source, allow_external_images=True, allowed_image_hosts={"cdn.example.com"})
        self.assertEqual(result.markdown, "logo")
        self.assertEqual(result.findings[0].code, CODE["DISALLOWED_IMAGE_HOST"])

    def test_wildcard_image_host_accepts_subdomain(self):
        source = "![logo](https://a.img.example.com/logo.png)"
        result = sanitize_markdown(source, allow_external_images=True, allowed_image_hosts={"*.img.example.com"})
        self.assertEqual(result.markdown, source)

    def test_wildcard_image_host_accepts_suffix_root(self):
        source = "![logo](https://img.example.com/logo.png)"
        result = sanitize_markdown(source, allow_external_images=True, allowed_image_hosts={"*.img.example.com"})
        self.assertEqual(result.markdown, source)

    def test_wildcard_image_host_rejects_lookalike(self):
        source = "![logo](https://evilimg.example.com/logo.png)"
        result = sanitize_markdown(source, allow_external_images=True, allowed_image_hosts={"*.img.example.com"})
        self.assertEqual(result.markdown, "logo")

    def test_private_host_wins_over_allowed_host_list(self):
        source = "![x](https://127.0.0.1/x.png)"
        result = sanitize_markdown(source, allow_external_images=True, allowed_image_hosts={"127.0.0.1"})
        self.assertEqual(result.markdown, "x")
        self.assertEqual(result.findings[0].code, CODE["PRIVATE_IMAGE_HOST"])

    def test_relative_image_is_allowed_by_default(self):
        source = "![diagram](images/diagram.png)"
        self.assertEqual(sanitize_markdown(source).markdown, source)

    def test_fragment_image_is_inert_and_allowed(self):
        source = "![diagram](#diagram)"
        self.assertEqual(sanitize_markdown(source).markdown, source)

    def test_dangerous_image_scheme_is_blocked(self):
        source = "![x](data:image/svg+xml;base64,xx)"
        result = sanitize_markdown(source, allow_external_images=True)
        self.assertEqual(result.markdown, "x")
        self.assertEqual(result.findings[0].code, CODE["DANGEROUS_SCHEME"])

    def test_reference_image_private_host_is_blocked(self):
        source = "![x][r]\n\n[r]: https://169.254.169.254/latest\n"
        result = sanitize_markdown(source, preset="docs")
        self.assertEqual(result.markdown, "x\n\n")
        self.assertTrue(any(finding.code == CODE["PRIVATE_IMAGE_HOST"] for finding in result.findings))

    def test_raw_html_img_private_host_is_blocked_when_html_allowed(self):
        source = "<img src=\"https://127.0.0.1/x.png\">"
        result = sanitize_markdown(source, allow_html=True, allow_external_images=True)
        self.assertEqual(result.markdown, "")
        self.assertTrue(any(finding.code == CODE["ACTIVE_HTML"] for finding in result.findings))


if __name__ == "__main__":
    unittest.main()
