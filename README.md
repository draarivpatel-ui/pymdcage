# pymdcage

`pymdcage` is a zero-dependency Python library for security-sensitive Markdown handling. It scans Markdown source with an iterative linear state machine, rewrites dangerous constructs into inert Markdown text, audits links and raw HTML, blocks image-based SSRF and tracking pixels, and strips invisible Unicode or hidden-reference prompt-injection channels.

The library does not render Markdown to HTML and it never fetches a URL. It is a source-layer security control intended to run before a renderer, before Markdown is stored, or before source text is shown to an AI agent.

## Threat model

`pymdcage` is designed for these attacks:

- `javascript:`, `vbscript:`, `data:`, `file:`, and `blob:` links hidden behind entities, percent escapes, backslashes, whitespace, mixed case, angle destinations, reference definitions, or autolinks.
- Raw HTML and SVG smuggling through tags such as `script`, `iframe`, `svg`, `math`, `style`, `form`, `object`, `embed`, `meta`, `link`, `base`, event-handler attributes, and dangerous URL-bearing attributes.
- External image beacons, tracking pixels, and literal-IP SSRF destinations such as `127.0.0.1`, `127.1`, decimal or hexadecimal IPv4 forms, `10.0.0.0/8`, `169.254.169.254`, `::1`, and IPv4-mapped IPv6 addresses.
- Hidden instructions in HTML comments, `[//]: # (...)` reference-comment tricks, and unused reference definitions.
- Unicode Tags block characters, zero-width characters, invisible formatting characters, bidirectional overrides and isolates, mid-document byte-order marks, and unpaired surrogates.
- Resource exhaustion through oversized input, oversized output, very long documents, excessive links, excessive reference definitions, deep nesting, or excessive findings.

## Important limits

- The scanner is conservative. A malformed construct that resembles a link is neutralized rather than reinterpreted as safe text.
- Inline code spans and fenced code blocks are preserved as literal code, except that invisible Unicode and control characters are stripped everywhere.
- The SSRF check inspects the literal URL host. It does not perform DNS resolution, so DNS rebinding and domain fronting are outside the library's zero-dependency model.
- Markdown dialects differ. The parser handles the common security-relevant forms documented here, but it is not a complete CommonMark renderer.
- Sanitized output is Markdown source. Downstream applications still need a safe renderer and appropriate browser defenses such as a content security policy.

## Installation

```sh
python3 -m pip install pymdcage
```

For local development use the source tree directly:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests
```

## Quick start

```python
from pymdcage import audit_markdown, sanitize_markdown

source = "[click](javascript:alert(1))\n\n<!-- hidden instructions -->\n"

result = sanitize_markdown(source)
print(result.markdown)   # click
print(result.changed)    # True

report = audit_markdown(source)
print(report.safe)       # False
for finding in report.findings:
    print(finding.code, finding.severity, finding.line, finding.column)
```

## Public API

### `sanitize_markdown(source, *, policy=None, preset=None, **options)`

Returns an immutable `MdSanitizeResult` with:

- `markdown`: rewritten Markdown source,
- `changed`: whether the bytes-visible Unicode text changed,
- `findings`: immutable finding objects,
- `stats`: parser and resource statistics,
- `links`: every link-like construct discovered, including unsafe links marked `safe=False`.

### `audit_markdown(source, *, policy=None, preset=None, **options)`

Returns an immutable `MdAuditReport`. `report.safe` is false when any high or critical finding exists, when a hard resource limit fails, or when findings are truncated by `max_findings`.

### `extract_links(source, *, policy=None, preset=None, **options)`

Returns a tuple of immutable `MdLink` objects. Unsafe destinations are returned with `safe=False` so an audit pipeline can record them without fetching them.

### `is_safe_markdown(...)`

Boolean convenience wrapper around `audit_markdown`.

### `validate_markdown(...)`

Returns a safe report or raises the first high-severity `MdCageError`.

## Presets

### `agent`

The default-oriented preset for AI-agent pipelines. Raw HTML and external images are disabled, safe reference links are unfolded, and autolinks are inspected.

### `strict`

The most restrictive built-in preset. It allows only `https:` and `mailto:` network schemes, disables autolinks, disables raw HTML, disables external images, and removes reference definitions.

### `docs`

A documentation-oriented preset. Safe used reference definitions are preserved and external images are allowed, subject to `allowed_image_hosts` and the always-on private-address block.

```python
from pymdcage import sanitize_markdown

result = sanitize_markdown(markdown_text, preset="strict")
```

## Custom policies

```python
from pymdcage import MdPolicy, sanitize_markdown

policy = MdPolicy(
    allow_external_images=True,
    allowed_image_hosts=frozenset({"cdn.example.com", "*.img.example.com"}),
    max_bytes=200_000,
    max_output_bytes=250_000,
    max_links=100,
)

result = sanitize_markdown(markdown_text, policy=policy)
```

Policy fields:

| Field | Default | Meaning |
| --- | --- | --- |
| `allowed_schemes` | `http`, `https`, `mailto` | Network schemes permitted for links |
| `allow_html` | `False` | Preserve inert raw HTML tags when true; active HTML is still removed |
| `allow_external_images` | `False` | Permit public external Markdown images |
| `allowed_image_hosts` | empty | Optional exact host or `*.suffix` allowlist for external images |
| `allow_reference_definitions` | `False` | Preserve safe used reference definitions instead of unfolding or removing them |
| `allow_autolinks` | `True` | Permit safe angle-bracket autolinks |
| `max_bytes` | `1048576` | Maximum encoded input bytes |
| `max_output_bytes` | `1048576` | Maximum encoded output bytes |
| `max_lines` | `20000` | Maximum input lines |
| `max_links` | `2000` | Maximum extracted link-like constructs |
| `max_reference_defs` | `500` | Maximum reference definitions |
| `max_nesting_depth` | `32` | Maximum bracket and destination nesting |
| `max_findings` | `1024` | Maximum retained findings before fail-closed truncation |

Dangerous schemes cannot be enabled by a custom policy. Private, loopback, link-local, multicast, unspecified, reserved, and otherwise non-public literal IP image hosts are always blocked even when external images are enabled.

## Rewrite behavior

- Safe inline links, reference links, images, code spans, and fenced code blocks are preserved exactly.
- Dangerous links are reduced to inert escaped label text.
- Dangerous or disallowed images are reduced to inert escaped alt text.
- Raw HTML tags and HTML comments are removed when raw HTML is disabled.
- Active HTML is removed even when `allow_html=True`.
- Safe reference links are unfolded when reference definitions are disabled, so the visible link behavior does not depend on hidden metadata.
- Hidden Unicode and control characters are removed before link scanning.

Sanitization is idempotent:

```python
first = sanitize_markdown(source).markdown
assert sanitize_markdown(first).markdown == first
```

## CLI

```sh
pymdcage audit README.md
pymdcage audit README.md --json --preset strict
pymdcage sanitize README.md --out clean.md
pymdcage extract-links README.md --json
cat README.md | pymdcage audit - --max-bytes 200000
```

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | Input is safe under the selected policy |
| `1` | Input is unsafe, malformed at a hard limit, or a security finding exists |
| `2` | CLI usage, input-file, or output-file error |

Terminal diagnostics neutralize C0, C1, newline, and bidirectional control characters so hostile file content cannot control the terminal through error output.

## Error codes

Public failures use stable `PYMDCAGE_*` codes on `MdCageError.code`. Findings use the same code namespace. Examples include `PYMDCAGE_DANGEROUS_SCHEME`, `PYMDCAGE_PRIVATE_IMAGE_HOST`, `PYMDCAGE_HTML_COMMENT`, `PYMDCAGE_UNICODE_TAGS`, `PYMDCAGE_BIDI_CONTROL`, `PYMDCAGE_MAX_BYTES`, and `PYMDCAGE_MAX_FINDINGS`.

## Development verification

```sh
PYTHONPATH=src python3 -m unittest discover -s tests
python3 -m build
python3 scripts/check_dist.py dist
```

The distribution check verifies that the wheel contains `pymdcage/py.typed`, contains no tests or bytecode, declares no runtime dependencies, and that the source distribution includes the test suite without bytecode.
