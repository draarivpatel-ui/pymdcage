# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.0.x | Yes |

## Reporting a vulnerability

Please report suspected vulnerabilities through a private GitHub Security Advisory for this repository. Do not open a public issue for a reproducer that can be used against downstream applications before a fix is available.

Include:

- the pymdcage version and Python version,
- a minimal Markdown input,
- the policy or preset used,
- the expected security property,
- the actual result, including findings or sanitized output.

pymdcage is a source-scanning library. It does not fetch URLs, render HTML, execute JavaScript, or evaluate prompt text. SSRF protection for images is therefore based on URL structure, literal IP classification, and configured host policy. It cannot prevent DNS rebinding or attacks that depend on server-side name resolution performed by another system.
