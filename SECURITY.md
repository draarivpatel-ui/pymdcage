# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.x | Yes |
| < 1.0 | No |

Security fixes land on the latest 1.x release. Upgrade before reporting an issue that only reproduces on an older release.

## Reporting a vulnerability

Report suspected vulnerabilities privately through [GitHub private vulnerability reporting](https://github.com/draarivpatel-ui/pymdcage/security/advisories/new). Do not open a public issue for an unpatched vulnerability.

Include:

- The affected pymdcage version or commit.
- The Python version and operating system.
- A minimal Markdown input and the policy or preset used.
- The expected security property and the observed result.
- A short assessment of impact and any preconditions.

Do not include real credentials, tokens, cookies, private keys, customer data or personal data in a report. Redact secrets before attaching logs.

## Acknowledgment and coordinated disclosure timeline

- We aim to acknowledge a vulnerability report within 3 business days.
- We aim to complete initial triage and severity assessment within 14 days.
- We aim to release a fix or documented mitigation within 90 days of confirming a vulnerability, sooner for high severity issues when practical.
- We coordinate public disclosure with the reporter. A public advisory is normally published after a fixed release is available or on a mutually agreed date.
- Credit is given in release notes and the advisory unless the reporter prefers otherwise.
- If a report is not accepted as a vulnerability, we will explain the reasoning before closing the advisory.

## Vulnerability handling process

1. Receive the private report through the GitHub security advisory.
2. Reproduce the issue, determine affected versions and assess severity.
3. Develop a fix with regression tests.
4. Publish the fixed state and prepare the advisory.
5. Publish coordinated disclosure notes with affected and fixed versions.

## Scope

In scope:

- Sanitization bypasses for dangerous Markdown links, raw HTML, SVG, event handlers or hidden reference definitions.
- Link auditor bypasses involving entities, percent escapes, control characters, mixed case, backslashes or angle destinations.
- Image URL bypasses that reach a blocked literal IP, loopback, private network, link local address or configured host policy.
- Hidden prompt-injection channels using invisible Unicode, comments, references, whitespace or nested encoding.
- Crashes, quadratic behavior or uncaught exceptions caused by hostile Markdown input.

Out of scope:

- Attacks that require a downstream renderer or network client to ignore the sanitized output or audit result.
- DNS rebinding and server-side name resolution performed by another system. pymdcage does not fetch URLs.
- HTML renderer vulnerabilities outside the Markdown source-scanning boundary.
- Denial of service through input already allowed by the configured policy and documented limits.

## Security design notes

pymdcage is a source-scanning library. It does not render HTML, execute JavaScript, fetch URLs or evaluate prompt text. SSRF protection for images is based on URL structure, literal IP classification and configured host policy.
