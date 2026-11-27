"""Basic pymdcage usage example."""
from pymdcage import audit_markdown, extract_links, sanitize_markdown

source = """# Example

[safe](https://example.com/docs)
[dangerous](javascript:alert(1))
![tracker](https://example.com/pixel.png)
"""

result = sanitize_markdown(source)
print(result.markdown)
print("changed:", result.changed)

report = audit_markdown(source)
print("safe:", report.safe)
for finding in report.findings:
    print(finding.severity, finding.code, finding.message)

for link in extract_links(source):
    print(link.kind, link.url, "safe=" + str(link.safe))
