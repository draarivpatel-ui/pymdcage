"""Custom policy example for pymdcage."""
from pymdcage import MdPolicy, sanitize_markdown

policy = MdPolicy(
    allow_external_images=True,
    allowed_image_hosts=frozenset({"cdn.example.com"}),
    max_bytes=100000,
    max_links=100,
)

source = "![logo](https://cdn.example.com/logo.png)"
result = sanitize_markdown(source, policy=policy)
print(result.markdown)

blocked = "![pixel](https://127.0.0.1/pixel.png)"
blocked_result = sanitize_markdown(blocked, policy=policy)
print(blocked_result.markdown)
print(blocked_result.findings[0].code if blocked_result.findings else "no finding")
