# Contributing

## Development rules

- Python 3.9 through 3.13 are supported.
- Runtime code must use only the Python standard library.
- Keep the scanner iterative and linear. Do not add recursive descent or polynomial regular expressions.
- Preserve typed `PYMDCAGE_*` error codes in public failures.
- Add tests for every security regression and every parsing change.
- Do not commit bytecode caches, build output, secrets, local paths, or personal data.

## Local verification

```sh
PYTHONPATH=src python3 -m unittest discover -s tests
python3 -m build
python3 scripts/check_dist.py dist
```

The repository test suite also checks packaging hygiene, distribution contents, Unicode dash hygiene, and the absence of runtime dependencies.

## Security changes

A security change must include:

1. a minimized malicious or adversarial input,
2. the expected output or finding code,
3. a regression test,
4. an explanation of whether the issue affects source scanning, rendered Markdown, agent prompt handling, or image URL fetching policy.
