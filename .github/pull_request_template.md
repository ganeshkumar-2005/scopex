## Description

<!-- Briefly describe the change and the motivation behind it. Link to the related issue. -->

Fixes #___

## Type of Change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to change)
- [ ] Documentation update
- [ ] Refactoring / code quality improvement
- [ ] CI / tooling change

## Checklist

- [ ] I have read [CONTRIBUTING.md](../CONTRIBUTING.md)
- [ ] My branch is based on dev (not main)
- [ ] The full test suite passes locally (python -m pytest tests/ -v)
- [ ] I have added tests that cover my changes
- [ ] uff check . --fix && ruff format . passes with no errors
- [ ] I have updated README.md / docstrings where relevant
- [ ] New CLI flags (if any) are documented in README.md under the CLI Reference section
- [ ] No hardcoded credentials, mock data, or debug-only code is included

## Testing Evidence

<!-- Paste relevant pytest output or a brief description of how you tested this. -->

`
pytest tests/ -v
`

## Screenshots / Recordings (if UI/output change)

<!-- Attach if the terminal output or report format changed visibly. -->
