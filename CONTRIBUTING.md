# Contributing to ScopeX

Thank you for your interest in contributing to ScopeX! This document covers everything you need to get started.

## Table of Contents

- [Development Setup](#development-setup)
- [Running Tests](#running-tests)
- [Code Quality](#code-quality)
- [Pull Request Process](#pull-request-process)
- [Adding a New Scanner](#adding-a-new-scanner)
- [Adding a New Plugin](#adding-a-new-plugin)
- [Commit Message Guidelines](#commit-message-guidelines)

---

## Development Setup

`ash
# 1. Fork and clone the repository
git clone https://github.com/YOUR_USERNAME/scopex.git
cd scopex

# 2. Create and activate a virtual environment
python -m venv venv
# Linux/macOS:
source venv/bin/activate
# Windows:
venv\Scripts\activate

# 3. Install in editable mode with all dev dependencies
pip install -e .[dev]

# 4. (Optional) Install Nmap for port scanning tests
# Ubuntu/Debian: sudo apt-get install nmap
# macOS:         brew install nmap
# Windows:       choco install nmap
`

---

## Running Tests

`ash
# Full test suite with coverage
python -m pytest tests/ -v --cov=core --cov=scanners --cov=plugins --cov=reports --cov=utils

# Run a specific test file
python -m pytest tests/test_helpers.py -v

# Run only fast unit tests (skip integration)
python -m pytest tests/ -v -m "not integration"
`

Tests live in 	ests/. Each new scanner or plugin should have a corresponding 	est_<module>.py.

---

## Code Quality

Before submitting a PR, run:

`ash
# Lint and auto-fix with ruff
ruff check . --fix
ruff format .

# Type checking
mypy core/ utils/ --ignore-missing-imports

# Dependency vulnerability audit
pip-audit
`

All of these are automatically run in CI on every push/PR.

---

## Pull Request Process

1. **Branch from dev** — not from main. main is the stable release branch.
2. **One concern per PR** — keep PRs focused. Bug fix, new scanner, or refactor — not all three.
3. **Add/update tests** — PRs without tests for new functionality will not be merged.
4. **Update documentation** — if you change CLI flags or module behaviour, update README.md.
5. **Run the full test suite** before opening the PR and confirm it passes.
6. **Fill out the PR template** — it guides you through the checklist.

---

## Adding a New Scanner

1. Create scanners/my_scanner.py inheriting from scanners.base_scanner.BaseScanner.
2. Implement sync def scan(self) -> List[Finding].
3. Register it in core/orchestrator.py by adding an entry to _SCANNER_REGISTRY:
   `python
   "my_scanner": ("scanners.my_scanner", "MyScanner"),
   `
4. Add a CLI flag to scopex.py (or use --modules my_scanner — no flag needed).
5. Add tests in 	ests/test_my_scanner.py.

---

## Adding a New Plugin

1. Create plugins/my_plugin.py inheriting from plugins.base_plugin.BasePlugin.
2. Set PLUGIN_SHORT_KEY = "my_plugin" — this is the key used with --modules plugin:my_plugin.
3. Implement def run(self, progress_callback=None) -> dict.
4. The plugin loader (plugins/__init__.py) auto-discovers all BasePlugin subclasses — no registration required.
5. Add tests in 	ests/test_my_plugin.py.

---

## Commit Message Guidelines

Use [Conventional Commits](https://www.conventionalcommits.org/):

`
feat(scanner): add GraphQL introspection scanner
fix(nuclei): wire CVE-skip logic to -exclude-id args
docs(readme): update scanner count to 16
test(compliance): add CIS Controls v8 mapping tests
refactor(orchestrator): replace scanner registry with decorator pattern
`

Allowed types: eat, ix, docs, 	est, efactor, chore, ci, perf.

---

## Security Reporting

**Do not file a public issue for security vulnerabilities.**

Please disclose responsibly by emailing the maintainer directly. See [SECURITY.md](./SECURITY.md) if present, or reach out via the GitHub profile linked in [README.md](./README.md).
