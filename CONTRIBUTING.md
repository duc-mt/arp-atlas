# Contributing to arp-atlas

Thank you for your interest in contributing!

## Development Setup

1. Fork the repository and clone it locally.
2. Create a virtual environment: `python3 -m venv .venv`
3. Activate the environment: `source .venv/bin/activate`
4. Install dependencies: `pip install -r requirements-dev.txt`
5. Install pre-commit hooks: `pre-commit install`

## Workflow

1. Create a branch for your feature or bug fix.
2. Make your changes.
3. Ensure all tests and static analysis pass by running:
   ```bash
   pytest
   ruff check .
   mypy .
   ```
4. Commit your changes (we recommend using Conventional Commits).
5. Open a Pull Request.

## Coding Standards
- We use **Ruff** for linting and formatting.
- We use **Mypy** for static type checking. All new code must be fully typed.
- All new features and bug fixes must include tests.
