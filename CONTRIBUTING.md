# Contributing to didit-sdk

Thank you for your interest in contributing to `didit-sdk`!

## Development Setup

We use [`uv`](https://docs.astral.sh/uv/) for Python packaging and dependency management.

```bash
# Clone the repository
git clone https://github.com/agustin18/didit-sdk.git
cd didit-sdk

# Create virtual environment and install development dependencies
uv sync --extra dev
```

## Quality Standards

All pull requests must pass the following quality gates:

1. **Testing & Coverage**:
   - 100% statement and branch coverage is strictly enforced.
   - Run tests:
     ```bash
     uv run pytest --cov=didit --cov-report=term-missing
     ```

2. **Code Style & Formatting**:
   - Code must adhere to Ruff linting and formatting standards:
     ```bash
     uv run ruff check .
     uv run ruff format --check .
     ```

3. **Strict Type Checking**:
   - Mypy must pass in strict mode:
     ```bash
     uv run mypy src/didit
     ```

## Pull Request Guidelines

- Follow conventional commits (`feat: ...`, `fix: ...`, `docs: ...`, `test: ...`).
- Include tests for any new features or bug fixes.
- Update `README.md` and docstrings when public APIs change.
