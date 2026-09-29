## Description
Briefly describe the change and why it is needed.

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## Checklist
- [ ] Unit tests added / updated covering 100% of new code and branches
- [ ] `uv run pytest --cov=didit --cov-report=term-missing` passes with 100% coverage
- [ ] `uv run ruff check .` and `uv run ruff format --check .` pass
- [ ] `uv run mypy src/didit` passes with 0 errors
- [ ] Updated `README.md` or docstrings if relevant
