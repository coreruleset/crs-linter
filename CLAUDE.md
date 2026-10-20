# CLAUDE.md

## Commands

- Unit tests: `uv run pytest -vs`
- Lint rules live in `src/crs_linter/rules/`. After changing one, regenerate the rules section of `README.md` with `uv run python generate_rules_docs.py`; `python generate_rules_docs.py --check` reports whether it is current.
