# Guide for developers

This project uses the `uv` tool to manage dependencies and virtual environments. See [here](https://docs.astral.sh/uv/) for more details.

You can install all dependencies using `uv sync --all-extras --dev`.

## Testing

- Add tests in the `tests/` directory.
- Run tests with `uv run pytest -vs`.
- Add as many fixtures as you want in `tests/conftest.py`.

