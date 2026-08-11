# Contributing

Thank you for helping improve UNASKED. Issues, threat-model corrections, minimal
reproductions, and documentation feedback are welcome.

## Before opening an issue

- Search existing issues and run `unasked --json doctor`.
- Remove credentials, private repository contents, benchmark cases, and sensitive paths.
- Use the private process in [`SECURITY.md`](SECURITY.md) for vulnerabilities.
- Keep milestone claims separate from software behavior. `NO_VERIFIED_DISCOVERY` is a valid
  result; the v0.2 series is non-certifying and does not demonstrate M0.

## Pull requests

External code contributions are not accepted while the repository remains source-visible
under reserved copyright. This avoids taking contribution rights without published
contributor terms. You may still open an issue proposing a change or attach a minimal
reproduction that you have permission to share. Maintainer-authored pull requests must use
the repository template and pass every required check.

If contribution and project licensing are changed later, that change will be explicit and
prospective; public visibility alone does not create a license grant.

## Maintainer development checks

Python 3.11 through 3.14, Git 2.45 or newer, and the pinned `uv` version used by CI are
required.

```powershell
uv sync --locked --extra dev --extra security
uv run ruff check .
uv run ruff format --check .
uv run bandit -q -r src scripts
uv export --locked --no-dev --no-emit-project --format requirements.txt --output-file .runtime-requirements.txt
uv run pip-audit -r .runtime-requirements.txt --progress-spinner off
uv run pytest
python scripts/verify_release.py
```

Do not edit `constitution/UNASKED_NORTH_STAR_v0.1.md`; the release verifier binds its exact
bytes. Changes to authority, protocol, schemas, replay, release workflows, security
boundaries, or public claims require focused regression tests and reviewer attention.
