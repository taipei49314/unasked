## Summary

Describe the outcome and why the change is needed.

## Evidence

- [ ] Tests cover the changed behavior and fail closed where integrity or authority is involved.
- [ ] `uv run ruff check .` and `uv run ruff format --check .` pass.
- [ ] `uv run pytest` passes.
- [ ] Security and release checks were run when their inputs changed.
- [ ] The exact-byte North Star charter was not modified.
- [ ] The change does not claim M0 or treat model output as evidence.

## Security and claim impact

List changed trust boundaries, executable/network/filesystem access, schemas, evidence
bindings, release behavior, and public claims. Write `None` only after checking each area.
