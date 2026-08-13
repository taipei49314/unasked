# Releasing UNASKED

Software releases and research milestone claims are separate. A tag may publish a working
research harness; it cannot authorize an M0 claim.

For each software release:

1. update the version in `pyproject.toml` and `src/unasked/__init__.py`;
2. update `CHANGELOG.md` and add `.github/releases/<version>.md` with the current claim
   boundary and limitations;
3. confirm public examples use only SHADOW trust policies and that no private key, signing
   seed, hidden case, ground truth, sealed manifest, or production credential is present;
4. run `uv lock`, then open a pull request and wait for every CI matrix job to pass;
5. merge to `main` and create an annotated `v<version>` tag on that exact merge commit;
6. push the tag; `.github/workflows/release.yml` rebuilds twice, compares artifact bytes,
   verifies the wheel and sdist, smoke-tests the wheel, writes `SHA256SUMS.txt`, and publishes
   the GitHub Release;
7. verify that the Release tag, target commit, artifacts, checksums, wheel smoke output, and
   claim-neutral release title agree.

The release workflow refuses a tag whose version differs from package metadata or whose
commit is not on `main`. Public visibility and open-source licensing are separate decisions.
The current source-visible distribution reserves all rights under `LICENSE`; changing that
license requires an explicit owner decision and a separately reviewed pull request.

The source and distribution verifier also requires the matching release note and scans public
resources and wheel members for private-key encodings and hidden-evaluation payload names.
Test-only in-memory keys are allowed under `tests/`, which is never included in the wheel;
serialized private keys and sealed benchmark data are forbidden in every published artifact.
