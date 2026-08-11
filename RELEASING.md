# Releasing UNASKED

Software releases and research milestone claims are separate. A tag may publish a working
research harness; it cannot authorize an M0 claim.

For each software release:

1. update the version in `pyproject.toml` and `src/unasked/__init__.py`;
2. update `CHANGELOG.md` and add `.github/releases/<version>.md` with the current claim
   boundary and limitations;
3. run `uv lock`, then open a pull request and wait for every CI matrix job to pass;
4. merge to `main` and create an annotated `v<version>` tag on that exact merge commit;
5. push the tag; `.github/workflows/release.yml` rebuilds twice, compares artifact bytes,
   verifies the wheel and sdist, smoke-tests the wheel, writes `SHA256SUMS.txt`, and publishes
   the GitHub Release;
6. verify that the Release tag, target commit, artifacts, and checksums agree.

The release workflow refuses a tag whose version differs from package metadata or whose
commit is not on `main`. Public/open-source distribution also requires an intentional license
decision; the private v0.2.0 release does not infer one.
