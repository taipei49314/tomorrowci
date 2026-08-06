# Release and support

## Versioning

Semantic versioning. Tag format: `vMAJOR.MINOR.PATCH`.

## Dry run (local)

```bash
# Unix
./scripts/release-dry-run.sh

# Windows PowerShell
./scripts/release-dry-run.ps1
```

Produces under `dist/`:

- CLI archives per target (as available on the host)
- `SHA256SUMS.txt`
- `sbom.cdx.json` (best-effort via `cargo metadata` / cyclonedx if installed)
- `claim-to-evidence.md` snapshot

## GitHub Release workflow

`.github/workflows/release.yml` triggers on `v*` tags:

1. Build Linux/macOS/Windows release binaries
2. Checksums
3. SBOM artifact
4. Upload to GitHub Release
5. Optional container image publish (when `DOCKERHUB` secrets configured)

If any required artifact is missing, the release job fails.

## Provenance

v0.1 documents the path toward signed provenance (SLSA):

- Build on GitHub Actions with pinned toolchains
- Emit checksums for all archives
- Future: cosign keyless signing for container images

v0.1 does **not** claim full SLSA Level 3.
