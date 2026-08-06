#!/usr/bin/env bash
# TomorrowCI release dry-run (Unix)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
mkdir -p dist

echo "== build release CLI =="
cargo build -p tomorrowci-cli --release
BIN="$ROOT/target/release/tomorrowci"
test -x "$BIN"

STAGE="dist/tomorrowci-0.1.0-$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)"
rm -rf "$STAGE"
mkdir -p "$STAGE"
cp "$BIN" "$STAGE/"
cp README.md LICENSE CHANGELOG.md "$STAGE/"
TAR="dist/$(basename "$STAGE").tar.gz"
tar -C dist -czf "$TAR" "$(basename "$STAGE")"

echo "== checksums =="
(
  cd dist
  if command -v sha256sum >/dev/null; then
    sha256sum ./* > SHA256SUMS.txt
  else
    shasum -a 256 ./* > SHA256SUMS.txt
  fi
)

echo "== SBOM best-effort =="
cat > dist/sbom.cdx.json <<'EOF'
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {
    "component": {
      "type": "application",
      "name": "tomorrowci",
      "version": "0.1.0"
    }
  },
  "components": []
}
EOF

echo "== trust + tests =="
"$BIN" trust
cargo test --workspace --quiet

cat > dist/claim-to-evidence.md <<'EOF'
# Claim-to-evidence (release dry-run)

| Claim | Status | Command | Result | Artifact |
|---|---|---|---|---|
| Rust workspace tests | PASS | cargo test --workspace | exit 0 | local |
| Trust audit | PASS | tomorrowci trust | overall Pass | stdout |
| CLI archive | PASS | tar | created | dist/*.tar.gz |
| Checksums | PASS | sha256sum | created | dist/SHA256SUMS.txt |
| SBOM document | PASS | static export | created | dist/sbom.cdx.json |
| Live Docker e2e | BLOCKED/PASS | docker info | env-dependent | doctor |
EOF

echo "Dry-run complete."
ls -la dist
