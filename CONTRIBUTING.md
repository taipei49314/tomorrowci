# Contributing

1. Read the mission Definition of Done and disqualification conditions.
2. Prefer a complete vertical slice over placeholder modules.
3. Never run untrusted target code on the host by default.
4. Never convert `BLOCKED` / `UNSUPPORTED` / `INCONCLUSIVE` into `PASS`.
5. Mark skipped infrastructure tests as `BLOCKED`, not silent success.

```bash
cargo test --workspace
cargo build -p tomorrowci-cli --release
./target/release/tomorrowci doctor
```
