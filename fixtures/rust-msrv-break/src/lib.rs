//! Fixture: baseline stable passes; beta/nightly fail `tests/toolchain_gate.rs`.

#[cfg(test)]
mod tests {
    #[test]
    fn always_passes_on_stable_baseline() {
        assert_eq!(2 + 2, 4);
    }
}
