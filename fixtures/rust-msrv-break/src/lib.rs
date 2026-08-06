//! Uses `std::cell::LazyCell`, stabilized in Rust 1.80.
//! Baseline rustc >= 1.80 passes; rustc 1.74 fails to compile (MSRV/toolchain break).

use std::cell::LazyCell;

pub fn answer() -> i32 {
    static VAL: LazyCell<i32> = LazyCell::new(|| 42);
    *VAL
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn works() {
        assert_eq!(answer(), 42);
    }
}
