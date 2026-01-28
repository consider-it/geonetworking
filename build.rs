#[cfg(feature = "validate")]
use std::env;

fn main() {
    #[cfg(feature = "validate")]
    if let Ok(v) = env::var("DEP_OPENSSL_VERSION_NUMBER") {
        let version = u64::from_str_radix(&v, 16).unwrap();

        assert!(version >= 0x3000_0000, "This crate supports openssl >= 3 only!");
    }
}
