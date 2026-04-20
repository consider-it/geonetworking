# C-ITS GeoNetworking Parser

Rust tools for encoding and decoding GeoNetworking packets according to EN 302 636-4-1 v1.3.1.
Supports `#[no_std]`.

## Usage

### Installation
Add `geonetworking = "$version"` to the `[dependencies]` section of your project's `Cargo.toml` manifest.
The default features include data validation functionalities and JSON serialization with `serde`.
If you do not wish to include validation and JSON functionalities in your build, declare the dependency as follows: `geonetworking = { version = "$version", default-features = false }`.

### API and Examples
See [docs.rs](docs.rs/crate/geonetworking).
