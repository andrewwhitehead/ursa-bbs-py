# ursa-bbs-py

## Build Instructions

Currently requires Rust nightly (`rustup toolchain install nightly`).

```sh
cargo build
cp target/debug/{libursa_bbs.dylib,libursa_bbs.so,ursa_bbs.dll} ursa_bbs.so
python test.py
```
