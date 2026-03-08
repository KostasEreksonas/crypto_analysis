# crypto_analysis
A (vibe-)coded Rust tool to scan Linux binaries and libraries for cryptographic signatures

Table of Contents
=================
* [Usage](#usage)

# Usage

```
cd crypto_analysis

cargo build --release

./target/release/crypto_analysis --json results.json -j "$(nproc)" -o results.txt
```
