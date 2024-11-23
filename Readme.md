# Experimental Shamir's secret sharing algorithm implementation in Rust programming language.

## Disclaimer

This is **experimental** implementation of Shamir Secret Sharing algorithm. 
This crate uses cryptographically safe libraries and dependencies and authors payed attention to make it secure.
But it is not extensively tested for cybersecurity usage and it is recommended to **not use this crate** in cybersecurity projects or
cryptographically secured applications. The subject of this crate is purely experimental.


## The theory:

Shamir's secret sharing (SSS) is an efficient secret sharing algorithm for distributing private information (the "secret") among a group. The secret cannot be revealed unless a quorum of the group acts together to pool their knowledge.

 - [Shamir's secret sharing wiki](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing)

 - [Shamir's secret sharing visualized](https://evervault.com/blog/shamir-secret-sharing)

## Technology

This algorithm is implemented in [Rust](https://www.rust-lang.org/) 2021 edition.

### Dependencies

- Random number generator is using vendored [Openssl library v111](https://openssl-library.org/news/openssl-1.1.1-notes/index.html).
- Bignum calculations are using BigNum from vendored [Openssl library v111](https://openssl-library.org/news/openssl-1.1.1-notes/index.html).
- Base64 encoding uses [base64](https://docs.rs/base64/latest/base64/) crate.
- Hex encoding uses [hex](https://docs.rs/hex/latest/hex/) crate.
- Errors are in format of [Thiserror](https://docs.rs/thiserror/latest/thiserror/) crate.
- Default prime number used for mod operations is: 115792089237316195423570985008687907853269984665640564039457584007913129639747

## Usage:

### Unit tests

To run unit test run in terminal:
 
```sh
cargo t --release -- --test-threads=1
```

### Benchmarks

To run benchmarks of library exposed functions run in terminal:
 
```sh
cargo bench
```

Macbook M2 (ARM64) processor:

- To create 100 shares with 50 minimum shares threshold of 512 bytes long key takes 25 [ ms ].
- To recreate 512 bytes long key from 100 shares with min 50 shares threshold takes 140 [ ms ].

### Docs

To generate crate documentation run in terminal:
 
```sh
cargo doc
```

