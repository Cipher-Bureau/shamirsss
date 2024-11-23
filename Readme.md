# Shamir's secret sharing algorithm implementation in Rust programming language.

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

### Crate secret shares 

 ```Rust
use shamir_secret_sharing::{create_std};

const SECRET_512_BYTES: &[u8; 512] = &[
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 112, 99, 131, 144, 100, 100, 93, 129, 160,
    99, 153, 151, 145, 114, 122, 123, 127, 148, 120, 98, 137, 175, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 243, 25, 64, 173, 202, 96, 116,
    133, 114, 12, 186, 37, 43, 2, 70, 194, 52, 40, 80, 160, 233, 205, 0, 0, 0, 0, 0, 0, 0, 0, 29,
    136, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 112, 99, 131, 144, 100, 100, 93, 129,
    160, 99, 153, 151, 145, 114, 122, 123, 127, 148, 120, 98, 137, 175, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 243, 25, 64, 173, 202, 96,
    116, 133, 114, 12, 186, 37, 43, 2, 70, 194, 52, 40, 80, 160, 233, 205, 0, 0, 0, 0, 0, 0, 0, 0,
    29, 136, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 112, 99, 131, 144, 100, 100, 93,
    129, 160, 99, 153, 151, 145, 114, 122, 123, 127, 148, 120, 98, 137, 175, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 243, 25, 64, 173,
    202, 96, 116, 133, 114, 12, 186, 37, 43, 2, 70, 194, 52, 40, 80, 160, 233, 205, 0, 0, 0, 0, 0,
    0, 0, 0, 29, 136, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 112, 99, 131, 144, 100,
    100, 93, 129, 160, 99, 153, 151, 145, 114, 122, 123, 127, 148, 120, 98, 137, 175, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 243, 25,
    64, 173, 202, 96, 116, 133, 114, 12, 186, 37, 43, 2, 70, 194, 52, 40, 80, 160, 233, 205, 0, 0,
    0, 0, 0, 0, 0, 0, 29, 136,
];

let _secret_shares: Vec<Vec<u8>> = create_std(50, 100, SECRET_512_BYTES).unwrap();
```

### Reconstruct secret shares 


```Rust
use shamir_secret_sharing::{create_std, combine_std};

const SECRET_512_BYTES: &[u8; 512] = &[
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 112, 99, 131, 144, 100, 100, 93, 129, 160,
    99, 153, 151, 145, 114, 122, 123, 127, 148, 120, 98, 137, 175, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 243, 25, 64, 173, 202, 96, 116,
    133, 114, 12, 186, 37, 43, 2, 70, 194, 52, 40, 80, 160, 233, 205, 0, 0, 0, 0, 0, 0, 0, 0, 29,
    136, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 112, 99, 131, 144, 100, 100, 93, 129,
    160, 99, 153, 151, 145, 114, 122, 123, 127, 148, 120, 98, 137, 175, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 243, 25, 64, 173, 202, 96,
    116, 133, 114, 12, 186, 37, 43, 2, 70, 194, 52, 40, 80, 160, 233, 205, 0, 0, 0, 0, 0, 0, 0, 0,
    29, 136, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 112, 99, 131, 144, 100, 100, 93,
    129, 160, 99, 153, 151, 145, 114, 122, 123, 127, 148, 120, 98, 137, 175, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 243, 25, 64, 173,
    202, 96, 116, 133, 114, 12, 186, 37, 43, 2, 70, 194, 52, 40, 80, 160, 233, 205, 0, 0, 0, 0, 0,
    0, 0, 0, 29, 136, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 112, 99, 131, 144, 100,
    100, 93, 129, 160, 99, 153, 151, 145, 114, 122, 123, 127, 148, 120, 98, 137, 175, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 243, 25,
    64, 173, 202, 96, 116, 133, 114, 12, 186, 37, 43, 2, 70, 194, 52, 40, 80, 160, 233, 205, 0, 0,
    0, 0, 0, 0, 0, 0, 29, 136,
];

let secret_shares: Vec<Vec<u8>> = create_std(50, 100, SECRET_512_BYTES).unwrap();
let secret_recreated = combine_std(secret_shares).unwrap();
assert_eq!(SECRET_512_BYTES.to_vec(), secret_recreated);
```


