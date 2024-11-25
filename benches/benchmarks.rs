use criterion::{criterion_group, criterion_main, Criterion};
use openssl::rand::rand_bytes;
use shamirss::{combine_inlined, create_inlined, errors::SSSError};

fn get_random_bytes(size: usize) -> Result<Vec<u8>, SSSError> {
    let mut bytes = vec![0; size];
    rand_bytes(&mut bytes)?;
    Ok(bytes)
}

fn benchmark_create_inlined_min_50_shares_100_secret_512(c: &mut Criterion) {
    for option in &[
        (10, 20, 128),
        (20, 30, 128),
        (40, 60, 128),
        (10, 20, 256),
        (20, 30, 256),
        (40, 60, 256),
        (10, 20, 512),
        (20, 30, 512),
        (40, 60, 512),
    ] {
        c.bench_function(
            &format!(
                "benchmark_create_inlined_min_{}_shares_{}_secret_{}",
                option.0, option.1, option.2
            ),
            |b| {
                let secret = get_random_bytes(option.2).unwrap();
                b.iter(|| {
                    let _ = create_inlined(option.0, option.1, &secret);
                });
            },
        );
    }
}

fn benchmark_combine_all_inlined_min_50_shares_100_secret_512(c: &mut Criterion) {
    for option in &[
        (10, 20, 128),
        (20, 30, 128),
        (40, 60, 128),
        (10, 20, 256),
        (20, 30, 256),
        (40, 60, 256),
        (10, 20, 512),
        (20, 30, 512),
        (40, 60, 512),
    ] {
        c.bench_function(
            &format!(
                "benchmark_combine_all_inlined__min_{}_shares_{}_secret_{}",
                option.0, option.1, option.2
            ),
            |b| {
                let secret = get_random_bytes(option.2).unwrap();
                let shares = create_inlined(option.0, option.1, &secret).unwrap();
                b.iter(|| {
                    let _ = combine_inlined(shares.clone());
                });
            },
        );
    }
}

criterion_group!(
    benches,
    benchmark_create_inlined_min_50_shares_100_secret_512,
    benchmark_combine_all_inlined_min_50_shares_100_secret_512,
);
criterion_main!(benches);
