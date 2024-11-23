use crate::{
    errors::SSSError,
    operations::{
        big_nums_to_bytes, bytes_to_big_nums, evaluate, random, DEFAULT_PRIME,
        U8S_TO_BIG_INT_INITIAL,
    },
};
use openssl::bn::{BigNum, BigNumContext};
const COEFFICIENTS_PER_SHARE: usize = 2;
const COEFFICIENTS_SIZE: usize = COEFFICIENTS_PER_SHARE * U8S_TO_BIG_INT_INITIAL;

/// Crates shares from given secret.
/// Function uses openssl library for cryptographically secure pseudo-random number generation and
/// BigNum from openssl big num package to calculate coefficients up to 64 bytes in size.
///
#[inline(always)]
pub(crate) fn create_shares(
    min: usize,
    shares: usize,
    secret: &[u8],
) -> Result<Vec<Vec<u8>>, SSSError> {
    if min > shares {
        return Err(SSSError::WithReason(
            "Minimum value cannot be bigger then total shares.".to_owned(),
        ));
    }

    let mut ctx = BigNumContext::new()?;
    let prime = BigNum::from_dec_str(DEFAULT_PRIME)?;

    let secret = bytes_to_big_nums(secret)?;
    let mut polynomial: Vec<Vec<BigNum>> = Vec::with_capacity(secret.len());
    for part in secret.iter() {
        let mut coefficients = Vec::with_capacity(min - 1);
        let temp = BigNum::from_slice(&part.to_vec())?;
        coefficients.push(temp);
        for _ in 1..min {
            coefficients.push(random(&prime)?);
        }
        polynomial.push(coefficients);
    }

    let mut results: Vec<Vec<u8>> = Vec::with_capacity(shares);

    for _ in 0..shares {
        let mut bytes: Vec<u8> = Vec::with_capacity(secret.len() * COEFFICIENTS_SIZE);
        let mut counter = 0;
        while counter < secret.len() {
            let coefficient_x = random(&prime)?;

            let coefficient_y = evaluate(&mut ctx, &polynomial[counter], &coefficient_x, &prime)?;
            let coefficients: &[BigNum; 2] = &[coefficient_x, coefficient_y];
            bytes.extend(big_nums_to_bytes(coefficients));
            counter += 1;
        }
        results.push(bytes);
    }

    Ok(results)
}

/// Recreates secret from given shares.
/// If number of shares is to small the secret calculated from them will not be correct.
/// Function uses openssl library for cryptographically secure pseudo-random number generation and
/// BigNum from openssl big num package to calculate coefficients up to 64 bytes in size.
///
#[inline(always)]
pub(crate) fn combine_shares(shares: Vec<Vec<u8>>) -> Result<Vec<u8>, SSSError> {
    let mut ctx = BigNumContext::new()?;
    let negative_one = BigNum::from_dec_str("-1")?;
    let prime = BigNum::from_dec_str(DEFAULT_PRIME)?;

    let mut shares_polynomials: Vec<Vec<Vec<BigNum>>> = Vec::with_capacity(shares.len());

    let mut first_share_count = None;

    for share in shares.iter() {
        if share.len() % COEFFICIENTS_SIZE != 0 {
            return Err(SSSError::WithReason(format!(
                "Share size is not divisible by {COEFFICIENTS_SIZE}"
            )));
        }
        let share_count = share.len() / COEFFICIENTS_SIZE;
        if let Some(first_share_count) = first_share_count {
            if share_count != first_share_count {
                return Err(SSSError::WithReason(format!(
                    "All shares shall have the same size of {first_share_count}"
                )));
            }
        } else {
            first_share_count = Some(share_count);
        }
        let mut polynomials: Vec<Vec<BigNum>> = Vec::with_capacity(share_count);
        for i in 0..share_count {
            let polynomial =
                bytes_to_big_nums(&share[i * COEFFICIENTS_SIZE..(i + 1) * COEFFICIENTS_SIZE])?;
            polynomials.push(polynomial);
        }
        shares_polynomials.push(polynomials);
    }

    let share_count = first_share_count.unwrap_or_default();
    let mut pre_secret_coeffisiances: Vec<BigNum> = Vec::with_capacity(share_count);

    for j in 0..share_count {
        let mut candidate = BigNum::from_dec_str("0")?;

        for (i, polys_i) in shares_polynomials.iter().enumerate() {
            let origin = &polys_i[j][0];
            let origin_y = &polys_i[j][1];
            let mut numerator = BigNum::from_dec_str("1")?;
            let mut denominator = BigNum::from_dec_str("1")?;

            'k_iter: for (k, polys_k) in shares_polynomials.iter().enumerate() {
                if k == i {
                    continue 'k_iter;
                }

                let current = &polys_k[j][0];
                let mut negative = BigNum::from_dec_str("0")?;
                negative.checked_mul(&negative_one, current, &mut ctx)?;

                let mut added = BigNum::from_dec_str("0")?;
                added.checked_sub(origin, current)?;

                let mut temp = BigNum::new()?;
                temp.checked_mul(&numerator, &negative, &mut ctx)?;
                numerator.nnmod(&temp, &prime, &mut ctx)?;

                let mut temp = BigNum::new()?;
                temp.checked_mul(&denominator, &added, &mut ctx)?;
                denominator.nnmod(&temp, &prime, &mut ctx)?;
            }

            let mut working = BigNum::from_dec_str("0")?;
            working.checked_mul(origin_y, &numerator, &mut ctx)?;

            let mut temp = BigNum::new()?;
            temp.mod_inverse(&denominator, &prime, &mut ctx)?;
            denominator = temp;

            let mut temp = BigNum::new()?;
            temp.checked_mul(&working, &denominator, &mut ctx)?;
            working = temp;

            let mut temp = BigNum::new()?;
            temp.checked_add(&candidate, &working)?;
            candidate.nnmod(&temp, &prime, &mut ctx)?;
        }

        pre_secret_coeffisiances.push(candidate);
    }

    Ok(big_nums_to_bytes(&pre_secret_coeffisiances))
}

#[cfg(test)]
mod tests {
    use crate::{
        combine_std, create_std,
        errors::SSSError,
        shamirss::{combine_shares, create_shares},
    };
    use openssl::rand::rand_bytes;
    use rand::seq::SliceRandom;
    use rand::thread_rng;

    fn get_random_bytes(size: usize) -> Result<Vec<u8>, SSSError> {
        let mut bytes = vec![0; size];
        rand_bytes(&mut bytes)?;
        Ok(bytes)
    }

    #[test]
    fn it_should_create_shares_and_combine_shares_for_min_half_and_all_shares(
    ) -> Result<(), SSSError> {
        struct TestCase<'a> {
            min: usize,
            shares: usize,
            secret: &'a [u8],
            fails: bool,
        }

        let test_cases: &[TestCase; 12] = &[
            TestCase {
                min: 4,
                shares: 5,
                secret: &get_random_bytes(128)?,
                fails: false,
            },
            TestCase {
                min: 10,
                shares: 20,
                secret: &get_random_bytes(256)?,
                fails: false,
            },
            TestCase {
                min: 20,
                shares: 40,
                secret: &get_random_bytes(512)?,
                fails: false,
            },
            TestCase {
                min: 40,
                shares: 41,
                secret: &get_random_bytes(128)?,
                fails: false,
            },
            TestCase {
                min: 40,
                shares: 41,
                secret: &get_random_bytes(256)?,
                fails: false,
            },
            TestCase {
                min: 40,
                shares: 41,
                secret: &get_random_bytes(512)?,
                fails: false,
            },
            TestCase {
                min: 40,
                shares: 80,
                secret: &get_random_bytes(128)?,
                fails: false,
            },
            TestCase {
                min: 40,
                shares: 80,
                secret: &get_random_bytes(256)?,
                fails: false,
            },
            TestCase {
                min: 40,
                shares: 80,
                secret: &get_random_bytes(512)?,
                fails: false,
            },
            TestCase {
                min: 100,
                shares: 200,
                secret: &get_random_bytes(128)?,
                fails: false,
            },
            TestCase {
                min: 100,
                shares: 200,
                secret: &get_random_bytes(256)?,
                fails: false,
            },
            TestCase {
                min: 100,
                shares: 200,
                secret: &get_random_bytes(512)?,
                fails: false,
            },
        ];

        for c in test_cases.iter() {
            let result = create_shares(c.min, c.shares, c.secret);
            let mut shares = match result {
                Ok(s) => {
                    assert!(!c.fails);
                    s
                }
                Err(_) => {
                    assert!(c.fails);
                    vec![]
                }
            };
            if shares.is_empty() {
                continue;
            }

            // SHUFFLE RESULT SLICE
            let mut rng = thread_rng();
            shares.shuffle(&mut rng);

            // LESS THEN MIN
            let secret = combine_shares(shares[0..c.min - 1].to_vec())?;
            assert_ne!(secret, c.secret);

            // MIN SHARES
            let secret = combine_shares(shares[0..c.min].to_vec())?;
            assert_eq!(secret, c.secret);

            // MORE THEN MIN LESS THEN ALL
            let secret = combine_shares(shares[0..c.min + (c.shares - c.min) / 2].to_vec())?;
            assert_eq!(secret, c.secret);

            // ALL SHARES
            let secret = combine_shares(shares)?;
            assert_eq!(secret, c.secret);
        }

        Ok(())
    }

    #[test]
    fn it_should_create_shares_and_combine_shares_randomized_data() -> Result<(), SSSError> {
        let mut size = 32;
        let min = 50;
        let shares_count = 100;
        for _ in 0..8 {
            let secret = get_random_bytes(size)?;
            let secret_shares = create_std(min, shares_count, &secret)?;
            let secret_decoded = combine_std(secret_shares)?;
            assert_eq!(secret, secret_decoded);
            size *= 2;
        }

        Ok(())
    }
}
