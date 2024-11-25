use crate::errors::SSSError;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use openssl::bn::{BigNum, BigNumContextRef};

/// Default prime used for mod calculations.
///
pub(crate) const DEFAULT_PRIME: &str =
    "115792089237316195423570985008687907853269984665640564039457584007913129639747";

/// Maximum initial size of big int is set to 32 bytes to protect against value overflow.
///
pub(crate) const U8S_TO_BIG_INT_INITIAL: usize = 32;

/// Calculates is the bytes slice divisor is initial big int size.
///
#[inline(always)]
pub(crate) fn is_proper_size(v: &[u8]) -> bool {
    v.len() % U8S_TO_BIG_INT_INITIAL == 0
}

/// Returns random number between 0 and DEFAULT_PRIME - 1.
///
#[inline(always)]
pub(crate) fn random(upper_limit: &BigNum) -> Result<BigNum, SSSError> {
    let mut result = BigNum::new()?;
    upper_limit.rand_range(&mut result)?;
    Ok(result)
}

/// Maps bytes to big nums.
///
#[inline(always)]
pub(crate) fn bytes_to_big_nums(bytes: &[u8]) -> Result<Vec<BigNum>, SSSError> {
    let mut slice =
        Vec::with_capacity((bytes.len() as f64 / U8S_TO_BIG_INT_INITIAL as f64).ceil() as usize);
    for (start, _) in bytes.iter().step_by(U8S_TO_BIG_INT_INITIAL).enumerate() {
        let start = start * U8S_TO_BIG_INT_INITIAL;
        let end = if start + U8S_TO_BIG_INT_INITIAL > bytes.len() {
            bytes.len()
        } else {
            start + U8S_TO_BIG_INT_INITIAL
        };
        let num = BigNum::from_slice(&bytes[start..end])?;
        slice.push(num);
    }

    Ok(slice)
}

/// Maps big nums to bytes.
///
#[inline(always)]
pub(crate) fn big_nums_to_bytes(slice: &[BigNum]) -> Vec<u8> {
    let mut result = Vec::with_capacity(slice.len() * U8S_TO_BIG_INT_INITIAL);
    for big_int in slice.iter() {
        let bytes = big_int.to_vec();
        if bytes.len() < U8S_TO_BIG_INT_INITIAL {
            result.extend(vec![0; U8S_TO_BIG_INT_INITIAL - bytes.len()].iter());
            result.extend(bytes);
        } else {
            result.extend(bytes);
        }
    }
    result
}

/// Evaluates polynomial slice.
///
#[inline(always)]
pub(crate) fn evaluate(
    ctx: &mut BigNumContextRef,
    slice: &[BigNum],
    value: &BigNum,
    prime: &BigNum,
) -> Result<BigNum, SSSError> {
    let mut result = BigNum::new()?;

    for i in (0..slice.len()).rev() {
        let mut temp = BigNum::new()?;
        temp.checked_mul(result.as_ref(), value, ctx)?;
        result.checked_add(temp.as_ref(), &slice[i])?;
        temp.nnmod(result.as_ref(), prime, ctx)?;
        result = temp
    }

    Ok(result)
}

/// Decodes hex to bytes.
///
#[inline(always)]
pub(crate) fn secret_hex_to_bytes(s: &str) -> Result<Vec<u8>, SSSError> {
    Ok(hex::decode(s)?)
}

/// Decodes hex shares slice to slices of bytes slices.
///
#[inline(always)]
pub(crate) fn shares_hex_to_bytes(s: &[String]) -> Result<Vec<Vec<u8>>, SSSError> {
    let mut err = None;
    let result = s
        .iter()
        .map(hex::decode)
        .filter_map(|r| {
            r.map_err(|e| {
                if err.is_none() {
                    err = Some(e)
                }
            })
            .ok()
        })
        .collect();
    if let Some(e) = err {
        return Err(SSSError::FromHex(e));
    }

    Ok(result)
}

/// Encodes secret bytes to hex.
///
#[inline(always)]
pub(crate) fn secret_bytes_to_hex(h: &[u8]) -> String {
    hex::encode(h)
}

/// Encodes shares slices of bytes to hex slices.
///
#[inline(always)]
pub(crate) fn shares_bytes_to_hex(h: Vec<Vec<u8>>) -> Vec<String> {
    h.iter().map(hex::encode).collect::<Vec<String>>()
}

/// Decodes base64 to bytes.
///
#[inline(always)]
pub(crate) fn secret_base64_to_bytes(s: &str) -> Result<Vec<u8>, SSSError> {
    Ok(STANDARD.decode(s)?)
}

/// Decodes base64 shares slice to slices of bytes slices.
///
#[inline(always)]
pub(crate) fn shares_base64_to_bytes(s: &[String]) -> Result<Vec<Vec<u8>>, SSSError> {
    let mut err = None;
    let result = s
        .iter()
        .map(|b| STANDARD.decode(b))
        .filter_map(|r| {
            r.map_err(|e| {
                if err.is_none() {
                    err = Some(e)
                }
            })
            .ok()
        })
        .collect();
    if let Some(e) = err {
        return Err(SSSError::FromBase64(e));
    }

    Ok(result)
}

/// Encodes secret bytes to base64.
///
#[inline(always)]
pub(crate) fn secret_bytes_to_base64(h: &[u8]) -> String {
    STANDARD.encode(h)
}

/// Encodes secret bytes to base64.
///
#[inline(always)]
pub(crate) fn shares_bytes_to_base64(h: Vec<Vec<u8>>) -> Vec<String> {
    h.iter()
        .map(|s| STANDARD.encode(s))
        .collect::<Vec<String>>()
}

#[cfg(test)]
mod tests {
    use openssl::bn::BigNumContext;

    use super::*;
    use std::collections::HashSet;
    use std::time::Instant;

    const ITER_COUNT: usize = 1_000_000;
    const BENCH_ITTER: usize = 100_000;

    #[test]
    fn it_shall_create_unique_random_big_int_each_time() -> Result<(), SSSError> {
        let prime = BigNum::from_dec_str(DEFAULT_PRIME).unwrap();
        let mut set = HashSet::new();
        for _ in 0..ITER_COUNT {
            assert!(set.insert(random(&prime)?.to_vec()));
        }

        Ok(())
    }

    #[test]
    fn it_should_benchmark_random_big_int() -> Result<(), SSSError> {
        let prime = BigNum::from_dec_str(DEFAULT_PRIME)?;
        let now = Instant::now();
        for _ in 0..BENCH_ITTER {
            random(&prime)?;
        }

        println!(
            "Time to calculate random big int took on average {} [ nanoseconds ]",
            (now.elapsed().as_nanos() as f64 / BENCH_ITTER as f64) as usize
        );

        Ok(())
    }

    #[test]
    fn it_should_convert_bytes_to_slice_of_big_ints() -> Result<(), SSSError> {
        let bytes_2_bytes: &[u8; 2] = &[10, 33];
        let expected_big_int_from_2_bytes: &[BigNum; 1] = &[BigNum::from_dec_str("2593")?];

        let bytes_16_bytes: &[u8; 16] = &[
            10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145,
        ];
        let expected_big_int_from_16_bytes: &[BigNum; 1] = &[BigNum::from_dec_str(
            "13468799629078354179291325055507502481",
        )?];

        let bytes_32_bytes: &[u8; 32] = &[
            10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23,
            123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145,
        ];
        let expected_big_int_from_32_bytes: &[BigNum; 1] = &[BigNum::from_dec_str(
            "4583195017366640394614729638310681267193810345231665377656985560666360124817",
        )?];

        let bytes_64_bytes: &[u8; 64] = &[
            10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23,
            123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99,
            0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22,
            233, 222, 21, 145,
        ];
        let expected_big_int_from_64_bytes: &[BigNum; 1] = &[BigNum::from_dec_str(
            "4583195017366640394614729638310681267193810345231665377656985560666360124817",
        )?];

        let bytes_128_bytes: &[u8; 128] = &[
            10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23,
            123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99,
            0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22,
            233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21,
            145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255,
            23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6,
            99, 0, 158, 160, 22, 233, 222, 21, 145,
        ];
        let expected_big_int_from_128_bytes: &[BigNum; 2] = &[
            BigNum::from_dec_str(
                "4583195017366640394614729638310681267193810345231665377656985560666360124817",
            )?,
            BigNum::from_dec_str(
                "4583195017366640394614729638310681267193810345231665377656985560666360124817",
            )?,
        ];

        let bytes_256_bytes: &[u8; 256] = &[
            10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23,
            123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99,
            0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22,
            233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21,
            145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255,
            23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6,
            99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160,
            22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21,
            145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255,
            23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6,
            99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160,
            22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21,
            145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145,
        ];
        let expected_big_int_from_256_bytes: &[BigNum; 4] = &[
            BigNum::from_dec_str(
                "4583195017366640394614729638310681267193810345231665377656985560666360124817",
            )?,
            BigNum::from_dec_str(
                "4583195017366640394614729638310681267193810345231665377656985560666360124817",
            )?,
            BigNum::from_dec_str(
                "4583195017366640394614729638310681267193810345231665377656985560666360124817",
            )?,
            BigNum::from_dec_str(
                "4583195017366640394614729638310681267193810345231665377656985560666360124817",
            )?,
        ];

        let bytes_512_bytes: &[u8; 512] = &[
            10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23,
            123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99,
            0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22,
            233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21,
            145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255,
            23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6,
            99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160,
            22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21,
            145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255,
            23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6,
            99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160,
            22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21,
            145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255,
            23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6,
            99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160,
            22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21,
            145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255,
            23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6,
            99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160,
            22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21,
            145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255,
            23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6,
            99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160,
            22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21,
            145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255,
            23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145,
        ];
        let expected_big_int_from_512_bytes: &[BigNum; 8] = &[
            BigNum::from_dec_str(
                "4583195017366640394614729638310681267193810345231665377656985560666360124817",
            )?,
            BigNum::from_dec_str(
                "4583195017366640394614729638310681267193810345231665377656985560666360124817",
            )?,
            BigNum::from_dec_str(
                "4583195017366640394614729638310681267193810345231665377656985560666360124817",
            )?,
            BigNum::from_dec_str(
                "4583195017366640394614729638310681267193810345231665377656985560666360124817",
            )?,
            BigNum::from_dec_str(
                "4583195017366640394614729638310681267193810345231665377656985560666360124817",
            )?,
            BigNum::from_dec_str(
                "4583195017366640394614729638310681267193810345231665377656985560666360124817",
            )?,
            BigNum::from_dec_str(
                "4583195017366640394614729638310681267193810345231665377656985560666360124817",
            )?,
            BigNum::from_dec_str(
                "4583195017366640394614729638310681267193810345231665377656985560666360124817",
            )?,
        ];

        let bytes_496_bytes: &[u8; 496] = &[
            10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23,
            123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99,
            0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22,
            233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21,
            145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255,
            23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6,
            99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160,
            22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21,
            145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255,
            23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6,
            99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160,
            22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21,
            145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255,
            23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6,
            99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160,
            22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21,
            145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255,
            23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6,
            99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160,
            22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21,
            145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255,
            23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6,
            99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160,
            22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21,
            145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145,
        ];
        let expected_big_int_from_496_bytes: &[BigNum; 8] = &[
            BigNum::from_dec_str(
                "4583195017366640394614729638310681267193810345231665377656985560666360124817",
            )?,
            BigNum::from_dec_str(
                "4583195017366640394614729638310681267193810345231665377656985560666360124817",
            )?,
            BigNum::from_dec_str(
                "4583195017366640394614729638310681267193810345231665377656985560666360124817",
            )?,
            BigNum::from_dec_str(
                "4583195017366640394614729638310681267193810345231665377656985560666360124817",
            )?,
            BigNum::from_dec_str(
                "4583195017366640394614729638310681267193810345231665377656985560666360124817",
            )?,
            BigNum::from_dec_str(
                "4583195017366640394614729638310681267193810345231665377656985560666360124817",
            )?,
            BigNum::from_dec_str(
                "4583195017366640394614729638310681267193810345231665377656985560666360124817",
            )?,
            BigNum::from_dec_str(
                "4583195017366640394614729638310681267193810345231665377656985560666360124817",
            )?,
        ];

        struct TestCase<'a> {
            name: &'a str,
            buff: &'a [u8],
            expected: &'a [BigNum],
        }

        for c in vec![
            TestCase {
                name: "bytes_2_bytes",
                buff: bytes_2_bytes,
                expected: expected_big_int_from_2_bytes,
            },
            TestCase {
                name: "bytes_16_bytes",
                buff: bytes_16_bytes,
                expected: expected_big_int_from_16_bytes,
            },
            TestCase {
                name: "bytes_32_bytes",
                buff: bytes_32_bytes,
                expected: expected_big_int_from_32_bytes,
            },
            TestCase {
                name: "bytes_64_bytes",
                buff: bytes_64_bytes,
                expected: expected_big_int_from_64_bytes,
            },
            TestCase {
                name: "bytes_128_bytes",
                buff: bytes_128_bytes,
                expected: expected_big_int_from_128_bytes,
            },
            TestCase {
                name: "bytes_256_bytes",
                buff: bytes_256_bytes,
                expected: expected_big_int_from_256_bytes,
            },
            TestCase {
                name: "bytes_512_bytes",
                buff: bytes_512_bytes,
                expected: expected_big_int_from_512_bytes,
            },
            TestCase {
                name: "bytes_496_bytes",
                buff: bytes_496_bytes,
                expected: expected_big_int_from_496_bytes,
            },
        ]
        .iter()
        {
            let polynomial = bytes_to_big_nums(c.buff)?;
            println!("Testing {}", c.name);
            for (x, y) in polynomial.iter().zip(c.expected.iter()) {
                assert_eq!(*x, *y);
            }
        }

        Ok(())
    }

    #[test]
    fn it_shall_benchmark_convert_bytes_to_slice_of_big_ints() -> Result<(), SSSError> {
        let bytes_512_bytes: &[u8; 512] = &[
            10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23,
            123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99,
            0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22,
            233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21,
            145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255,
            23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6,
            99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160,
            22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21,
            145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255,
            23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6,
            99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160,
            22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21,
            145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255,
            23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6,
            99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160,
            22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21,
            145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255,
            23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6,
            99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160,
            22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21,
            145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255,
            23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6,
            99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160,
            22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21,
            145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255,
            23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145,
        ];
        let now = Instant::now();
        for _ in 0..BENCH_ITTER {
            let _ = bytes_to_big_nums(bytes_512_bytes)?;
        }

        println!(
            "Time to transform 512 bytes to big int slice took on average {} [ nanoseconds ]",
            (now.elapsed().as_nanos() as f64 / BENCH_ITTER as f64) as usize
        );

        Ok(())
    }

    #[test]
    fn it_should_convert_bytes_to_polynomial_and_back() -> Result<(), SSSError> {
        let bytes_512_bytes: &[u8; 512] = &[
            10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23,
            123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99,
            0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22,
            233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21,
            145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255,
            23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6,
            99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160,
            22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21,
            145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255,
            23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6,
            99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160,
            22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21,
            145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255,
            23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6,
            99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160,
            22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21,
            145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255,
            23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6,
            99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160,
            22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21,
            145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255,
            23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6,
            99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160,
            22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21,
            145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255,
            23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145,
        ];

        let polynomial = bytes_to_big_nums(bytes_512_bytes)?;
        let bytes_converted_back: Vec<u8> = big_nums_to_bytes(&polynomial);

        for (x, y) in bytes_512_bytes.iter().zip(bytes_converted_back.iter()) {
            assert_eq!(*x, *y);
        }

        Ok(())
    }

    #[test]
    fn it_should_benchmark_convert_big_int_to_bytes() -> Result<(), SSSError> {
        let bytes_512_bytes: &[u8; 512] = &[
            10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23,
            123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99,
            0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22,
            233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21,
            145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255,
            23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6,
            99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160,
            22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21,
            145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255,
            23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6,
            99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160,
            22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21,
            145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255,
            23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6,
            99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160,
            22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21,
            145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255,
            23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6,
            99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160,
            22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21,
            145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255,
            23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6,
            99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160,
            22, 233, 222, 21, 145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21,
            145, 10, 33, 255, 23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145, 10, 33, 255,
            23, 123, 111, 6, 99, 0, 158, 160, 22, 233, 222, 21, 145,
        ];

        let polynomial = bytes_to_big_nums(bytes_512_bytes)?;

        let now = Instant::now();
        for _ in 0..BENCH_ITTER {
            let _: Vec<u8> = big_nums_to_bytes(&polynomial);
        }

        println!(
            "Time to transform {} big ints to bytes took on average {} [ nanoseconds ]",
            polynomial.len(),
            (now.elapsed().as_nanos() as f64 / BENCH_ITTER as f64) as usize
        );

        Ok(())
    }

    #[test]
    fn it_should_evaluate_the_polynomial() -> Result<(), SSSError> {
        struct TestCase<'a> {
            name: &'a str,
            slice: &'a [BigNum],
            value: BigNum,
            actual: BigNum,
        }

        let test_cases: &[TestCase; 3] = &[
            TestCase {
                name: "actual 20",
                slice: &[
                    BigNum::from_dec_str("20")?,
                    BigNum::from_dec_str("21")?,
                    BigNum::from_dec_str("42")?,
                ],
                value: BigNum::from_dec_str("0")?,
                actual: BigNum::from_dec_str("20")?,
            },
            TestCase {
                name: "actual 0",
                slice: &[
                    BigNum::from_dec_str("0")?,
                    BigNum::from_dec_str("0")?,
                    BigNum::from_dec_str("0")?,
                ],
                value: BigNum::from_dec_str("4")?,
                actual: BigNum::from_dec_str("0")?,
            },
            TestCase {
                name: "actual 54321",
                slice: &[
                    BigNum::from_dec_str("1")?,
                    BigNum::from_dec_str("2")?,
                    BigNum::from_dec_str("3")?,
                    BigNum::from_dec_str("4")?,
                    BigNum::from_dec_str("5")?,
                ],
                value: BigNum::from_dec_str("10")?,
                actual: BigNum::from_dec_str("54321")?,
            },
        ];

        let mut ctx = BigNumContext::new().unwrap();
        let prime = BigNum::from_dec_str(DEFAULT_PRIME).unwrap();

        for c in test_cases.iter() {
            println!("Testing {}", c.name);
            let actual = evaluate(&mut ctx, c.slice, &c.value, &prime)?;
            assert!(actual.eq(&c.actual));
        }

        Ok(())
    }

    #[test]
    fn it_should_benchmark_evaluate_the_polynomial() -> Result<(), SSSError> {
        let slice: &[BigNum; 12] = &[
            BigNum::from_dec_str("1")?,
            BigNum::from_dec_str("22")?,
            BigNum::from_dec_str("322")?,
            BigNum::from_dec_str("42222")?,
            BigNum::from_dec_str("234235")?,
            BigNum::from_dec_str("242424241")?,
            BigNum::from_dec_str("2242234242")?,
            BigNum::from_dec_str("3424242435687")?,
            BigNum::from_dec_str("43456345635777")?,
            BigNum::from_dec_str("5256767346724562")?,
            BigNum::from_dec_str("414514351432434")?,
            BigNum::from_dec_str("5134578587467844567")?,
        ];
        let value = BigNum::from_dec_str("0")?;
        let mut ctx = BigNumContext::new()?;
        let prime = BigNum::from_dec_str(DEFAULT_PRIME)?;
        let now = Instant::now();

        for _ in 0..BENCH_ITTER {
            let _ = evaluate(&mut ctx, slice, &value, &prime);
        }

        println!(
            "Time to evaluate polynomial of {} parameters to bytes took on average {} [ nanoseconds ]",
            slice.len(),
            (now.elapsed().as_nanos() as f64 / BENCH_ITTER as f64) as usize
        );

        Ok(())
    }
}
