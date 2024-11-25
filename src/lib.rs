pub mod errors;
mod operations;
mod shamirss;
use errors::SSSError;
use operations::{
    is_proper_size, secret_base64_to_bytes, secret_bytes_to_base64, secret_bytes_to_hex,
    secret_hex_to_bytes, shares_base64_to_bytes, shares_bytes_to_base64, shares_bytes_to_hex,
    shares_hex_to_bytes, U8S_TO_BIG_INT_INITIAL,
};

/// Creates shared secrets from given secret.
/// Function will not be inlined.
/// Can calculate shares for secret divisible by 32 without rest (secret_size mod 32 == 0).
///
/// # Argument
///
/// * `min_shares_count`    - minimal amount of shares required to reconstruct the secret.
/// * `total_shares_count`  - total amount of shares.
/// * `secret`              - bytes slice of secret to create shares from.
///
/// # Examples
///
/// ```
/// use shamirss::{create_std};
///
///const SECRET_512_BYTES: &[u8; 512] = &[
///    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
///    110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 112, 99, 131, 144, 100, 100, 93, 129, 160,
///    99, 153, 151, 145, 114, 122, 123, 127, 148, 120, 98, 137, 175, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
///    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 243, 25, 64, 173, 202, 96, 116,
///    133, 114, 12, 186, 37, 43, 2, 70, 194, 52, 40, 80, 160, 233, 205, 0, 0, 0, 0, 0, 0, 0, 0, 29,
///    136, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
///    0, 0, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 112, 99, 131, 144, 100, 100, 93, 129,
///    160, 99, 153, 151, 145, 114, 122, 123, 127, 148, 120, 98, 137, 175, 0, 0, 0, 0, 0, 0, 0, 0, 0,
///    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 243, 25, 64, 173, 202, 96,
///    116, 133, 114, 12, 186, 37, 43, 2, 70, 194, 52, 40, 80, 160, 233, 205, 0, 0, 0, 0, 0, 0, 0, 0,
///    29, 136, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
///    0, 0, 0, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 112, 99, 131, 144, 100, 100, 93,
///    129, 160, 99, 153, 151, 145, 114, 122, 123, 127, 148, 120, 98, 137, 175, 0, 0, 0, 0, 0, 0, 0,
///    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 243, 25, 64, 173,
///    202, 96, 116, 133, 114, 12, 186, 37, 43, 2, 70, 194, 52, 40, 80, 160, 233, 205, 0, 0, 0, 0, 0,
///    0, 0, 0, 29, 136, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
///    0, 0, 0, 0, 0, 0, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 112, 99, 131, 144, 100,
///    100, 93, 129, 160, 99, 153, 151, 145, 114, 122, 123, 127, 148, 120, 98, 137, 175, 0, 0, 0, 0,
///    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 243, 25,
///    64, 173, 202, 96, 116, 133, 114, 12, 186, 37, 43, 2, 70, 194, 52, 40, 80, 160, 233, 205, 0, 0,
///    0, 0, 0, 0, 0, 0, 29, 136,
///];
///
/// let _secret_shares: Vec<Vec<u8>> = create_std(50, 100, SECRET_512_BYTES).unwrap();
///
///```
///
pub fn create_std(
    min_shares_count: usize,
    total_shares_count: usize,
    secret: &[u8],
) -> Result<Vec<Vec<u8>>, errors::SSSError> {
    if !is_proper_size(secret) {
        return Err(errors::SSSError::WithReason(format!(
            "Secret size should be divisible by {U8S_TO_BIG_INT_INITIAL} without rest"
        )));
    }
    shamirss::create_shares(min_shares_count, total_shares_count, secret)
}

/// Combines shares to a secrets.
/// Function will not be inlined.
///
/// # Argument
///
/// * `shares`  - vector of shares to reconstruct the secret. Shall be equal or more the minimal
/// share count required to re-create the secret used for crating shares.
///
/// # Examples
///
/// ```
///use shamirss::{create_std, combine_std};
///
///const SECRET_512_BYTES: &[u8; 512] = &[
///    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
///    110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 112, 99, 131, 144, 100, 100, 93, 129, 160,
///    99, 153, 151, 145, 114, 122, 123, 127, 148, 120, 98, 137, 175, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
///    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 243, 25, 64, 173, 202, 96, 116,
///    133, 114, 12, 186, 37, 43, 2, 70, 194, 52, 40, 80, 160, 233, 205, 0, 0, 0, 0, 0, 0, 0, 0, 29,
///    136, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
///    0, 0, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 112, 99, 131, 144, 100, 100, 93, 129,
///    160, 99, 153, 151, 145, 114, 122, 123, 127, 148, 120, 98, 137, 175, 0, 0, 0, 0, 0, 0, 0, 0, 0,
///    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 243, 25, 64, 173, 202, 96,
///    116, 133, 114, 12, 186, 37, 43, 2, 70, 194, 52, 40, 80, 160, 233, 205, 0, 0, 0, 0, 0, 0, 0, 0,
///    29, 136, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
///    0, 0, 0, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 112, 99, 131, 144, 100, 100, 93,
///    129, 160, 99, 153, 151, 145, 114, 122, 123, 127, 148, 120, 98, 137, 175, 0, 0, 0, 0, 0, 0, 0,
///    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 243, 25, 64, 173,
///    202, 96, 116, 133, 114, 12, 186, 37, 43, 2, 70, 194, 52, 40, 80, 160, 233, 205, 0, 0, 0, 0, 0,
///    0, 0, 0, 29, 136, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
///    0, 0, 0, 0, 0, 0, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 112, 99, 131, 144, 100,
///    100, 93, 129, 160, 99, 153, 151, 145, 114, 122, 123, 127, 148, 120, 98, 137, 175, 0, 0, 0, 0,
///    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 243, 25,
///    64, 173, 202, 96, 116, 133, 114, 12, 186, 37, 43, 2, 70, 194, 52, 40, 80, 160, 233, 205, 0, 0,
///    0, 0, 0, 0, 0, 0, 29, 136,
///];
///
/// let secret_shares: Vec<Vec<u8>> = create_std(50, 100, SECRET_512_BYTES).unwrap();
/// let secret_recreated = combine_std(secret_shares).unwrap();
/// assert_eq!(SECRET_512_BYTES.to_vec(), secret_recreated);
///```
///
pub fn combine_std(shares: Vec<Vec<u8>>) -> Result<Vec<u8>, errors::SSSError> {
    shamirss::combine_shares(shares)
}

/// Creates shared secrets from given secret.
/// Function will be inlined.
/// Can calculate shares for secret divisible by 32 without rest (secret_size mod 32 == 0).
///
/// # Argument
///
/// * `min_shares_count`    - minimal amount of shares required to reconstruct the secret.
/// * `total_shares_count`  - total amount of shares.
/// * `secret`              - bytes slice of secret to create shares from.
///
/// # Examples
///
/// ```
///use shamirss::{create_inlined};
///
///const SECRET_512_BYTES: &[u8; 512] = &[
///    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
///    110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 112, 99, 131, 144, 100, 100, 93, 129, 160,
///    99, 153, 151, 145, 114, 122, 123, 127, 148, 120, 98, 137, 175, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
///    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 243, 25, 64, 173, 202, 96, 116,
///    133, 114, 12, 186, 37, 43, 2, 70, 194, 52, 40, 80, 160, 233, 205, 0, 0, 0, 0, 0, 0, 0, 0, 29,
///    136, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
///    0, 0, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 112, 99, 131, 144, 100, 100, 93, 129,
///    160, 99, 153, 151, 145, 114, 122, 123, 127, 148, 120, 98, 137, 175, 0, 0, 0, 0, 0, 0, 0, 0, 0,
///    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 243, 25, 64, 173, 202, 96,
///    116, 133, 114, 12, 186, 37, 43, 2, 70, 194, 52, 40, 80, 160, 233, 205, 0, 0, 0, 0, 0, 0, 0, 0,
///    29, 136, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
///    0, 0, 0, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 112, 99, 131, 144, 100, 100, 93,
///    129, 160, 99, 153, 151, 145, 114, 122, 123, 127, 148, 120, 98, 137, 175, 0, 0, 0, 0, 0, 0, 0,
///    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 243, 25, 64, 173,
///    202, 96, 116, 133, 114, 12, 186, 37, 43, 2, 70, 194, 52, 40, 80, 160, 233, 205, 0, 0, 0, 0, 0,
///    0, 0, 0, 29, 136, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
///    0, 0, 0, 0, 0, 0, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 112, 99, 131, 144, 100,
///    100, 93, 129, 160, 99, 153, 151, 145, 114, 122, 123, 127, 148, 120, 98, 137, 175, 0, 0, 0, 0,
///    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 243, 25,
///    64, 173, 202, 96, 116, 133, 114, 12, 186, 37, 43, 2, 70, 194, 52, 40, 80, 160, 233, 205, 0, 0,
///    0, 0, 0, 0, 0, 0, 29, 136,
///];
///
/// let _secret_shares: Vec<Vec<u8>> = create_inlined(50, 100, SECRET_512_BYTES).unwrap();
///
///```
///
#[inline(always)]
pub fn create_inlined(
    min_shares_count: usize,
    total_shares_count: usize,
    secret: &[u8],
) -> Result<Vec<Vec<u8>>, errors::SSSError> {
    if !is_proper_size(secret) {
        return Err(errors::SSSError::WithReason(format!(
            "Secret size should be divisible by {U8S_TO_BIG_INT_INITIAL} without rest"
        )));
    }
    shamirss::create_shares(min_shares_count, total_shares_count, secret)
}

/// Combines shares to a secrets.
/// Function will be inlined.
///
/// # Argument
///
/// * `shares`  - vector of shares to reconstruct the secret. Shall be equal or more the minimal
/// share count required to re-create the secret used for crating shares.
///
/// # Examples
///
/// ```
///use shamirss::{combine_inlined, create_inlined};
///
///const SECRET_512_BYTES: &[u8; 512] = &[
///    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
///    110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 112, 99, 131, 144, 100, 100, 93, 129, 160,
///    99, 153, 151, 145, 114, 122, 123, 127, 148, 120, 98, 137, 175, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
///    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 243, 25, 64, 173, 202, 96, 116,
///    133, 114, 12, 186, 37, 43, 2, 70, 194, 52, 40, 80, 160, 233, 205, 0, 0, 0, 0, 0, 0, 0, 0, 29,
///    136, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
///    0, 0, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 112, 99, 131, 144, 100, 100, 93, 129,
///    160, 99, 153, 151, 145, 114, 122, 123, 127, 148, 120, 98, 137, 175, 0, 0, 0, 0, 0, 0, 0, 0, 0,
///    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 243, 25, 64, 173, 202, 96,
///    116, 133, 114, 12, 186, 37, 43, 2, 70, 194, 52, 40, 80, 160, 233, 205, 0, 0, 0, 0, 0, 0, 0, 0,
///    29, 136, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
///    0, 0, 0, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 112, 99, 131, 144, 100, 100, 93,
///    129, 160, 99, 153, 151, 145, 114, 122, 123, 127, 148, 120, 98, 137, 175, 0, 0, 0, 0, 0, 0, 0,
///    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 243, 25, 64, 173,
///    202, 96, 116, 133, 114, 12, 186, 37, 43, 2, 70, 194, 52, 40, 80, 160, 233, 205, 0, 0, 0, 0, 0,
///    0, 0, 0, 29, 136, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
///    0, 0, 0, 0, 0, 0, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 112, 99, 131, 144, 100,
///    100, 93, 129, 160, 99, 153, 151, 145, 114, 122, 123, 127, 148, 120, 98, 137, 175, 0, 0, 0, 0,
///    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 243, 25,
///    64, 173, 202, 96, 116, 133, 114, 12, 186, 37, 43, 2, 70, 194, 52, 40, 80, 160, 233, 205, 0, 0,
///    0, 0, 0, 0, 0, 0, 29, 136,
///];
///
/// let secret_shares: Vec<Vec<u8>> = create_inlined(50, 100, SECRET_512_BYTES).unwrap();
/// let secret_recreated = combine_inlined(secret_shares).unwrap();
/// assert_eq!(SECRET_512_BYTES.to_vec(), secret_recreated);
///```
///
#[inline(always)]
pub fn combine_inlined(shares: Vec<Vec<u8>>) -> Result<Vec<u8>, errors::SSSError> {
    shamirss::combine_shares(shares)
}

/// Encoding standard for secret and shares.
///
#[derive(Debug, Clone)]
pub enum EncodingStd {
    Hex,
    Base64,
}

/// Encodes secret bytes to string in given encoding standard.
///
/// # Argument
///
/// * `b`  - secret bytes to encode.
///
/// # Examples
///
/// ```
///use shamirss::{encode_secret_bytes, EncodingStd};
///
///const secret_bytes: &[u8; 512] = &[
///    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
///    110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 112, 99, 131, 144, 100, 100, 93, 129, 160,
///    99, 153, 151, 145, 114, 122, 123, 127, 148, 120, 98, 137, 175, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
///    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 243, 25, 64, 173, 202, 96, 116,
///    133, 114, 12, 186, 37, 43, 2, 70, 194, 52, 40, 80, 160, 233, 205, 0, 0, 0, 0, 0, 0, 0, 0, 29,
///    136, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
///    0, 0, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 112, 99, 131, 144, 100, 100, 93, 129,
///    160, 99, 153, 151, 145, 114, 122, 123, 127, 148, 120, 98, 137, 175, 0, 0, 0, 0, 0, 0, 0, 0, 0,
///    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 243, 25, 64, 173, 202, 96,
///    116, 133, 114, 12, 186, 37, 43, 2, 70, 194, 52, 40, 80, 160, 233, 205, 0, 0, 0, 0, 0, 0, 0, 0,
///    29, 136, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
///    0, 0, 0, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 112, 99, 131, 144, 100, 100, 93,
///    129, 160, 99, 153, 151, 145, 114, 122, 123, 127, 148, 120, 98, 137, 175, 0, 0, 0, 0, 0, 0, 0,
///    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 243, 25, 64, 173,
///    202, 96, 116, 133, 114, 12, 186, 37, 43, 2, 70, 194, 52, 40, 80, 160, 233, 205, 0, 0, 0, 0, 0,
///    0, 0, 0, 29, 136, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
///    0, 0, 0, 0, 0, 0, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 112, 99, 131, 144, 100,
///    100, 93, 129, 160, 99, 153, 151, 145, 114, 122, 123, 127, 148, 120, 98, 137, 175, 0, 0, 0, 0,
///    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 243, 25,
///    64, 173, 202, 96, 116, 133, 114, 12, 186, 37, 43, 2, 70, 194, 52, 40, 80, 160, 233, 205, 0, 0,
///    0, 0, 0, 0, 0, 0, 29, 136,
///];
///
///let encoding = EncodingStd::Hex;
///let enc = encode_secret_bytes(secret_bytes, encoding);
///```
///
pub fn encode_secret_bytes(b: &[u8], encoding: EncodingStd) -> String {
    match encoding {
        EncodingStd::Hex => secret_bytes_to_hex(b),
        EncodingStd::Base64 => secret_bytes_to_base64(b),
    }
}

/// Decodes secret to bytes from string in given encoding standard.
///
/// # Argument
///
/// * `s`  - secret string to decode.
///
/// # Examples
///
/// ```
///use shamirss::{encode_secret_bytes, decode_secret_to_bytes, EncodingStd};
///
///const secret_bytes: &[u8; 512] = &[
///    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
///    110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 112, 99, 131, 144, 100, 100, 93, 129, 160,
///    99, 153, 151, 145, 114, 122, 123, 127, 148, 120, 98, 137, 175, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
///    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 243, 25, 64, 173, 202, 96, 116,
///    133, 114, 12, 186, 37, 43, 2, 70, 194, 52, 40, 80, 160, 233, 205, 0, 0, 0, 0, 0, 0, 0, 0, 29,
///    136, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
///    0, 0, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 112, 99, 131, 144, 100, 100, 93, 129,
///    160, 99, 153, 151, 145, 114, 122, 123, 127, 148, 120, 98, 137, 175, 0, 0, 0, 0, 0, 0, 0, 0, 0,
///    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 243, 25, 64, 173, 202, 96,
///    116, 133, 114, 12, 186, 37, 43, 2, 70, 194, 52, 40, 80, 160, 233, 205, 0, 0, 0, 0, 0, 0, 0, 0,
///    29, 136, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
///    0, 0, 0, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 112, 99, 131, 144, 100, 100, 93,
///    129, 160, 99, 153, 151, 145, 114, 122, 123, 127, 148, 120, 98, 137, 175, 0, 0, 0, 0, 0, 0, 0,
///    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 243, 25, 64, 173,
///    202, 96, 116, 133, 114, 12, 186, 37, 43, 2, 70, 194, 52, 40, 80, 160, 233, 205, 0, 0, 0, 0, 0,
///    0, 0, 0, 29, 136, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
///    0, 0, 0, 0, 0, 0, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 112, 99, 131, 144, 100,
///    100, 93, 129, 160, 99, 153, 151, 145, 114, 122, 123, 127, 148, 120, 98, 137, 175, 0, 0, 0, 0,
///    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 243, 25,
///    64, 173, 202, 96, 116, 133, 114, 12, 186, 37, 43, 2, 70, 194, 52, 40, 80, 160, 233, 205, 0, 0,
///    0, 0, 0, 0, 0, 0, 29, 136,
///];
///
///let encoding = EncodingStd::Hex;
///let enc = encode_secret_bytes(secret_bytes, encoding.clone());

///let _dec = decode_secret_to_bytes(&enc, encoding).unwrap();
///```
///
pub fn decode_secret_to_bytes(s: &str, encoding: EncodingStd) -> Result<Vec<u8>, SSSError> {
    match encoding {
        EncodingStd::Hex => secret_hex_to_bytes(s),
        EncodingStd::Base64 => secret_base64_to_bytes(s),
    }
}

/// Encodes slice of shares bytes to slice of strings in given encoding standard.
///
/// # Argument
///
/// * `b`  - vector of shares in bytes to encode.
///
/// # Examples
///
/// ```
///use shamirss::{encode_shares_bytes, EncodingStd};
///
///let secret_shares: Vec<Vec<u8>> = vec![vec![1;128], vec![2;128], vec![3;128], vec![4;128]];
///
///
///let encoding = EncodingStd::Hex;
///let _enc = encode_shares_bytes(secret_shares, encoding);
///```
///
pub fn encode_shares_bytes(b: Vec<Vec<u8>>, encoding: EncodingStd) -> Vec<String> {
    match encoding {
        EncodingStd::Hex => shares_bytes_to_hex(b),
        EncodingStd::Base64 => shares_bytes_to_base64(b),
    }
}

/// Decodes slice of shares strings encoded in given encoding standard to slice of shares in bytes.
///
/// # Argument
///
/// * `b`  - vector of shares strings to decode.
///
/// # Examples
///
/// ```
///use shamirss::{encode_shares_bytes, decode_shares_to_bytes, EncodingStd};
///
///let secret_shares: Vec<Vec<u8>> = vec![vec![1;128], vec![2;128], vec![3;128], vec![4;128]];
///
///
///let encoding = EncodingStd::Hex;
///let enc = encode_shares_bytes(secret_shares, encoding.clone());
///let _dec = decode_shares_to_bytes(&enc, encoding).unwrap();
///```
///
pub fn decode_shares_to_bytes(
    s: &[String],
    encoding: EncodingStd,
) -> Result<Vec<Vec<u8>>, SSSError> {
    match encoding {
        EncodingStd::Hex => shares_hex_to_bytes(s),
        EncodingStd::Base64 => shares_base64_to_bytes(s),
    }
}
