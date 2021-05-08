//! Key and IV structures for the cipher

use getrandom::getrandom;
use std::{fmt, str};
pub use crate::cha::{
    KEY_SIZE,
    IV_SIZE,
};
use crate::ext::*;

/// A 32 byte key for the chacha20_poly1305 cipher
///
/// # Generation
/// You can generate a random key with `Key::new()`.
/// To create a key structure from bytes, you can use `Key::from_bytes()` if the size of the buffer is exact, or you can write to an empty `Key` as it implements `Default`.
/// ```
/// # use chacha20stream::{Key, key::KEY_SIZE};
/// # let key_bytes = [0u8; 32];
/// let mut key = Key::default();
/// key.as_mut().copy_from_slice(&key_bytes[..KEY_SIZE]);
/// ```
///
/// You can also generate a random key/IV pair with `chacha20stream::keygen()`.
///
/// # Encoding
/// This type implements `std::fmt::Display`, which prints the key as a base64 string.
/// Additionally, it implements `std::str::FromStr`, which decodes a base64 string into a `Key` instance.
/// If the input base64 string data decoded is shorter than `KEY_SIZE`, the rest of the key instance is padded with 0s.
/// If it is longer, the rest is ignored.
///
/// The key can also be lazily formatted as a hex string, with the method `to_hex_string()`.
/// ```
/// # use chacha20stream::Key;
/// let key = Key::new();
/// let key_encoded = key.to_string();
///
/// println!("Key base64: {}", key_encoded);
/// println!("Key hex: {}", key.to_hex_string());
///
/// assert_eq!(key_encoded.parse::<Key>().unwrap(), key);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Copy, Default)]
#[cfg_attr(feature="serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct Key([u8; KEY_SIZE]);

/// A 12 byte IV for the chacha20_poly1305 cipher
///
/// # Generation
/// You can generate a random IV with `IV::new()`.
/// To create an IV structure from bytes, you can use `IV::from_bytes()` if the size of the buffer is exact, or you can write to an empty `IV` as it implements `Default`.
/// ```
/// # use chacha20stream::{IV, key::IV_SIZE};
/// # let iv_bytes = [0u8; 12];
/// let mut iv = IV::default();
/// iv.as_mut().copy_from_slice(&iv_bytes[..IV_SIZE]);
/// ```
///
/// You can also generate a random key/IV pair with `chacha20stream::keygen()`.
///
/// # Encoding
/// This type implements `std::fmt::Display`, which prints the IV as a base64 string.
/// Additionally, it implements `std::str::FromStr`, which decodes a base64 string into a `IV` instance.
/// If the input base64 string data decoded is shorter than `IV_SIZE`, the rest of the IV instance is padded with 0s.
/// If it is longer, the rest is ignored.
///
/// The IV can also be lazily formatted as a hex string, with the method `to_hex_string()`.
/// ```
/// # use chacha20stream::IV;
/// let iv = IV::new();
/// let iv_encoded = iv.to_string();
///
/// println!("IV base64: {}", iv_encoded);
/// println!("IV hex: {}", iv.to_hex_string());
///
/// assert_eq!(iv_encoded.parse::<IV>().unwrap(), iv);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Copy, Default)]
#[cfg_attr(feature="serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct IV([u8; IV_SIZE]);

impl Key
{
    /// Construct a `Key` from an exact length (32 bytes) buffer.
    #[inline] pub fn from_bytes(k: [u8; KEY_SIZE]) -> Self
    {
	Self(k)
    }
    /// Create a new random 32 byte chacha20_poly1305 `Key`.
    pub fn new() -> Self
    {
	let mut output = [0u8; KEY_SIZE];
	getrandom(&mut output[..]).expect("rng fatal");
	Self(output)
    }

    /// Format this key as a hex string
    ///
    /// Returns an opaque type that lazily formats the key into a hex string when written.
    ///
    /// # Example
    /// ```
    /// # use chacha20stream::Key;
    /// fn print_key_info(key: &Key) {
    ///   println!("Key base64: {}", key);
    ///   println!("Key hex: {}", key.to_hex_string());
    /// }
    /// ```
    /// Formatting to `String`
    /// ```
    /// # use chacha20stream::Key;
    /// # let key = Key::new();
    /// let key_hex_string = key.to_hex_string().to_string();
    /// ```
    pub fn to_hex_string(&self) -> impl fmt::Display + '_
    {
	self.0.iter().copied().into_hex()
    }
}

impl IV
{
    
    /// Construct a `IV` from an exact length (12 bytes) buffer.
    #[inline] pub fn from_bytes(k: [u8; IV_SIZE]) -> Self
    {
	Self(k)
    }
    /// Create a new random 12 byte chacha20_poly1305 `IV`.
    pub fn new() -> Self
    {
	let mut output = [0u8; IV_SIZE];
	getrandom(&mut output[..]).expect("rng fatal");
	Self(output)
    }
    
    /// Format this IV as a hex string
    ///
    /// Returns an opaque type that lazily formats the IV into a hex string when written.
    ///
    /// # Example
    /// ```
    /// # use chacha20stream::IV;
    /// fn print_iv_info(iv: &IV) {
    ///   println!("IV base64: {}", iv);
    ///   println!("IV hex: {}", iv.to_hex_string());
    /// }
    /// ```
    /// Formatting to `String`
    /// ```
    /// # use chacha20stream::IV;
    /// # let iv = IV::new();
    /// let iv_hex_string = iv.to_hex_string().to_string();
    /// ```
    pub fn to_hex_string(&self) -> impl fmt::Display + '_
    {
	self.0.iter().copied().into_hex()
    }
}

impl From<[u8; KEY_SIZE]> for Key
{
    #[inline] fn from(from: [u8; KEY_SIZE]) -> Self
    {
	Self(from)
    }
}

impl From<[u8; IV_SIZE]> for IV
{
    fn from(from: [u8; IV_SIZE]) -> Self
    {
	Self(from)
    }
}


impl AsRef<[u8]> for Key
{
    fn as_ref(&self) -> &[u8]
    {
	&self.0[..]
    }
}
impl AsRef<[u8]> for IV
{
    fn as_ref(&self) -> &[u8]
    {
	&self.0[..]
    }
}

impl AsMut<[u8]> for Key
{
    fn as_mut(&mut self) -> &mut [u8]
    {
	&mut self.0[..]
    }
}

impl AsMut<[u8]> for IV
{
    fn as_mut(&mut self) -> &mut [u8]
    {
	&mut self.0[..]
    }
}

impl AsRef<Key> for Key
{
    #[inline] fn as_ref(&self) -> &Key
    {
	self
    }
}
impl AsRef<IV> for IV
{
    #[inline] fn as_ref(&self) -> &IV
    {
	self
    }
}

impl fmt::Display for Key
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
	write!(f, "{}", base64::encode(&self.0[..]))
    }
}

impl fmt::Display for IV
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
	write!(f, "{}", base64::encode(&self.0[..]))
    }
}

impl str::FromStr for Key
{
    type Err = base64::DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
	let mut buffer = Vec::with_capacity(KEY_SIZE);
	base64::decode_config_buf(s.as_bytes(), base64::STANDARD, &mut buffer)?;

	let mut this = Self::default();
	let sz = std::cmp::min(KEY_SIZE, buffer.len());
	(&mut this.0[..sz]).copy_from_slice(&buffer[..sz]);
	Ok(this)
    }
}

impl str::FromStr for IV
{
    type Err = base64::DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
	let mut buffer = Vec::with_capacity(IV_SIZE);
	base64::decode_config_buf(s.as_bytes(), base64::STANDARD, &mut buffer)?;

	let mut this = Self::default();
	let sz = std::cmp::min(IV_SIZE, buffer.len());
	(&mut this.0[..sz]).copy_from_slice(&buffer[..sz]);
	Ok(this)
    }
}

#[cfg(test)]
mod tests
{
    use super::{Key, IV};
    #[test]
    fn enc_dec()
    {
	let (key, iv) = crate::keygen();

	let key_str = key.to_string();
	let iv_str = iv.to_string();

	let (key2, iv2): (Key, IV) = (key_str.parse().expect("key"),
				      iv_str.parse().expect("iv"));

	assert_eq!(key, key2);
	assert_eq!(iv, iv2);
    }
}
