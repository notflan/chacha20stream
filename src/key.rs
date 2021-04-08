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
#[derive(Debug, Clone, PartialEq, Eq, Hash, Copy, Default)]
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
#[derive(Debug, Clone, PartialEq, Eq, Hash, Copy, Default)]
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
	write!(f, "{}", self.0.iter().copied().into_hex())
    }
}

impl fmt::Display for IV
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
	write!(f, "{}", self.0.iter().copied().into_hex())
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
