use getrandom::getrandom;
use std::{fmt, str};
pub use crate::cha::{
    KEY_SIZE,
    IV_SIZE,
};
use crate::ext::*;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Copy, Default)]
#[repr(transparent)]
pub struct Key([u8; KEY_SIZE]);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Copy, Default)]
#[repr(transparent)]
pub struct IV([u8; IV_SIZE]);

impl Key
{
    #[inline] pub fn from_bytes(k: [u8; KEY_SIZE]) -> Self
    {
	Self(k)
    }
    pub fn new() -> Self
    {
	let mut output = [0u8; KEY_SIZE];
	getrandom(&mut output[..]).expect("rng fatal");
	Self(output)
    }
}

impl IV
{
    
    #[inline] pub fn from_bytes(k: [u8; IV_SIZE]) -> Self
    {
	Self(k)
    }
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
