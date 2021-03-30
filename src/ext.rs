use std::{
    mem,
    iter::{
	self, 
	ExactSizeIterator,
	FusedIterator,
    },
    slice,
    fmt,
};
#[derive(Debug, Clone)]
pub struct HexStringIter<I>(I, [u8; 2]);

impl<I: Iterator<Item = u8>> HexStringIter<I>
{
    /// Write this hex string iterator to a formattable buffer
    pub fn consume<F>(self, f: &mut F) -> fmt::Result
    where F: std::fmt::Write
    {
	if self.1[0] != 0 {
	    write!(f, "{}", self.1[0] as char)?;
	}
	if self.1[1] != 0 {
	    write!(f, "{}", self.1[1] as char)?;
	}

	for x in self.0 {
	    write!(f, "{:02x}", x)?;
	}
	
	Ok(())
    }

    /// Consume into a string
    pub fn into_string(self) -> String
    {
	let mut output = match self.size_hint() {
	    (0, None) => String::new(),
	    (_, Some(x)) |
	    (x, None) => String::with_capacity(x),
	};
	self.consume(&mut output).unwrap();
	output
    }
}

pub trait HexStringIterExt<I>: Sized
{
    fn into_hex(self) -> HexStringIter<I>;
}

pub type HexStringSliceIter<'a> = HexStringIter<iter::Copied<slice::Iter<'a, u8>>>;

pub trait HexStringSliceIterExt
{
    fn hex(&self) -> HexStringSliceIter<'_>;
}

impl<S> HexStringSliceIterExt for S
where S: AsRef<[u8]>
{
    fn hex(&self) -> HexStringSliceIter<'_>
    {
	self.as_ref().iter().copied().into_hex()
    }
}

impl<I: IntoIterator<Item=u8>> HexStringIterExt<I::IntoIter> for I
{
    #[inline] fn into_hex(self) -> HexStringIter<I::IntoIter> {
	HexStringIter(self.into_iter(), [0u8; 2])
    }
}

impl<I: Iterator<Item = u8>> Iterator for HexStringIter<I>
{
    type Item = char;
    fn next(&mut self) -> Option<Self::Item>
    {
	match self.1 {
	    [_, 0] => {
		use std::io::Write;
		write!(&mut self.1[..], "{:02x}", self.0.next()?).unwrap();

		Some(mem::replace(&mut self.1[0], 0) as char)
	    },
	    [0, _] => Some(mem::replace(&mut self.1[1], 0) as char),
	    _ => unreachable!(),
	}
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
	let (l, h) = self.0.size_hint();

	(l * 2, h.map(|x| x*2))
    }
}

impl<I: Iterator<Item = u8> + ExactSizeIterator> ExactSizeIterator for HexStringIter<I>{}
impl<I: Iterator<Item = u8> + FusedIterator> FusedIterator for HexStringIter<I>{}

impl<I: Iterator<Item = u8>> From<HexStringIter<I>> for String
{
    fn from(from: HexStringIter<I>) -> Self
    {
	from.into_string()
    }
}

impl<I: Iterator<Item = u8> + Clone> fmt::Display for HexStringIter<I>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
	self.clone().consume(f)
    }
}

#[macro_export] macro_rules! prog1 {
    ($first:expr, $($rest:expr);+ $(;)?) => {
	($first, $( $rest ),+).0
    }
}
