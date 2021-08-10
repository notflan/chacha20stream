#![allow(dead_code)]

use super::*;
use key::*;

use std::io::{self, Write};
use std::fmt;
use openssl::{
    symm::Crypter,
    error::ErrorStack,
};

/// Size of the in-structure buffer
#[cfg(feature="smallvec")]
pub const BUFFER_SIZE: usize = 32;

#[cfg(feature="smallvec")]
type BufferVec = smallvec::SmallVec<[u8; BUFFER_SIZE]>;
#[cfg(not(feature="smallvec"))]
type BufferVec = Vec<u8>;

pub type Error = ErrorStack;

/// ChaCha Sink
///
/// # Encryption
/// To create an encrypting wrapper stream:
/// ```
/// # use chacha20stream::Sink;
/// # use std::io::Write;
/// # let (key, iv) = chacha20stream::keygen();
/// # let mut backing_stream = Vec::new();
/// let mut stream = Sink::encrypt(&mut backing_stream, key, iv).expect("Failed to create encryptor");
/// /* do work with `stream` */
///
/// // It is recommended to `flush` the stream to clear out any remaining data in the internal transformation buffer.
/// stream.flush().unwrap();
/// ```
///
/// # Decryption
/// To create a decrypting wrapper stream:
/// ```
/// # use chacha20stream::Sink;
/// # use std::io::Write;
/// # let (key, iv) = chacha20stream::keygen();
/// # let mut backing_stream = Vec::new();
/// let mut stream = Sink::decrypt(&mut backing_stream, key, iv).expect("Failed to create decryptor");
/// /* do work with `stream` */
///
/// // It is recommended to `flush` the stream to clear out any remaining data in the internal transformation buffer.
/// stream.flush().unwrap();
/// ```
///
/// # Note
/// When writing, a temporary buffer stored in the structure is used. This buffer is **not** cleared after a write, for efficiency reasons. This may leave sensitive information in the buffer after the write operation.
/// The `flush()` implementation *does* clear this buffer.
/// You can use the `prune()` function to zero out this buffer manually too.
//#[derive(Debug)]
pub struct Sink<W: ?Sized>
{
    crypter: Crypter, // for chacha, finalize does nothing it seems. we can also call it multiple times.
    buffer: BufferVec, // used to buffer the operation

    stream: W,
}

/// TODO: Document
//#[derive(Debug)]
pub struct Source<R>
{
    crypter: Crypter, 
    #[cfg(not(feature="reuse-buffer"))] buffer: BufferVec, // When `reuse-buffer` is enabled, this isn't needed. We re-use the output buffer for the initial read of untransformed data from `stream` and the actual transformation of the read bytes.
    
    stream: R
}

impl<W: ?Sized+ fmt::Debug> fmt::Debug for Sink<W>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
	write!(f, "Sink({:?}, ({} buffer cap))", &self.stream, self.buffer.capacity())
    }
}

impl<W: ?Sized> Sink<W>
where W: Write
{

    /// The crypter of this instance
    #[inline] pub fn crypter(&self) -> &Crypter
    {
	&self.crypter
    }
    
    /// The crypter of this instance
    #[inline] pub fn crypter_mut(&mut self) -> &mut Crypter
    {
	&mut self.crypter
    }

    /// The inner stream
    #[inline] pub fn inner(&self) -> &W
    {
	&self.stream
    }
    
    /// The inner stream
    #[inline] pub fn inner_mut(&mut self) -> &mut W
    {
	&mut self.stream
    }

    /// Perform the cipher transform on this input to the inner buffer, returning the number of bytes updated.
    fn transform(&mut self, buf: &[u8]) -> Result<usize, ErrorStack>
    {
	if buf.len() > self.buffer.len() {
	    self.buffer.resize(buf.len(), 0);
	}
	
	let n = self.crypter.update(&buf[..], &mut self.buffer[..])?;
	let _f = self.crypter.finalize(&mut self.buffer[..n])?; // I don't know if this is needed.
	debug_assert_eq!(_f, 0);

	Ok(n)
    }

    /// Clear the internal buffer while keeping it allocated for further use.
    ///
    /// This does not affect operations at all, all it does is 0 out the left-over temporary buffer from the last operation(s).
    #[inline] 
    pub fn prune(&mut self)
    {
	#[cfg(feature="explicit_clear")]
	{
	    bytes::explicit_prune(&mut self.buffer[..]);
	    return;
	}
	#[cfg(not(feature="explicit_clear"))] 
	unsafe {
	    std::ptr::write_bytes(self.buffer.as_mut_ptr(), 0, self.buffer.len());
	}
    }
}

impl<W> Sink<W>
where W: Write
{
    /// Create a new Chacha Sink stream wrapper
    #[inline] fn new(stream: W, crypter: Crypter) -> Self
    {
	Self{stream, crypter, buffer: BufferVec::new()}
    }

    /// Create an encrypting Chacha Sink stream wrapper
    pub fn encrypt(stream: W, key: Key, iv: IV) -> Result<Self, Error>
    {
	Ok(Self::new(stream, cha::encrypter(key, iv)?))
    }
    
    /// Create a decrypting Chacha Sink stream wrapper
    pub fn decrypt(stream: W, key: Key, iv: IV) -> Result<Self, Error>
    {
	Ok(Self::new(stream, cha::decrypter(key, iv)?))
    }
    

    /// Consume into the inner stream
    #[inline] pub fn into_inner(self) -> W
    {
	self.stream
    }

    /// Consume into the inner stream and crypter
    #[inline] pub fn into_parts(self) -> (W, Crypter)
    {
	(self.stream, self.crypter)
    }
    

}

impl<W: ?Sized + Write> Write for Sink<W>
{
    #[inline] fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
	let n = self.transform(buf)?;

	self.stream.write(&self.buffer[..n])
	    
    }
    #[inline] fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
	let n = self.transform(buf)?;

	self.stream.write_all(&self.buffer[..n])
    }
    #[inline] fn flush(&mut self) -> io::Result<()> {
	#[cfg(feature="explicit_clear")] self.prune();
	self.buffer.clear();
	
	self.stream.flush()
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    const INPUT: &'static str = "Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!";

    fn enc_stream(input: impl AsRef<[u8]>, key: Key, iv: IV) -> Sink<Vec<u8>>
    {
	let enc_buffer = Vec::new();
	let input = input.as_ref();
	
	eprintln!("(enc) Key: {}, IV: {}, Input: ({}, {})", key, iv, input.len(), input.hex());
	
	let mut stream = Sink::encrypt(enc_buffer, key, iv).expect("sink::enc");
	assert_eq!(stream.write(input).unwrap(), input.len());
	stream.flush().unwrap();
	
	eprintln!("Output encrypted: {}", stream.inner().hex());

	stream
    }

    #[test]
    fn enc()
    {
	let (key, iv) = cha::keygen();

	eprintln!("Sink ends: {:?}", enc_stream(INPUT.as_bytes(), key, iv));
    }

    #[test]
    fn dec()
    {
	println!(">>> Sink's size with ref is {}", std::mem::size_of::<Sink<&mut Vec<u8>>>());
	let (key, iv) = cha::keygen();
	eprintln!("Input unencrypted: {}", INPUT.hex());

	let input = enc_stream(INPUT.as_bytes(), key.clone(), iv.clone()).into_inner();

	let mut dec_buffer = Vec::new();
	{
	    let mut stream = Sink::decrypt(&mut dec_buffer, key, iv).expect("sink::dec");

	    stream.write_all(&input[..]).unwrap();
	    stream.flush().unwrap();
	    
	    eprintln!("Output decrypted: {}", stream.inner().hex());
	}
	assert_eq!(&dec_buffer[..], INPUT.as_bytes());
    }

    /// Checks if explicit clear is actually clearing.
    #[cfg(feature="explicit_clear")] 
    #[test]
    fn remainder()
    {
	let mut dec_buffer = Vec::new();

	let (buf, off, _s) = {
	    let (key, iv) = cha::keygen();

	    let input = enc_stream(INPUT.as_bytes(), key.clone(), iv.clone()).into_inner();

	    {
		let mut stream = Sink::decrypt(&mut dec_buffer, key, iv).expect("sink::rem");

		stream.write_all(&input[..]).unwrap();

		let by = stream.buffer[0];
		//stream.prune();
		stream.flush().unwrap();
		(by, (stream.buffer.as_ptr() as u64), stream)
	    }
	};

	// Check to see if the buffer remains in our process's memory.
	use std::fs::OpenOptions;
	use std::io::{Seek, SeekFrom, Read};
	let mut file = OpenOptions::new().read(true).open("/proc/self/mem").unwrap();

	file.seek(SeekFrom::Start(off)).unwrap();
	let mut chk = [0u8; 10];
	file.read_exact(&mut chk).unwrap();
	assert!(buf != chk[0]);
    }
}


