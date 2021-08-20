//! Syncronous stream `Write` componant.
use super::*;

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
    pub(super) buffer: BufferVec, // used to buffer the operation

    stream: W,
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
    
    /// Create a sink from a stream and a crypter
    ///
    /// The counterpart to `into_parts()`.
    #[inline] pub fn from_parts(stream: W, crypter: Crypter) -> Self
    {
	Self::new(stream, crypter)
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
