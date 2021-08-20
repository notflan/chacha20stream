//! Asyncronous `AsyncWrite` wrapper.
use super::*;

/// Async ChaCha Sink
///
/// # Encryption
/// To create an encrypting wrapper stream:
/// ```
/// # use chacha20stream::AsyncSink;
/// # use tokio::prelude::*;
/// # let (key, iv) = chacha20stream::keygen();
/// # let mut backing_stream = Vec::new();
/// # async move {
/// let mut stream = AsyncSink::encrypt(&mut backing_stream, key, iv).expect("Failed to create encryptor");
/// /* do work with `stream` */
///
/// // It is recommended to `flush` the stream to clear out any remaining data in the internal transformation buffer.
/// stream.flush().await.unwrap();
/// # };
/// ```
///
/// # Decryption
/// To create a decrypting wrapper stream:
/// ```
/// # use chacha20stream::AsyncSink;
/// # use tokio::prelude::*;
/// # let (key, iv) = chacha20stream::keygen();
/// # let mut backing_stream = Vec::new();
/// # async move {
/// let mut stream = AsyncSink::decrypt(&mut backing_stream, key, iv).expect("Failed to create decryptor");
/// /* do work with `stream` */
///
/// // It is recommended to `flush` the stream to clear out any remaining data in the internal transformation buffer.
/// stream.flush().await.unwrap();
/// # };
/// ```
///
///
/// # Note
/// When writing, a temporary buffer stored in the structure is used. This buffer is **not** cleared after a write, for efficiency reasons. This may leave sensitive information in the buffer after the write operation.
/// The `flush()` implementation *does* clear this buffer.
/// You can use the `prune()` function to zero out this buffer manually too.
//#[derive(Debug)]
#[pin_project]
pub struct Sink<W>
{
    #[pin] stream: W,
    
    crypter: Crypter, // for chacha, finalize does nothing it seems. we can also call it multiple times.

    buffer: BufferVec, // used to buffer the operation
}

impl<W: fmt::Debug> fmt::Debug for Sink<W>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
	write!(f, "Sink({:?}, ({} buffer cap))", self.stream, self.buffer.capacity())
    }
}

/// Perform the cipher transform on this input to the inner buffer, returning the number of bytes updated.
fn transform(crypter: &mut Crypter, buffer: &mut BufferVec, buf: &[u8]) -> Result<(), ErrorStack>
{
    //if buf.len() > self.buffer.len() {
    buffer.resize(buf.len(), 0);
    //}
    
    let n = crypter.update(&buf[..], &mut buffer[..])?;
    let _f = crypter.finalize(&mut buffer[..n])?; // I don't know if this is needed.
    debug_assert_eq!(_f, 0);

    buffer.resize(n, 0);
    Ok(())
}


impl<W: AsyncWrite> Sink<W>
{
    
    /// Create a new async Chacha Sink stream wrapper
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
	Self {
	    stream, crypter
	}
    }
    
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

//When implementing `poll`, we check if buffer is empty on poll, and if it isn't, poll backing stream to write it. Then, clear buffer after `Poll::Ready` on backing stream's write.
impl<W: AsyncWrite> AsyncWrite for Sink<W>
{
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, io::Error>> {
	let this = self.project();
	if this.buffer.is_empty() {
	    transform(this.crypter, this.buffer, buf)?;
	}
	let poll = this.stream.poll_write(cx, &this.buffer[..]);
	if poll.is_ready() {
	    #[cfg(feature="explicit_clear")]
	    bytes::explicit_prune(&mut this.buffer[..]);
	    this.buffer.clear();
	} 
	poll
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
	let this = self.project();

	let poll = this.stream.poll_flush(cx);
	if poll.is_ready() {
	    #[cfg(feature="explicit_clear")]
	    bytes::explicit_prune(&mut this.buffer[..]);
	    this.buffer.clear();
	}
	poll
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
	let this = self.project();

	let poll = this.stream.poll_shutdown(cx);
	if poll.is_ready() {
	    #[cfg(feature="explicit_clear")]
	    bytes::explicit_prune(&mut this.buffer[..]);
	    this.buffer.clear();
	}
	poll
    }
}
