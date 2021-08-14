//! Asyncronous `AsyncRead` wrapper.
use super::*;
use tokio::io::AsyncRead;

/// Asyncronous ChaCha source.
/// En/decrypts information from the source async reader.
///
/// This is the `Read` implementing counterpart to `AsyncSink`.
//#[derive(Debug)]
#[pin_project]
pub struct Source<R>
{
    #[pin] stream: R,
    
    crypter: Crypter, // for chacha, finalize does nothing it seems. we can also call it multiple times.

    buffer: BufferVec, // used to buffer the operation (ad-hoc-buffer wouldn't work for async operations as the buffer may need to be saved over yields.)
}

impl<R: fmt::Debug> fmt::Debug for Source<R>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
	write!(f, "Source({:?}, ({} buffer cap))", self.stream, self.buffer.capacity())
    }
}

/// Perform the cipher transform on the inner buffer, writing to the output buffer, returning the number of bytes updated.
fn transform(crypter: &mut Crypter, buf: &[u8], buffer: &mut [u8]) -> Result<usize, ErrorStack>
{
    //if buf.len() > self.buffer.len() {
    //buf.resize(buffer.len(), 0);
    //}
    
    let n = crypter.update(&buf[..], &mut buffer[..])?;
    let _f = crypter.finalize(&mut buffer[..n])?; // I don't know if this is needed.
    debug_assert_eq!(_f, 0);
    
    Ok(n)
}


impl<R: AsyncRead> Source<R>
{
    
    /// Create a new async Chacha Source stream wrapper
    #[inline] fn new(stream: R, crypter: Crypter) -> Self
    {
	Self{stream, crypter, buffer: BufferVec::new()}
    }

    /// Create an encrypting Chacha Source stream wrapper
    pub fn encrypt(stream: R, key: Key, iv: IV) -> Result<Self, Error>
    {
	Ok(Self::new(stream, cha::encrypter(key, iv)?))
    }
    
    /// Create a decrypting Chacha Source stream wrapper
    pub fn decrypt(stream: R, key: Key, iv: IV) -> Result<Self, Error>
    {
	Ok(Self::new(stream, cha::decrypter(key, iv)?))
    }
    

    /// Consume into the inner stream
    #[inline] pub fn into_inner(self) -> R
    {
	self.stream
    }

    /// Consume into the inner stream and crypter
    #[inline] pub fn into_parts(self) -> (R, Crypter)
    {
	(self.stream, self.crypter)
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
    #[inline] pub fn inner(&self) -> &R
    {
	&self.stream
    }
    
    /// The inner stream
    #[inline] pub fn inner_mut(&mut self) -> &mut R
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
impl<R: AsyncRead> AsyncRead for Source<R>
{
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<usize, io::Error>> {
	let this = self.project();

	if this.buffer.is_empty() {
	    this.buffer.resize(buf.len(), 0);
	}
	debug_assert_eq!(buf.len(), this.buffer.len());
	
	let poll = this.stream.poll_read(cx, &mut this.buffer[..]);
	match poll {
	    Poll::Ready(Ok(read)) => {
		// Data read, perform transform.
		
		let n = transform(this.crypter, &this.buffer[..read], &mut buf[..read])?;
		debug_assert_eq!(n, read);
		
		// Reset buffer size to 0, so we know the next call will be on a new buffer, and we can resize it to the correct size again
		if cfg!(feature="explicit_clear") {
		    bytes::explicit_prune(&mut this.buffer[..]);
		} // XXX: Should we blank the buffer here? Or is just a `.clear()` alright?
		this.buffer.clear();
		Poll::Ready(Ok(n))
	    },
	    other => other
	}
    }
}

