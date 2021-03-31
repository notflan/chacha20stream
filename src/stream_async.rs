use super::*;
use key::*;

use std::io;
use tokio::io::AsyncWrite;
use std::{
    pin::Pin,
    task::{Context, Poll},
};

use std::fmt;
use openssl::{
    symm::Crypter,
    error::ErrorStack,
};

#[cfg(feature="smallvec")]
pub const BUFFER_SIZE: usize = 32;

#[cfg(feature="smallvec")]
type BufferVec = smallvec::SmallVec<[u8; BUFFER_SIZE]>;
#[cfg(not(feature="smallvec"))]
type BufferVec = Vec<u8>;

pub type Error = ErrorStack;

/// Async ChaCha Sink
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

//When implementing `poll`, we can check if buffer is empty on poll, and if it isn't, poll backing stream to write it. Then, clear buffer after `Poll::Ready` on backing stream's write.
impl<W: AsyncWrite> AsyncWrite for Sink<W>
{
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, io::Error>> {
	let this = self.project();
	if this.buffer.is_empty() {
	    transform(this.crypter, this.buffer, buf)?;
	}	
	let poll = this.stream.poll_write(cx, &this.buffer[..]);
	if poll.is_ready() {
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
