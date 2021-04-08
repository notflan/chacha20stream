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

#[cfg(test)]
mod test
{
    use tokio::prelude::*;
    #[tokio::test]
    async fn sink_sync()
    {
	let mut output = Vec::new();
	let input = "Hello world!";
	let (key, iv) = crate::cha::keygen();
	
	let encrypted = {
	    let mut sink = super::Sink::encrypt(&mut output, key, iv).expect("Sink::encrypt");
	    sink.write_all(input.as_bytes()).await.expect("Sink::write_all");
	    sink.flush().await.expect("Sink::flush");
	    sink.shutdown().await.expect("Sink::shutdown");

	    sink.into_inner().clone()
	};

	output.clear();
	let decrypted = {
	    let mut sink = super::Sink::decrypt(&mut output, key, iv).expect("Sink::decrypt");
	    sink.write_all(&encrypted[..]).await.expect("Sink::write_all");
	    
	    sink.flush().await.expect("Sink::flush");
	    sink.shutdown().await.expect("Sink::shutdown");

	    sink.into_inner().clone()
	};
	assert_eq!(&decrypted[..], input.as_bytes());
    }
    #[tokio::test]
    async fn sink_mem()
    {
	const BACKLOG: usize = 4;
	let (mut client, mut server) = tokio::io::duplex(BACKLOG);
	let (key, iv) = crate::cha::keygen();

	let input = "Hello!";

	let enctask = tokio::spawn(async move {
	    let mut sink = super::Sink::encrypt(&mut client, key, iv).expect("Sink::encrypt");
	    sink.write_all(input.as_bytes()).await.expect("Sink::write_all");
	    sink.flush().await.expect("Sink::flush");
	    sink.shutdown().await.expect("Sink::shutdown");

	    drop(client);
	});

	let (mut declient, mut deserver) = tokio::io::duplex(BACKLOG * 2);
	let dectask = tokio::spawn(async move {
	    
	    let mut sink = super::Sink::decrypt(&mut declient, key, iv).expect("Sink::encrypt");
	    tokio::io::copy(&mut server, &mut sink).await.expect("Copy to sink failed");
	    sink.flush().await.expect("Sink::flush");
	    sink.shutdown().await.expect("Sink::shutdown");
	});

	let (de, en) = tokio::join![dectask, enctask];
	
	de.expect("Dec task panic");
	en.expect("Enc task panic");
	
	let mut output = Vec::new();
	tokio::io::copy(&mut deserver, &mut output).await.expect("Copy into vec");

	println!("In: {}, Out: {}", String::from_utf8_lossy(&output[..]), input);
	assert_eq!(&output[..], input.as_bytes());
    }
    #[tokio::test]
    async fn sink_files()
    {
	let mut output = tokio::fs::File::from_std(tempfile::tempfile().unwrap());
	
	let input = "Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!";
	let (key, iv) = crate::cha::keygen();
	
	{
	    let mut sink = super::Sink::encrypt(&mut output, key, iv).expect("Sink::encrypt");
	    sink.write_all(input.as_bytes()).await.expect("Sink::write_all");
	    sink.flush().await.expect("Sink::flush");
	    sink.shutdown().await.expect("Sink::shutdown");
	}

	let mut encrypted = output;
	encrypted.seek(tokio::io::SeekFrom::Start(0)).await.unwrap();
	
	let mut output = tokio::fs::File::from_std(tempfile::tempfile().unwrap());
	{
	    let mut sink = super::Sink::decrypt(&mut output, key, iv).expect("Sink::decrypt");
	    tokio::io::copy(&mut encrypted, &mut sink).await.expect("Copy to sinl");
	    
	    sink.flush().await.expect("Sink::flush");
	    sink.shutdown().await.expect("Sink::shutdown");
	}
	let mut decrypted = output;

	let (r1, r2) = tokio::join![encrypted.sync_data(),
				    decrypted.sync_data()];
	r1.expect("enc sync");
	r2.expect("dec sync");

	let decrypted = {
	    decrypted.seek(tokio::io::SeekFrom::Start(0)).await.unwrap();

	    let mut output = vec![0u8; input.len()];
	    decrypted.read_exact(&mut output[..]).await.expect("Read decrypted");

	    output
	};
	
	assert_eq!(&decrypted[..], input.as_bytes());
    }
}

