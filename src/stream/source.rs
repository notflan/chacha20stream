//! Syncronous stream `Read` componant.
use super::*;

/// TODO: Document
//#[derive(Debug)]
pub struct Source<R: ?Sized>
{
    crypter: Crypter,
    #[cfg(not(feature="reuse-buffer"))] buffer: BufferVec, // When `reuse-buffer` is enabled, this isn't needed. We re-use the output buffer for the initial read of untransformed data from `stream` and the actual transformation of the read bytes.
    
    stream: R
}


impl<R: ?Sized+ fmt::Debug> fmt::Debug for Source<R>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
	#[cfg(feature="reuse-buffer")] 
	return write!(f, "Source({:?}, (unbounded buffer cap))", &self.stream);
	#[cfg(not(feature="reuse-buffer"))]
	return write!(f, "Source({:?}, ({} buffer cap))", &self.stream, self.buffer.capacity());
    }
}

impl<R: ?Sized> Source<R>
where R: Read
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
    #[inline] pub fn inner(&self) -> &R
    {
	&self.stream
    }
    
    /// The inner stream
    #[inline] pub fn inner_mut(&mut self) -> &mut R
    {
	&mut self.stream
    }

    #[cfg(not(feature="reuse-buffer"))]
    /// Grow the inner buffer to fix this size, if needed.
    fn grow_to_fit(&mut self, sz: usize)
    {
	if sz > self.buffer.len() {
	    self.buffer.resize(sz, 0);
	}
    }
    
    #[cfg(not(feature="reuse-buffer"))]
    /// Perform the cipher transform on this input to the inner buffer, returning the number of bytes updated.
    fn transform(&mut self, bufsz: usize, output: &mut [u8]) -> Result<usize, ErrorStack>
    {
	//self.grow_to_fix(output.len());
	//let bufsz = self.stream.read(&mut self.buffer[..bufsz])?;
	let n = self.crypter.update(&self.buffer[..bufsz], &mut output[..])?;
	let _f = self.crypter.finalize(&mut output[..n])?;
	debug_assert_eq!(_f, 0);

	Ok(n)
	/*
	    if buf.len() > self.buffer.len() {
	    self.buffer.resize(buf.len(), 0);
    }
	    
	    let n = self.crypter.update(&buf[..], &mut self.buffer[..])?;
	    let _f = self.crypter.finalize(&mut self.buffer[..n])?; // I don't know if this is needed.
	    debug_assert_eq!(_f, 0);

	    Ok(n)*/
    }

    #[cfg(not(feature="reuse-buffer"))] 
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

impl<R: ?Sized> Read for Source<R>
where R: Read
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
	(#[cfg(feature="reuse-buffer")] {
	    todo!()
	},
	 #[cfg(not(feature="reuse-buffer"))] {
	     self.grow_to_fit(buf.len());
	     let read = self.stream.read(&mut self.buffer[..buf.len()])?;
	     Ok(self.transform(read, &mut buf[..read])?)
	 },).0
    }
}
