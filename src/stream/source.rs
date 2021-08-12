//! Syncronous stream `Read` componant.
use super::*;

/// How buffers are used.
pub trait BufferKind : private::Sealed
{
    type InternalBuffer;

    fn create_buffer(cap: usize) -> Self::InternalBuffer;

    fn buffer_len<R: ?Sized>(source: &Source<R, Self>) -> usize;
    fn buffer_cap<R: ?Sized>(source: &Source<R, Self>) -> usize;

    fn buffer_bytes_mut(source: &mut Self::InternalBuffer) -> &'_ mut [u8];
    fn buffer_bytes(source: &Self::InternalBuffer) -> &'_ [u8];

    fn buffer_resize<R: ?Sized>(source: &mut Source<R, Self>, to: usize);
}

/// Use struct-internal buffer for `Read`s
#[derive(Debug)]
pub struct UseBufferInternal;
/// Reuse the output buffer for `Read`s
#[derive(Debug)]
pub struct UseBufferExternal;

impl private::Sealed for UseBufferInternal{}
impl BufferKind for UseBufferInternal
{
    type InternalBuffer = BufferVec;

    #[inline] fn create_buffer(cap: usize) -> Self::InternalBuffer {
	if cap == 0 {
	    BufferVec::new()
	} else {
	    BufferVec::with_capacity(cap)
	}
    }
    
    #[inline(always)] fn buffer_cap<R: ?Sized>(source: &Source<R, Self>) -> usize {
	source.buffer.capacity()
    }
    #[inline(always)] fn buffer_len<R: ?Sized>(source: &Source<R, Self>) -> usize {
	source.buffer.len()
    }
    
    #[inline(always)] fn buffer_bytes_mut(source: &mut Self::InternalBuffer) -> &'_ mut [u8]
    {
	&mut source[..]
    }
    #[inline(always)] fn buffer_bytes(source: &Self::InternalBuffer) -> &'_ [u8]
    {
	&source[..]
    }

    #[inline(always)] fn buffer_resize<R: ?Sized>(source: &mut Source<R, Self>, to: usize)
    {
	source.buffer.resize(to, 0);
    }
}
impl private::Sealed for UseBufferExternal{}
impl BufferKind for UseBufferExternal
{
    type InternalBuffer = ();

    // -- always used --
    
    #[inline(always)] fn create_buffer(_: usize) -> Self::InternalBuffer {
	()
    }
    #[inline(always)] fn buffer_cap<R: ?Sized>(_: &Source<R, Self>) -> usize {
	0
    }

    // -- conditional --
    
    #[cold]
    #[inline(never)] fn buffer_len<R: ?Sized>(_: &Source<R, Self>) -> usize {
	panic!("Phantom buffer length cannot be checked")
    }
    #[cold]
    #[inline(never)] fn buffer_bytes_mut(_: &mut Self::InternalBuffer) -> &'_ mut [u8]
    {
	panic!("Cannot mutref non-existent ibuf.")
    }
    #[cold]
    #[inline(never)] fn buffer_bytes(_: &Self::InternalBuffer) -> &'_ [u8]
    {    
	panic!("Cannot ref non-existent ibuf.")
    }
    #[cold]
    #[inline(never)] fn buffer_resize<R: ?Sized>(_: &mut Source<R, Self>, _: usize)
    {
	panic!("Cannot resize non-existent ibuf.")
    }
}

#[cfg(not(feature="reuse-buffer"))] 
pub type DefaultBuffer = UseBufferInternal;
#[cfg(feature="reuse-buffer")] 
pub type DefaultBuffer = UseBufferExternal;

/// TODO: Document
//#[derive(Debug)]
pub struct Source<R: ?Sized, Buffer: ?Sized + BufferKind = DefaultBuffer>
{
    crypter: Crypter,
    buffer: Buffer::InternalBuffer, // When `reuse-buffer` is enabled, this isn't needed. We re-use the output buffer for the initial read of untransformed data from `stream` and the actual transformation of the read bytes.
    
    stream: R
}

impl<R: ?Sized+ fmt::Debug, K: ?Sized + BufferKind> fmt::Debug for Source<R, K>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
	use std::any::type_name;
	write!(f, "Source<Wraps: {}, BufferKind: {}>", type_name::<R>(), type_name::<K>())?;
	match K::buffer_cap(self) {
	    0 => write!(f, "({:?}, (unbounded buffer cap))", &self.stream),
	    cap => write!(f, "({:?}, ({} buffer cap))", &self.stream, cap), 
	}
    }
}

impl<R: ?Sized, K: ?Sized + BufferKind> Source<R, K>
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

    /// Grow the inner buffer to fix this size, if needed.
    fn grow_to_fit(&mut self, sz: usize)
    {
	if sz > K::buffer_len(self) {
	    K::buffer_resize(self, sz);
	}
    }
    
    /// Perform the cipher transform on this input to the inner buffer, returning the number of bytes updated.
    fn transform(&mut self, bufsz: usize, output: &mut [u8]) -> Result<usize, ErrorStack>
    {
	//self.grow_to_fix(output.len());
	//let bufsz = self.stream.read(&mut self.buffer[..bufsz])?;
	let n = self.crypter.update(& K::buffer_bytes(&self.buffer)[..bufsz], &mut output[..])?;
	let _f = self.crypter.finalize(&mut output[..n])?;
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
	    bytes::explicit_prune(K::buffer_bytes_mut(self));
	    return;
	}
	#[cfg(not(feature="explicit_clear"))] 
	unsafe {
	    std::ptr::write_bytes(K::buffer_bytes_mut(&mut self.buffer).as_mut_ptr(), 0, K::buffer_len(self));
	}
    }

}

impl<R> Source<R, UseBufferExternal>
{
    /// Convert this instance to use external buffer (instead of internal.)
    pub fn with_reused_buffer(self) -> Source<R, UseBufferInternal>
    {
	Source {
	    buffer: UseBufferInternal::create_buffer(UseBufferExternal::buffer_cap(&self)),
	    crypter: self.crypter,
	    stream: self.stream,
	}
    }
}

impl<R> Source<R, UseBufferInternal>
{
    /// Convert this instance to use external buffer (instead of internal.)
    pub fn with_reused_buffer(self) -> Source<R, UseBufferExternal>
    {
	Source {
	    buffer: UseBufferExternal::create_buffer(UseBufferInternal::buffer_cap(&self)),
	    crypter: self.crypter,
	    stream: self.stream,
	}
    }
}

impl<R: ?Sized, K: ?Sized + BufferKind> Read for Source<R, K>
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
