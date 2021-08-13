//! Asyncronous `AsyncRead` wrapper.
use super::*;

/// TODO: Document
//#[derive(Debug)]
#[pin_project]
pub struct Source<R>
{
    #[pin] stream: R,
    
    crypter: Crypter, // for chacha, finalize does nothing it seems. we can also call it multiple times.

    buffer: BufferVec, // used to buffer the operation (ad-hoc-buffer wouldn't work for async operations as the buffer may need to be saved over yields.)
}
