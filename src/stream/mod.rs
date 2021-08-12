#![allow(dead_code)]

use super::*;
use key::*;

use std::io::{self, Write, Read};
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

pub mod sink;
pub mod source;

pub use sink::Sink;
pub use source::Source;

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
