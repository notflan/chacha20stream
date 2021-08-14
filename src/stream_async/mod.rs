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

/// Size of the in-structure buffer
#[cfg(feature="smallvec")]
pub const BUFFER_SIZE: usize = 32;

#[cfg(feature="smallvec")]
type BufferVec = smallvec::SmallVec<[u8; BUFFER_SIZE]>;
#[cfg(not(feature="smallvec"))]
type BufferVec = Vec<u8>;

pub type Error = ErrorStack;

pub mod sink;
pub use sink::Sink;

pub mod source;
pub use source::Source;

#[cfg(test)]
mod test
{
    use tokio::prelude::*;

    #[tokio::test]
    async fn async_source_enc_dec()
    {
	use crate::ext::*;
	const INPUT: &'static [u8] = b"Hello world!";
	let (key, iv) = crate::cha::keygen();

	println!("Input: {}", INPUT.hex());
	let mut enc = super::Source::encrypt(&INPUT[..], key, iv).expect("Failed to create encryptor");
	let mut enc_out = Vec::with_capacity(INPUT.len());
	tokio::io::copy(&mut enc, &mut enc_out).await.expect("Failed to copy encrypted output");

	println!("(enc) output: {}", enc_out.hex());

	let mut dec = super::Source::decrypt(&enc_out[..], key, iv).expect("Failed to create decryptor");
	let mut dec_out = Vec::with_capacity(INPUT.len());
	tokio::io::copy(&mut dec, &mut dec_out).await.expect("Failed to copy decrypted output");

	println!("(dec) output: {}", dec_out.hex());

	assert_eq!(&dec_out[..], INPUT);
    }
    
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

