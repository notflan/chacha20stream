/*!
# chacha20_poly1305 stream wrapper
Contains a writable stream that wraps another, applying the chacha20_poly1305 cipher to the input before writing for either encryption or decryption.

## Examples
Encrypt a message to an in-memory buffer.
```
# use chacha20stream::Sink;
# use std::io::Write;
// Generate random key and IV for the operations.
let (key, iv) = chacha20stream::keygen();

let input = "Hello world!";

let mut sink = Sink::encrypt(Vec::new(), key, iv).expect("Failed to create encryptor");
sink.write_all(input.as_bytes()).unwrap();
sink.flush().unwrap(); // `flush` also clears the in-memory buffer if there is left over data in it.

let output_encrypted = sink.into_inner();
```
Decrypting a message:
```
# use chacha20stream::{Sink, Key, IV};
# use std::io::{self, Write};
fn decrypt_message_to<W: Write + ?Sized>(output: &mut W, encrypted: &[u8], key: Key, iv: IV) -> io::Result<()>
{
	let mut sink = Sink::decrypt(output, key, iv)?;
	sink.write_all(&encrypted[..])?;
	sink.flush().unwrap(); // `flush` also clears the in-memory buffer if there is left over data in it.

	Ok(())
}
```

# Features
* **smallvec** - Use `smallvec` crate to store the in-memory buffer on the stack if it's smalle enough (*default*)
* **async** - Enable `AsyncSink` with tokio 0.2 `AsyncWrite`
* **explicit_clear** - Explicitly clear in-memory buffer after operations.
* **serde** - Enable `Key` and `IV` to be de/serialised with Serde.
*/

#![cfg_attr(nightly, feature(asm))] 

#![allow(dead_code)]

//extern crate test;

#[cfg(feature="async")] 
#[macro_use] extern crate pin_project;

#[macro_use] mod ext; #[allow(unused_imports)] use ext::*;

mod private
{
    /// This trait cannot be subtraited by downstream crates.
    pub trait Sealed{}
}

pub mod key;
mod cha;
mod stream;
mod bytes;

#[cfg(feature="async")] mod stream_async;
#[cfg(feature="async")] pub use stream_async::Sink as AsyncSink;
#[cfg(feature="async")] pub use stream_async::Source as AsyncSource;

pub use stream::Sink;
pub use stream::Source;
pub use key::{
    Key, IV,
};

pub use cha::keygen;

#[cfg(feature="ffi")] pub mod ffi;
