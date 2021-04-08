# chacha20_poly1305 stream wrapper
Contains a writable stream that wraps another, applying the chacha20_poly1305 cipher to the input before writing for either encryption or decryption.

## Usage
Encrypt and decrypt message with an in-memory buffer.
```rust
// Generate random key and IV for the operations.
let (key, iv) = chacha20stream::keygen();

let input = "Hello world!";

// Encryption into a new `Vec<u8>`.
let mut sink = Sink::encrypt(Vec::new(), key, iv).expect("Failed to create encryptor");
sink.write_all(input.as_bytes()).unwrap();
sink.flush().unwrap(); // `flush` also clears the in-memory buffer if there is left over data in it.

let output_encrypted = sink.into_inner();

// Decryption into a new `Vec<u8>`
let mut sink = Sink::decrypt(Vec::new(), key, iv).expect("Failed to create decryptor");
sink.write_all(&output_encrypted[..]).unwrap();
sink.flush().unwrap();

let output_decrypted = sink.into_inner();

assert_eq!(&output_decrypted[..], input.as_bytes());
```

# Features
* **smallvec** - Use `smallvec` crate to store the in-memory buffer on the stack if it's smalle enough (*default*)
* **async** - Enable `AsyncSink` with Tokio *0.2* `AsyncWrite`. The API is the same as for the regular `Sink`.
* **explicit_clear** - Explicitly clear in-memory buffer after operations.

# License
MIT
