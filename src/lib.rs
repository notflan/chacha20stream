#![cfg_attr(nightly, feature(asm))] 

#![allow(dead_code)]

//extern crate test;

#[cfg(feature="async")] 
#[macro_use] extern crate pin_project;

#[macro_use] mod ext; #[allow(unused_imports)] use ext::*;

pub mod key;
mod cha;
mod stream;
mod bytes;

#[cfg(feature="async")] mod stream_async;
#[cfg(feature="async")] pub use stream_async::Sink as AsyncSink;

pub use stream::Sink;
pub use key::{
    Key, IV,
};

pub use cha::keygen;
