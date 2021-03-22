#![cfg_attr(nightly, feature(asm))] 

#![allow(dead_code)]

//extern crate test;

#[macro_use] mod ext; #[allow(unused_imports)] use ext::*;

pub mod key;
mod cha;
mod stream;

pub use stream::Sink;
pub use key::{
    Key, IV,
};

pub use cha::keygen;
