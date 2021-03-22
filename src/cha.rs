
use openssl::{
    symm::{
	Cipher, Crypter, Mode,
    },
    error::ErrorStack,
};
use crate::key::{Key, IV};

pub const KEY_SIZE: usize = 32;
pub const IV_SIZE: usize = 12;

static NEW_CIPHER: fn() -> Cipher = Cipher::chacha20_poly1305;

#[inline] pub fn decrypter(key: impl AsRef<Key>, iv: impl AsRef<IV>) -> Result<Crypter, ErrorStack>
{
    Crypter::new(
	NEW_CIPHER(),
	Mode::Decrypt,
	key.as_ref().as_ref(),
	Some(iv.as_ref().as_ref())
    )
}
#[inline] pub fn encrypter(key: impl AsRef<Key>, iv: impl AsRef<IV>) -> Result<Crypter, ErrorStack>
{
    Crypter::new(
	NEW_CIPHER(),
	Mode::Encrypt,
	key.as_ref().as_ref(),
	Some(iv.as_ref().as_ref())
    )
}

/// Generate a random key and IV.
#[inline(always)] pub fn keygen() -> (Key, IV)
{
    (Key::new(), IV::new())
}
