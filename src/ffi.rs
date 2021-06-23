//! Raw C interface bindings
//!
//! Low level bindings to create in-memory translators for the cipher stream API.
//! Intended to be linked to the C wrapper object `wrapper.c`.
use super::*;
use std::ptr;
use std::io::{
    self, Write,
};

use key::{
    Key,
    IV,
};

/*
#[derive(Debug, Clone, PartialEq, Eq, Hash, Copy, PartialOrd, Ord, Default)]
#[repr(C)]
pub struct CKey([u8; key::KEY_SIZE]);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Copy, PartialOrd, Ord, Default)]
#[repr(C)]
pub struct CIv([u8; key::IV_SIZE]);
 */

/// Non-encrypted wrapper
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct CPassthrough
{
    backing: *mut libc::FILE,
    key: key::Key,
    iv: key::IV,
    mode: CMode
}

/// A sink wrapper of `CPassthrough`.
//TODO: Create a Custom Stream in `wrapper.c` that allows creating a FILE* object with `fopencookie()` from this.
#[derive(Debug)]
#[repr(C)]
pub struct CSink
{
    sink: Sink<CPassthrough>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Copy)]
#[repr(C)]
pub enum CMode
{
    Encrypt,
    Decrypt,
}

mod interop;

mod error;
pub use error::*;

#[no_mangle] pub unsafe extern "C" fn cc20_gen_meta(file: *mut libc::FILE, key: *const Key, iv: *const IV, mode: CMode, output: *mut CPassthrough) -> i32
{
    no_unwind!({
	if file.is_null() {
	    return CErr::InvalidFile;
	}
	let key = nullchk!(move key);
	let iv = nullchk!(move iv);
	let write = CPassthrough {
	    backing: file,
	    key,
	    iv,
	    mode,
	};
	nullchk!(output);
	output.write(write);
	CErr::Success
    }).unwrap_or(CErr::Panic).into()
}

/// Create an encrypting `Sink` over a `FILE*` from this metadata struct.
#[no_mangle] pub unsafe extern "C"  fn cc20_gen_sink(meta: *const CPassthrough) -> *mut CSink
{
    no_unwind!({
	let meta = nullchk!(ref meta);
	
	let sink = CSink {
	    sink: match meta.mode {
		CMode::Encrypt => Sink::encrypt(meta.clone(), meta.key, meta.iv).map_err(|_| CErr::SslError).unwrap(),
		CMode::Decrypt => Sink::decrypt(meta.clone(), meta.key, meta.iv).map_err(|_| CErr::SslError).unwrap(),
	    },
	};
	
	interop::give(sink)
    }).unwrap_or(ptr::null_mut())
}
/// Create an encrypting `Sink` over a `FILE*` with these options.
#[no_mangle] pub unsafe extern "C" fn cc20_gen_sink_full(file: *mut libc::FILE, key: *const Key, iv: *const IV, mode: CMode) -> *mut CSink
{
    let meta = {
	// No need to `no_unwind` this, `cc20_gen_meta` already does it, and nothing else here can panic.
	let mut meta: std::mem::MaybeUninit<CPassthrough> = std::mem::MaybeUninit::uninit();
	match cc20_gen_meta(file, key, iv, mode, &mut meta as *mut _ as  *mut CPassthrough) {
	    0 => meta.assume_init(),
	    _ => return ptr::null_mut(),
	}
    };
    cc20_gen_sink(&meta as *const _)
}
/// Create a wrapper `FILE*` that acts as a `Sink` when written to.
#[no_mangle] pub unsafe extern "C" fn cc20_wrap(file: *mut libc::FILE, key: *const Key, iv: *const IV, mode: CMode) -> *mut libc::FILE
{
    // No need to `no_unwind` this, nothing here can panic.
    let csink = cc20_gen_sink_full(file, key, iv, mode);
    if csink.is_null() {
	return ptr::null_mut();
    }
    cc20_wrap_sink(csink)
}
/// Closes and frees the wrapper `sink`, and writes inner metadata struct to `meta`, if `file` is non-null.
#[no_mangle] pub unsafe extern "C" fn cc20_close_sink(sink: *mut CSink, meta: *mut CPassthrough) -> i32
{
    no_unwind!({
	let sink = interop::take(nullchk!(sink));
	if !meta.is_null() {
	    *meta = sink.sink.into_inner();
	}
	CErr::Success
    }).unwrap_or(CErr::Panic)
	.into()
}

/// Convert a `Sink` into a `FILE*`.
#[no_mangle] pub unsafe extern "C" fn cc20_wrap_sink(sink: *mut CSink) -> *mut libc::FILE
{
    todo!("Create a Custom Stream in `wrapper.c` that allows creating a FILE* object from `sink`.")
}

impl Write for CPassthrough
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
	match unsafe { libc::fwrite(buf.as_ptr() as *const _, 1, buf.len(), self.backing) } {
	    full if full == buf.len() => Ok(full),
	    _ if unsafe { libc::ferror(self.backing) == 1 } => {
		//unsafe { libc::clearerr(self.backing) };
		Err(io::Error::last_os_error())
	    },
	    0 if unsafe { libc::feof(self.backing) == 1 } => {		
		Ok(0)
	    },
	    x => Ok(x),
	}
    }
    fn flush(&mut self) -> io::Result<()> {
	match unsafe { libc::fflush(self.backing) } {
	    0 => Ok(()),
	    n => Err(io::Error::from_raw_os_error(n)),
	}
    }
}