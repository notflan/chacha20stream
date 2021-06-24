//! Raw C interface bindings
//!
//! Low level bindings to create in-memory translators for the cipher stream API.
//! Intended to be linked to the C wrapper object `wrapper.c`.
use super::*;
use std::ptr;
use std::ffi::c_void;
use std::io::{
    self, Write,
};

use key::{
    Key,
    IV,
};

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
#[derive(Debug)]
#[repr(C)]
pub struct CSink
{
    sink: Sink<CPassthrough>,

    cookie_settings: cookie::Config,
    //last_err: () //TODO: how to implement this?
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Copy)]
#[repr(C)]
pub enum CMode
{
    Encrypt,
    Decrypt,
}

mod interop;
mod cookie;

mod error;
pub use error::*;

#[no_mangle] pub unsafe extern "C" fn cc20_keygen(key: *mut Key, iv: *mut IV) -> CErr
{
    no_unwind!(ref {
	if !key.is_null() {
	    *key = Key::new();
	}
	if !iv.is_null() {
	    *iv = IV::new();
	}
	
	CErr::Success
    }).unwrap_or(CErr::Panic)
}

#[no_mangle] pub unsafe extern "C" fn cc20_write(ptr: *const c_void, bytes: *mut usize, sink: *mut CSink) -> CErr
{
    no_unwind!({
	let sink = nullchk!(ref mut sink);
	let nbytes = nullchk!(move bytes);
	
	let slice = if ptr.is_null() {
	    return CErr::NullPointer;
	} else {
	    std::slice::from_raw_parts(ptr as *const u8, nbytes)
	};
	match sink.sink.write(&slice[..]) {
	    Err(_) => return CErr::IO,
	    Ok(v) => *bytes = v,
	}
	CErr::Success
    })
	.unwrap_or(CErr::Panic)
}

#[no_mangle] pub unsafe extern "C" fn cc20_gen_meta(file: *mut libc::FILE, key: *const Key, iv: *const IV, mode: CMode, output: *mut CPassthrough) -> CErr
{
    no_unwind!({
	if file.is_null() {
	    return CErr::InvalidFile;
	}
	let key = if key.is_null() {
	    Key::new()
	} else {
	    *key
	};
	let iv = if iv.is_null() {
	    IV::new()
	} else {
	    *iv
	};
	let write = CPassthrough {
	    backing: file,
	    key,
	    iv,
	    mode,
	};
	nullchk!(output);
	output.write(write);
	CErr::Success
    }).unwrap_or(CErr::Panic)
}

/// Create an encrypting `Sink` over a `FILE*` from this metadata struct.
#[no_mangle] pub unsafe extern "C"  fn cc20_gen_sink(meta: *const CPassthrough, output: *mut *mut CSink) -> CErr
{
    no_unwind!({
	let meta = nullchk!(ref meta);
	let output = nullchk!(ref mut output);
	
	let sink = CSink {
	    sink: match meta.mode {
		CMode::Encrypt => Sink::encrypt(meta.clone(), meta.key, meta.iv).map_err(|_| CErr::SslError).unwrap(),
		CMode::Decrypt => Sink::decrypt(meta.clone(), meta.key, meta.iv).map_err(|_| CErr::SslError).unwrap(),
	    },
	    cookie_settings: Default::default(),
	};
	*output = interop::give(sink);
	CErr::Success
    }).unwrap_or(CErr::Panic)
}

/// Create an encrypting `Sink` over a `FILE*` with these options.
#[no_mangle] pub unsafe extern "C" fn cc20_gen_sink_full(file: *mut libc::FILE, key: *const Key, iv: *const IV, mode: CMode, output: *mut *mut CSink) -> CErr
{
    let meta = {
	// No need to `no_unwind` this, `cc20_gen_meta` already does it, and nothing else here can panic.
	let mut meta: std::mem::MaybeUninit<CPassthrough> = std::mem::MaybeUninit::uninit();
	match cc20_gen_meta(file, key, iv, mode, &mut meta as *mut _ as  *mut CPassthrough) {
	    CErr::Success => meta.assume_init(),
	    x => return x,
	}
    };
    cc20_gen_sink(&meta as *const _, output)
}

#[no_mangle] pub unsafe extern "C" fn cc20_gen(meta: *const CPassthrough, output: *mut *mut libc::FILE) -> CErr
{
    let mut sink: *mut CSink = ptr::null_mut();
    errchk!(cc20_gen_sink(meta, &mut sink as *mut *mut CSink));
    *output = cc20_wrap_sink(sink, ptr::null());
    CErr::Success
}

/// Create a wrapper `FILE*` that acts as a `Sink` when written to.
#[no_mangle] pub unsafe extern "C" fn cc20_wrap_full(file: *mut libc::FILE, key: *const Key, iv: *const IV, mode: CMode, output: &mut *mut libc::FILE) -> CErr
{
    // No need to `no_unwind` this, nothing here can panic.
    let mut csink: *mut CSink = ptr::null_mut();
    errchk!(cc20_gen_sink_full(file, key, iv, mode, &mut csink as *mut *mut CSink));
    *output = cc20_wrap_sink(csink, ptr::null());
    CErr::Success
}
/// Closes and frees the wrapper `sink`, and writes inner metadata struct to `meta`, if `file` is non-null.
#[no_mangle] pub unsafe extern "C" fn cc20_close_sink(sink: *mut CSink, meta: *mut CPassthrough) -> CErr
{
    no_unwind!({
	let sink = interop::take(nullchk!(sink));
	if !meta.is_null() {
	    *meta = sink.sink.into_inner();
	}
	CErr::Success
    }).unwrap_or(CErr::Panic)
}

/// Convert a `Sink` into a `FILE*` with specific config (if not `NULL`).
#[no_mangle] pub unsafe extern "C" fn cc20_wrap_sink(sink: *mut CSink, config: *const cookie::Config) -> *mut libc::FILE
{
    if sink.is_null() {
	return ptr::null_mut();
    }
    if !config.is_null() {
	let sink = &mut *sink;
	sink.cookie_settings = *config;
    }
    cookie::create(sink)
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
