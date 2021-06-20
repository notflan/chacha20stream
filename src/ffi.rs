//! Raw C interface bindings
//!
//! Low level bindings to create in-memory translators for the cipher stream API.
//! Intended to be linked to the C wrapper object `wrapper.c`.
use super::*;
use std::ptr;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Copy, PartialOrd, Ord, Default)]
#[repr(C)]
struct CKey([u8; key::KEY_SIZE]);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Copy, PartialOrd, Ord, Default)]
#[repr(C)]
struct CIv([u8; key::IV_SIZE]);

/// Non-encrypted wrapper
#[derive(Debug)]
#[repr(C)]
struct CPassthrough
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
struct CSink
{
    sink: Sink<CPassthrough>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Copy)]
#[repr(C)]
enum CMode
{
    Encrypt,
    Decrypt,
}

mod interop;

mod error;
use error::*;

#[no_mangle] extern "C" fn cc20_gen_meta(file: *mut libc::FILE, key: *const CKey, iv: *const CIv, mode: CMode, output: *mut CPassthrough) -> i32
{
    no_unwind!({
	if file.is_null() {
	    return CErr::InvalidFile;
	}
	let key = nullchk!(<- key);
	let iv = nullchk!(<- iv);
	let write = CPassthrough {
	    backing: file,
	    key: key::Key::from_bytes(key.0),
	    iv: key::IV::from_bytes(iv.0),
	    mode,
	};
	unsafe {
	    nullchk!(output);
	    output.write(write);
	}
	CErr::Success
    }).unwrap_or(CErr::Panic).into()
}

/// Create an encrypting `Sink` over a `FILE*`.
#[no_mangle] extern "C" fn cc20_gen_sink(file: *mut libc::FILE, key: *const CKey, iv: *const CIv, mode: CMode) -> *mut CSink
{
    let meta = {
	// No need to `no_unwind` this, `cc20_gen_meta` already does it, and nothing else here can panic.
	let mut meta: std::mem::MaybeUninit<CPassthrough> = std::mem::MaybeUninit::uninit();
	match cc20_gen_meta(file, key, iv, mode, &mut meta as *mut _ as  *mut CPassthrough) {
	    0 => unsafe { meta.assume_init() },
	    _ => return ptr::null_mut(),
	}
    };
    no_unwind!({
	//TODO: Create CSink from `meta` (`CPassthrough`).
	let sink = CSink {
	    sink: match meta.mode {
		CMode::Encrypt => Sink::encrypt(meta, meta.key, meta.iv),
		CMode::Decrypt => Sink::decrypt(meta, meta.key, meta.iv),
	    },
	};
	interop::give(sink)
    }).unwrap_or(ptr::null_mut())
}
/// Create a wrapper `FILE*` that acts as a `Sink` when written to.
#[no_mangle] extern "C" fn cc20_wrap(file: *mut libc::FILE, key: *const CKey, iv: *const CIv, mode: CMode) -> *mut libc::FILE
{
    // No need to `no_unwind` this, nothing here can panic.
    let csink = cc20_gen_sink(file, key, iv, mode);
    if csink.is_null() {
	return ptr::null_mut();
    }
    cc20_wrap_sink(csink)
}
/// Closes the wrapper `sink`, and writes inner `FILE*` pointer to `file`, if `file` is non-null.
#[no_mangle] extern "C" fn cc20_close_sink(sink: *mut CSink, file: *mut *mut libc::FILE)
{
    todo!()
}

/// Convert a `Sink` into a `FILE*`.
#[no_mangle] extern "C" fn cc20_wrap_sink(sink: *mut CSink) -> *mut libc::FILE
{
    todo!("Create a Custom Stream in `wrapper.c` that allows creating a FILE* object from `sink`.")
}

//TODO: `impl io::Write for CPassthrough`...
