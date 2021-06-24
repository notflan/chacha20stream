#![allow(non_camel_case_types)]

use super::*;
use std::{
    slice,
};
use libc::{
    c_void,
    c_char,
    c_int,
    off64_t,
    ssize_t,
    size_t,
    
    FILE,
};

/// Configuration for the `FILE*` wrapper
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Copy)]
#[repr(C)]
pub struct Config
{
    pub keep_alive: c_int,
}

impl Default for Config
{
    #[inline]
    fn default() -> Self
    {
	Self {
	    keep_alive: 0,
	}
    }
}


type cookie_read_function_t = Option<extern "C" fn (cookie: *mut c_void, buf: *mut c_char , size: size_t) -> ssize_t>;
type cookie_write_function_t = Option<extern "C" fn (cookie: *mut c_void, buf: *const c_char, size: size_t) -> ssize_t>;
type cookie_seek_function_t = Option<extern "C" fn (cookie: *mut c_void, offset: *mut off64_t, whence: c_int) -> c_int>;
type cookie_close_function_t = Option<extern "C" fn (cookie: *mut c_void) -> c_int>;

const _: [u8; 8] = [0u8; std::mem::size_of::<cookie_read_function_t>()];

// `fopencookie` API
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
struct cookie_io_functions_t
{
    read: cookie_read_function_t,
    write: cookie_write_function_t,
    seek: cookie_seek_function_t,
    close: cookie_close_function_t,
}

extern "C" {
    fn fopencookie(cookie: *mut c_void, mode: *const c_char, funcs: cookie_io_functions_t) -> *mut FILE;
}

#[inline(always)] unsafe fn ref_cookie<'a>(cookie: *mut c_void) -> Option<&'a mut CSink>
{
    if cookie.is_null() {
	None
    } else {
	Some(&mut *(cookie as *mut CSink))
    }
}

macro_rules! unwrap {
    (? $expr:expr, $or:expr) => {
	if let Some(val) = $expr {
	    val
	} else {
	    return $or;
	}
    };
}

extern "C" fn read(_cookie: *mut c_void, _buf: *mut c_char, _size: size_t) -> ssize_t
{
    -1
}
extern "C" fn write(cookie: *mut c_void, buf: *const c_char, size: size_t) -> ssize_t
{
    //Remember: Cannot return -1 here
    no_unwind!({
	if buf.is_null() {
	    return 0;
	}
	let sink = unwrap!(? unsafe { ref_cookie(cookie) }, 0);
	let buf = unsafe { slice::from_raw_parts(buf as *const u8, size) };
	
	match sink.sink.write(buf) {
	    Ok(n) if n < ssize_t::MAX as usize => n as ssize_t,
	    Err(_er) => {
		//sink.last_err_code = 
		//sink.last_err = Some(
		0
	    },
	    _ => {
		// TODO
		// Write succeeded, but wrote more than `isize::MAX`.
		0
	    },
	}
    }).unwrap_or(0)
}
extern "C" fn seek(_cookie: *mut c_void, _offset: *mut off64_t, _whence: c_int) -> c_int
{
    -1
}
extern "C" fn close(cookie: *mut c_void) -> c_int
{
    let sink = if cookie.is_null() {
	return -1;
    } else {
	cookie as *mut CSink
    };
    let CSink { sink, cookie_settings } = unsafe { interop::take(sink) };
    let mut meta = sink.into_inner();
    if cookie_settings.keep_alive == 0 && !meta.backing.is_null() {
	unsafe {  (libc::fclose(meta.backing), meta.backing = ptr::null_mut()).0 }
    } else {
	0
    }
}

#[inline(always)] pub unsafe fn create(raw_sink: *mut CSink) -> *mut FILE
{
    fopencookie(raw_sink as *mut c_void, b"wb\0" as *const u8 as *const c_char, cookie_io_functions_t {
	read: Some(read),
	write: Some(write),
	seek: Some(seek),
	close: Some(close),
    })
}
