use super::*;
use libc::{c_void, FILE};

//TODO: Remove `wrapper.c`, implement it in Rust here

//FILE* _cc20c_create(cc20_sink_t* restrict sink)
extern "C" {
    fn _cc20c_create(sink: *mut c_void) -> *mut FILE;
}

#[inline(always)] pub unsafe fn create(raw_sink: *mut CSink) -> *mut FILE
{
    _cc20c_create(raw_sink as *mut c_void)
}
