use std::ffi::c_void;
use std::ptr;

#[cfg(nightly)] 
#[inline(never)]
pub fn explicit_prune(buffer: &mut[u8]) {

    unsafe {
	ptr::write_bytes(buffer.as_mut_ptr() as *mut c_void, 0, buffer.len());
	if cfg!(target_arch = "x86_64") || cfg !(target_arch = "x86") {
            asm!("clflush [{}]", in(reg)buffer.as_mut_ptr());
	} else {
            asm!("")
	}
    }
}

#[cfg(not(nightly))]
#[inline] 
pub fn explicit_prune(buffer: &mut[u8]) {

    extern "C" {
	fn explicit_bzero(_: *mut c_void, _:usize);
    }
    
    unsafe {
	explicit_bzero(buffer.as_mut_ptr() as *mut c_void, buffer.len());
    }
}
