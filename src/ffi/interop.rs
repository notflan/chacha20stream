use super::*;

#[macro_export] macro_rules! no_unwind {
    ($expr:expr) => {
	::std::panic::catch_unwind(move || $expr).ok()
    };
}

/// Expose an opaque pointer to FFI
#[inline] pub fn give<T>(val: T) -> *mut T
{
    Box::into_raw(Box::new(val))
}

/// Take a value back from an opaque FFI pointer
///
/// # Panics
/// If the pointer is `null`.
#[inline] pub unsafe fn take<T>(val: *mut T) -> T
{
    if val.is_null() {
	panic!("null value in opaque take");
    }
    *Box::from_raw(val)
}
