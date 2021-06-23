
#[macro_export] macro_rules! no_unwind {
    ($expr:expr) => {
	::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(move || $expr)).ok()
    };
    (ref $expr:expr) => {
	::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(|| $expr)).ok()
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
