//! FFI errors
use super::*;


#[macro_export] macro_rules! errchk {
    ($expr:expr) => {
	match CErr::from($expr) {
	    CErr::Success => (),
	    x => return x,
	}
    };
}

//TODO: Rework the error handling/reporting here. 
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Copy)]
#[repr(C)]
pub enum CErr
{
    Success = 0,
    InvalidFile,
    /// Unexpected null pointer
    NullPointer,
    /// Internal SSL error
    SslError,
    /// I/O error
    IO,

    Panic = -1,
}

impl CErr
{
    #[inline] pub fn is_error(&self) -> bool
    {
	*self != Self::Success
    }
    #[inline] pub fn is_success(&self) -> bool
    {
	*self == Self::Success
    }
}

impl Default for CErr
{
    #[inline]
    fn default() -> Self
    {
	Self::Success
    }
}

impl From<CErr> for i32
{
    fn from(from: CErr) -> Self
    {
	from as i32
    }
}

impl<T> From<CErr> for *mut T
{
    fn from(from: CErr) -> Self
    {
	if from.is_error() { ptr::null_mut() }
	else { panic!("invalid conversion of successful operation to non-null output pointer") }
    }
}


/// Null check a pointer. If it's not null, dereference it.
#[macro_export] macro_rules! nullchk {
    (move $ptr:expr) => {
	{
	    let ptr = $ptr;
	    if ptr.is_null() {
		return From::from(CErr::NullPointer);
	    } else {
		unsafe {
		    *ptr
		}
	    }
	}
    };
    (ref $ptr:expr) => {
	{
	    let ptr = $ptr;
	    if ptr.is_null() {
		return From::from(CErr::NullPointer);
	    } else {
		unsafe {
		    & *ptr
		}
	    }
	}
    };
    (ref mut $ptr:expr) => {
	{
	    let ptr = $ptr;
	    if ptr.is_null() {
		return From::from(CErr::NullPointer);
	    } else {
		unsafe {
		    &mut *ptr
		}
	    }
	}
    };
    
    ($ptr:expr) => {
	{
	    let ptr = $ptr;
	    if ptr.is_null() {
		return From::from(CErr::NullPointer);
	    } else {
		ptr
	    }
	}
    }
}
