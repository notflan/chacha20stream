//! FFI errors
use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Copy)]
#[repr(C)]
pub enum CErr
{
    Success = 0,
    InvalidFile,
    /// Unexpected null pointer
    NullPointer,

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

/// Null check a pointer. If it's not null, dereference it.
#[macro_export] macro_rules! nullchk {
    (<- $ptr:expr) => {
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
    ($ptr:expr) => {
	{
	    if $ptr.is_null() {
		return From::from(CErr::NullPointer);
	    }
	    ()
	}
    }
}
