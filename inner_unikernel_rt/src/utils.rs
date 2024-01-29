use core::ffi::c_int;

#[repr(transparent)]
pub struct u16be(pub(crate) u16);

impl From<u16be> for u16 {
    // Required method
    fn from(value: u16be) -> Self {
        u16::from_be(value.0)
    }
}

mod private {
    pub trait SafeTransmuteBase {}
}

pub trait SafeTransmute: private::SafeTransmuteBase {}

macro_rules! safe_transmute_impl {
    ($dest_ty:ident $($dest_tys:ident)*) => {
        impl private::SafeTransmuteBase for $dest_ty {}
        impl SafeTransmute for $dest_ty {}
        safe_transmute_impl!($($dest_tys)*);
    };
    () => {};
}

safe_transmute_impl!(u64 i64 u32 i32 u16 i16 u8 i8);

macro_rules! safe_transmute_impl_arr {
    ($dest_ty:ident $($dest_tys:ident)*) => {
        impl<const N: usize> private::SafeTransmuteBase for [$dest_ty; N] {}
        impl<const N: usize> SafeTransmute for [$dest_ty; N] {}
        safe_transmute_impl_arr!($($dest_tys)*);
    };
    () => {};
}

safe_transmute_impl_arr!(u64 i64 u32 i32 u16 i16 u8 i8);

#[inline(always)]
pub fn safe_transmute<T: SafeTransmute>() {}

/// A specialized Result for typical int return value in the kernel
///
/// To be used as the return type for functions that may fail.
///
/// Ref: linux/rust/kernel/error.rs
pub type Result = core::result::Result<c_int, c_int>;

/// Converts an integer as returned by a C kernel function to an error if it's
/// negative, and `Ok(val)` otherwise.
///
/// Ref: linux/rust/kernel/error.rs
// genetic specialization to Macro
#[macro_export]
macro_rules! to_result {
    ($retval:expr) => {{
        let val = $retval;
        if val < 0 {
            Err(val as i32)
        } else {
            Ok(val as i32)
        }
    }};
}

pub(crate) use to_result;
