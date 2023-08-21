use core::ffi::c_uchar;

#[repr(transparent)]
pub struct u16be(pub(crate) u16);

impl From<u16be> for u16 {
    // Required method
    fn from(value: u16be) -> Self {
        u16::from_be(value.0)
    }
}

pub trait FromCharBufSafe {
    fn from_char_buf_safe(buf: &[u8]) -> Option<&Self>;
}

macro_rules! from_char_buf_safe_impl {
    ($dest_ty:ident $($dest_tys:ident)*) => {
        impl FromCharBufSafe for $dest_ty {
            fn from_char_buf_safe(buf: &[u8]) -> Option<&$dest_ty> {
                if (buf.len() != core::mem::size_of::<$dest_ty>()) {
                    None
                } else {
                    unsafe { Some(core::mem::transmute(buf.as_ptr())) }
                }
            }
        }
        from_char_buf_safe_impl!($($dest_tys)*);
    };
    () => {};
}

from_char_buf_safe_impl!(u64 i64 u32 i32 u16 i16 u8 i8);

macro_rules! from_char_buf_safe_impl_arr {
    ($dest_ty:ident $($dest_tys:ident)*) => {
        impl<const N: usize> FromCharBufSafe for [$dest_ty; N] {
            fn from_char_buf_safe(buf: &[u8]) -> Option<&[$dest_ty; N]> {
                if (buf.len() != core::mem::size_of::<$dest_ty>() * N) {
                    None
                } else {
                    unsafe { Some(&*buf.as_ptr().cast::<[$dest_ty; N]>()) }
                }
            }
        }
        from_char_buf_safe_impl_arr!($($dest_tys)*);
    };
    () => {};
}

from_char_buf_safe_impl_arr!(u64 i64 u32 i32 u16 i16 u8 i8);

pub trait FromCharBufSafeMut {
    fn from_char_buf_safe_mut(buf: &[u8]) -> Option<&mut Self>;
}