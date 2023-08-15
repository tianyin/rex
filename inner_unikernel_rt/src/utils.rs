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

impl<const N: usize> FromCharBufSafe for [u16; N] {
    fn from_char_buf_safe(buf: &[u8]) -> Option<&[u16; N]> {
        if (buf.len() != core::mem::size_of::<u16>() * N) {
            None
        } else {
            unsafe { Some(&*buf.as_ptr().cast::<[u16; N]>()) }
        }
    }
}
