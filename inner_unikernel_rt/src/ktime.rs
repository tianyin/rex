use crate::stub;

pub(crate) type ktime_t = i64;
pub(crate) type time64_t = i64;

#[inline(always)]
pub(crate) fn ktime_to_ns(kt: ktime_t) -> i64 {
    kt
}
