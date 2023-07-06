use crate::bindings::linux::kernel::xdp_buff;
use crate::stub;

pub fn bpf_xdp_adjust_head(xdp: &mut xdp_buff, offset: i32) -> i32 {
    let helper: extern "C" fn(*mut xdp_buff, i32) -> i32 =
        unsafe { core::mem::transmute(stub::bpf_xdp_adjust_head_addr()) };
    helper(xdp, offset)
}

pub fn bpf_xdp_adjust_tail(xdp: &mut xdp_buff, offset: i32) -> i32 {
    let helper: extern "C" fn(*mut xdp_buff, i32) -> i32 =
        unsafe { core::mem::transmute(stub::bpf_xdp_adjust_tail_addr()) };
    helper(xdp, offset)
}
