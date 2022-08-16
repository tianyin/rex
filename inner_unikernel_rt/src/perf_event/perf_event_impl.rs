use super::binding::{bpf_perf_event_data_kern, bpf_user_pt_regs_t, perf_sample_data};
use crate::linux::bpf::bpf_perf_event_value;
use crate::prog_type::prog_type;
use crate::stub;

pub type pt_regs = super::binding::pt_regs;

#[derive(Debug, Copy, Clone)]
pub struct bpf_perf_event_data {
    pub regs: bpf_user_pt_regs_t,
    pub sample_period: u64,
    pub addr: u64,
    kptr: *const bpf_perf_event_data_kern,
}

pub struct perf_event {
    placeholder: u64, // not sure if we really need this
}

impl perf_event {
    pub const fn new() -> Self {
        Self { placeholder: 0 }
    }
}

impl prog_type for perf_event {
    type ctx_ty = bpf_perf_event_data;
    fn convert_ctx(&mut self, ctx: *const ()) -> Self::ctx_ty {
        let kern_ctx: &bpf_perf_event_data_kern = unsafe {
            let _kern_ctx: *const bpf_perf_event_data_kern = core::mem::transmute(ctx);
            &*_kern_ctx
        };

        let regs = unsafe { *kern_ctx.regs };
        let data: &perf_sample_data = unsafe { &*kern_ctx.data };
        let sample_period = data.period;
        let addr = data.addr;

        bpf_perf_event_data {
            regs: regs,
            sample_period: sample_period,
            addr: addr,
            kptr: kern_ctx,
        }
    }
}

pub fn __bpf_perf_prog_read_value(
    ctx: &bpf_perf_event_data,
    buf: &bpf_perf_event_value,
    buf_size: usize,
) -> i64 {
    let ptr = stub::STUB_BPF_PERF_PROG_READ_VALUE as *const ();
    let khelper: extern "C" fn(*const bpf_perf_event_data_kern, &bpf_perf_event_value, u32) -> i64 =
        unsafe { core::mem::transmute(ptr) };
    khelper(ctx.kptr, buf, buf_size as u32)
}

pub fn __bpf_get_stackid_pe<T>(ctx: &bpf_perf_event_data, map: &T, flags: u64) -> i64 {
    let ptr = stub::STUB_BPF_GET_STACKID_PE as *const ();
    let khelper: extern "C" fn(*const bpf_perf_event_data_kern, &T, u64) -> i64 =
        unsafe { core::mem::transmute(ptr) };
    khelper(ctx.kptr, map, flags)
}
