use crate::linux::bpf::bpf_perf_event_value;
use crate::perf_event_kern::{bpf_perf_event_data_kern, bpf_user_pt_regs_t, perf_sample_data};
use crate::stub;

pub type pt_regs = crate::perf_event_kern::pt_regs;

pub trait prog_type {
    type ctx_ty;
    fn convert_ctx(&mut self, ctx: *const ()) -> Self::ctx_ty;
}

pub struct tracepoint {
    placeholder: u64,
}

impl tracepoint {
    pub const fn new() -> Self {
        Self { placeholder: 0 }
    }
}

impl prog_type for tracepoint {
    type ctx_ty = *const ();
    fn convert_ctx(&mut self, ctx: *const ()) -> Self::ctx_ty {
        ctx
    }
}

/**************************** perf_event ***********************************/

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
    let code: extern "C" fn(*const bpf_perf_event_data_kern, &bpf_perf_event_value, u32) -> i64 =
        unsafe { core::mem::transmute(ptr) };
    code(ctx.kptr, buf, buf_size as u32)
}

pub fn __bpf_get_stackid_pe<T>(ctx: &bpf_perf_event_data, map: &T, flags: u64) -> i64 {
    let ptr = stub::STUB_BPF_GET_STACKID_PE as *const ();
    let code: extern "C" fn(*const bpf_perf_event_data_kern, &T, u64) -> i64 =
        unsafe { core::mem::transmute(ptr) };
    code(ctx.kptr, map, flags)
}

#[macro_export]
macro_rules! PROG_DEF {
    ($f:ident, $n:ident, perf_event) => {
        #[no_mangle]
        #[link_section = "perf_event"]
        pub extern "C" fn $n(ctx: *const ()) -> i64 {
            // convert ctx
            let new_ctx = <perf_event>::new().convert_ctx(ctx);
            $f(&new_ctx).into()
        }
    };
}
