use super::binding::{
    bpf_perf_event_data_kern, bpf_user_pt_regs_t, perf_sample_data,
};
use crate::linux::bpf::{bpf_perf_event_value, BPF_PROG_TYPE_PERF_EVENT};
use crate::map::*;
use crate::prog_type::iu_prog;
use crate::stub;

pub type pt_regs = super::binding::pt_regs;

#[derive(Debug, Copy, Clone)]
pub struct bpf_perf_event_data {
    pub regs: bpf_user_pt_regs_t,
    pub sample_period: u64,
    pub addr: u64,
    kptr: *const bpf_perf_event_data_kern,
}

// First 3 fields should always be rtti, prog_fn, and name
//
// rtti should be u64, therefore after compiling the
// packed struct type rustc generates for LLVM does
// not additional padding after rtti
//
// prog_fn should have &Self as its first argument
//
// name is a &str
#[repr(C)]
pub struct perf_event<'a> {
    rtti: u64,
    prog: fn(&Self, &bpf_perf_event_data) -> u32,
    name: &'a str,
}

impl<'a> perf_event<'a> {
    crate::base_helper::base_helper_defs!();

    pub const fn new(
        f: fn(&perf_event<'a>, &bpf_perf_event_data) -> u32,
        nm: &'a str,
    ) -> perf_event<'a> {
        Self {
            rtti: BPF_PROG_TYPE_PERF_EVENT as u64,
            prog: f,
            name: nm,
        }
    }

    fn convert_ctx(&self, ctx: *const ()) -> bpf_perf_event_data {
        let kern_ctx: &bpf_perf_event_data_kern = unsafe {
            &*core::mem::transmute::<*const (), *const bpf_perf_event_data_kern>(
                ctx,
            )
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

    pub fn bpf_perf_prog_read_value(
        &self,
        ctx: &bpf_perf_event_data,
        buf: &bpf_perf_event_value,
    ) -> i64 {
        let ptr = unsafe { stub::bpf_perf_prog_read_value_addr() } as *const ();
        let helper: extern "C" fn(
            *const bpf_perf_event_data_kern,
            &bpf_perf_event_value,
            u32,
        ) -> i64 = unsafe { core::mem::transmute(ptr) };
        let size = core::mem::size_of::<bpf_perf_event_value>() as u32;
        helper(ctx.kptr, buf, size)
    }

    // TODO: needs to restrict the map to only BPF_MAP_TYPE_STACK_TRACE
    pub fn bpf_get_stackid_pe<K, V>(
        &self,
        ctx: &bpf_perf_event_data,
        map: &'a IUMap<K, V>,
        flags: u64,
    ) -> i64 {
        let ptr = unsafe { stub::bpf_get_stackid_pe_addr() } as *const ();
        let helper: extern "C" fn(
            *const bpf_perf_event_data_kern,
            &'a IUMap<K, V>,
            u64,
        ) -> i64 = unsafe { core::mem::transmute(ptr) };
        helper(ctx.kptr, map, flags)
    }
}

impl iu_prog for perf_event<'_> {
    fn prog_run(&self, ctx: *const ()) -> u32 {
        let mut newctx = self.convert_ctx(ctx);
        (self.prog)(self, &newctx)
    }
}
