use super::binding::{
    bpf_perf_event_data_kern, bpf_user_pt_regs_t, perf_sample_data,
};
use crate::bindings::uapi::linux::bpf::{
    bpf_map_type, bpf_perf_event_value, BPF_MAP_TYPE_STACK_TRACE,
    BPF_PROG_TYPE_PERF_EVENT,
};
use crate::linux::errno::EINVAL;
use crate::map::*;
use crate::prog_type::iu_prog;
use crate::stub;
use crate::task_struct::TaskStruct;
use crate::utils::{to_result, Result};

#[derive(Debug)]
pub struct bpf_perf_event_data<'a> {
    kptr: &'a mut bpf_perf_event_data_kern,
}

macro_rules! decl_reg_accessors {
    ($t:ident $($ts:ident)*) => {
        #[inline(always)]
        pub fn $t(&self) -> u64 {
            unsafe { (*self.kptr.regs).$t }
        }
        decl_reg_accessors!($($ts)*);
    };
    () => {};
}

impl<'a> bpf_perf_event_data<'a> {
    decl_reg_accessors!(r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi
        rdi orig_rax rip cs eflags rsp ss);

    #[inline(always)]
    pub fn sample_period(&self) -> u64 {
        unsafe { (&*self.kptr.data).period }
    }

    #[inline(always)]
    pub fn addr(&self) -> u64 {
        unsafe { (&*self.kptr.data).addr }
    }
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
    prog: fn(&Self, &bpf_perf_event_data) -> Result,
    name: &'a str,
}

impl<'a> perf_event<'a> {
    crate::base_helper::base_helper_defs!();

    pub const fn new(
        f: fn(&perf_event<'a>, &bpf_perf_event_data) -> Result,
        nm: &'a str,
    ) -> perf_event<'a> {
        Self {
            rtti: BPF_PROG_TYPE_PERF_EVENT as u64,
            prog: f,
            name: nm,
        }
    }

    fn convert_ctx(&self, ctx: *mut ()) -> bpf_perf_event_data {
        let kptr: &mut bpf_perf_event_data_kern =
            unsafe { &mut *(ctx as *mut bpf_perf_event_data_kern) };

        bpf_perf_event_data { kptr }
    }

    pub fn bpf_perf_prog_read_value(
        &self,
        ctx: &bpf_perf_event_data,
        buf: &mut bpf_perf_event_value,
    ) -> Result {
        let size = core::mem::size_of::<bpf_perf_event_value>() as u32;

        unsafe {
            to_result!(stub::bpf_perf_prog_read_value(ctx.kptr, buf, size))
        }
    }

    pub fn bpf_get_stackid_pe<K, V>(
        &self,
        ctx: &bpf_perf_event_data,
        map: &'static IUStackMap<K, V>,
        flags: u64,
    ) -> Result {
        let map_kptr = unsafe { core::ptr::read_volatile(&map.kptr) };
        if map_kptr.is_null() {
            return Err(EINVAL as i32);
        }

        unsafe {
            to_result!(stub::bpf_get_stackid_pe(ctx.kptr, map_kptr, flags))
        }
    }

    pub fn bpf_get_current_task(&self) -> Option<TaskStruct> {
        TaskStruct::get_current_task()
    }
}

impl iu_prog for perf_event<'_> {
    fn prog_run(&self, ctx: *mut ()) -> u32 {
        let mut newctx = self.convert_ctx(ctx);
        ((self.prog)(self, &newctx)).unwrap_or_else(|_| 0) as u32
    }
}
