use crate::bindings::linux::kernel::{
    bpf_perf_event_data_kern, bpf_user_pt_regs_t, perf_sample_data,
};

use crate::bindings::uapi::linux::bpf::{
    bpf_map_type, bpf_perf_event_value, BPF_MAP_TYPE_STACK_TRACE,
    BPF_PROG_TYPE_PERF_EVENT,
};

use crate::linux::errno::EINVAL;
use crate::map::*;
use crate::prog_type::rex_prog;
use crate::stub;
use crate::task_struct::TaskStruct;
use crate::utils::{to_result, Result};

use core::intrinsics::unlikely;
use paste::paste;

#[repr(transparent)]
pub struct bpf_perf_event_data {
    kdata: bpf_perf_event_data_kern,
}

macro_rules! decl_reg_accessors1 {
    ($t:ident $($ts:ident)*) => {
        #[inline(always)]
        pub fn $t(&self) -> u64 {
            unsafe { (*self.kdata.regs).$t }
        }
        decl_reg_accessors1!($($ts)*);
    };
    () => {};
}

macro_rules! decl_reg_accessors2 {
    ($t:ident $($ts:ident)*) => {
        paste! {
            #[inline(always)]
            pub fn [<r $t>](&self) -> u64 {
                unsafe { (*self.kdata.regs).$t }
            }
        }
        decl_reg_accessors2!($($ts)*);
    };
    () => {};
}

impl bpf_perf_event_data {
    // regs that does not require special handling
    decl_reg_accessors1!(r15 r14 r13 r12 r11 r10 r9 r8);

    // regs that does not have the 'r' prefix in kernel pt_regs
    decl_reg_accessors2!(bp bx ax cx dx si di ip sp);

    // orig_rax cs eflags ss cannot be batch-processed by macros
    #[inline(always)]
    pub fn orig_rax(&self) -> u64 {
        unsafe { (*self.kdata.regs).orig_ax }
    }

    #[inline(always)]
    pub fn cs(&self) -> u64 {
        unsafe { (*self.kdata.regs).__bindgen_anon_1.cs as u64 }
    }

    #[inline(always)]
    pub fn eflags(&self) -> u64 {
        unsafe { (*self.kdata.regs).flags }
    }

    #[inline(always)]
    pub fn ss(&self) -> u64 {
        unsafe { (*self.kdata.regs).__bindgen_anon_2.ss as u64 }
    }

    #[inline(always)]
    pub fn sample_period(&self) -> u64 {
        unsafe { (&*self.kdata.data).period }
    }

    #[inline(always)]
    pub fn addr(&self) -> u64 {
        unsafe { (&*self.kdata.data).addr }
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

    fn convert_ctx(&self, ctx: *mut ()) -> &bpf_perf_event_data {
        unsafe { &*(ctx as *mut bpf_perf_event_data) }
    }

    pub fn bpf_perf_prog_read_value(
        &self,
        ctx: &bpf_perf_event_data,
        buf: &mut bpf_perf_event_value,
    ) -> Result {
        let size = core::mem::size_of::<bpf_perf_event_value>() as u32;
        let ctx_kptr = ctx as *const bpf_perf_event_data
            as *const bpf_perf_event_data_kern;

        unsafe {
            to_result!(stub::bpf_perf_prog_read_value(ctx_kptr, buf, size))
        }
    }

    pub fn bpf_get_stackid_pe<K, V>(
        &self,
        ctx: &bpf_perf_event_data,
        map: &'static RexStackTrace<K, V>,
        flags: u64,
    ) -> Result {
        let map_kptr = unsafe { core::ptr::read_volatile(&map.kptr) };
        if unlikely(map_kptr.is_null()) {
            return Err(EINVAL as i32);
        }

        let ctx_kptr = ctx as *const bpf_perf_event_data
            as *const bpf_perf_event_data_kern;

        unsafe {
            to_result!(stub::bpf_get_stackid_pe(ctx_kptr, map_kptr, flags))
        }
    }

    pub fn bpf_get_current_task(&self) -> Option<TaskStruct> {
        TaskStruct::get_current_task()
    }
}

impl rex_prog for perf_event<'_> {
    fn prog_run(&self, ctx: *mut ()) -> u32 {
        let mut newctx = self.convert_ctx(ctx);
        ((self.prog)(self, newctx)).unwrap_or_else(|_| 0) as u32
    }
}
