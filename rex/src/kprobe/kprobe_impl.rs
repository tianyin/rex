use crate::bindings::linux::kernel::pt_regs as pt_regs_kern;
use crate::bindings::uapi::linux::bpf::{bpf_map_type, BPF_PROG_TYPE_KPROBE};
use crate::map::*;
use crate::prog_type::rex_prog;
use crate::stub;
use crate::task_struct::TaskStruct;
use crate::Result;

use paste::paste;

#[repr(transparent)]
pub struct pt_regs {
    regs: pt_regs_kern,
}

macro_rules! decl_reg_accessors1 {
    ($t:ident $($ts:ident)*) => {
        #[inline(always)]
        pub fn $t(&self) -> u64 {
            self.regs.$t
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
                self.regs.$t
            }
        }
        decl_reg_accessors2!($($ts)*);
    };
    () => {};
}

impl pt_regs {
    // regs that does not require special handling
    decl_reg_accessors1!(r15 r14 r13 r12 r11 r10 r9 r8);

    // regs that does not have the 'r' prefix in kernel pt_regs
    decl_reg_accessors2!(bp bx ax cx dx si di ip sp);

    // orig_rax cs eflags ss cannot be batch-processed by macros
    #[inline(always)]
    pub fn orig_rax(&self) -> u64 {
        self.regs.orig_ax
    }

    #[inline(always)]
    pub fn cs(&self) -> u64 {
        unsafe { self.regs.__bindgen_anon_1.cs as u64 }
    }

    #[inline(always)]
    pub fn eflags(&self) -> u64 {
        self.regs.flags
    }

    #[inline(always)]
    pub fn ss(&self) -> u64 {
        unsafe { self.regs.__bindgen_anon_2.ss as u64 }
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
pub struct kprobe<'a> {
    rtti: u64,
    prog: fn(&Self, &mut pt_regs) -> Result,
    name: &'a str,
}

impl<'a> kprobe<'a> {
    crate::base_helper::base_helper_defs!();

    pub const fn new(
        f: fn(&kprobe<'a>, &mut pt_regs) -> Result,
        nm: &'a str,
    ) -> kprobe<'a> {
        Self {
            rtti: BPF_PROG_TYPE_KPROBE as u64,
            prog: f,
            name: nm,
        }
    }

    // Now returns a mutable ref, but since every reg is private the user prog
    // cannot change reg contents. The user should not be able to directly
    // assign this reference a new value either, given that they will not able
    // to create another instance of pt_regs (private fields, no pub ctor)
    fn convert_ctx(&self, ctx: *mut ()) -> &mut pt_regs {
        // ctx has actual type *mut crate::bindings::linux::kernel::pt_regs
        // therefore it is safe to just interpret it as a *mut pt_regs
        // since the later is #[repr(transparent)] over the former
        unsafe { &mut *(ctx as *mut pt_regs) }
    }

    #[cfg(CONFIG_BPF_KPROBE_OVERRIDE = "y")]
    // Not usable for now, this function requires a mutation ref, which is
    // not safe to expose to the user progs
    pub fn bpf_override_return(&self, regs: &mut pt_regs, rc: u64) -> i32 {
        regs.regs.ax = rc;
        regs.regs.ip = unsafe { stub::just_return_func as *const () as u64 };
        return 0;
    }

    pub fn bpf_get_current_task(&self) -> Option<TaskStruct> {
        TaskStruct::get_current_task()
    }
}

impl rex_prog for kprobe<'_> {
    fn prog_run(&self, ctx: *mut ()) -> u32 {
        let newctx = self.convert_ctx(ctx);
        ((self.prog)(self, newctx)).unwrap_or_else(|_| 0) as u32
    }
}
