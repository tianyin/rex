#![no_std]
#![no_main]

use rex::kprobe::kprobe;
use rex::map::RexArrayMap;
use rex::pt_regs::PtRegs;
use rex::rex_kprobe;
use rex::rex_map;
use rex::Result;

#[allow(non_upper_case_globals)]
#[rex_map]
static pid_map: RexArrayMap<i32> = RexArrayMap::new(1, 0);

#[allow(non_upper_case_globals)]
#[rex_map]
static errno_map: RexArrayMap<u64> = RexArrayMap::new(1, 0);

#[rex_kprobe]
pub fn err_injector(obj: &kprobe, ctx: &mut PtRegs) -> Result {
    let current = obj.bpf_get_current_task().ok_or(0)?;
    obj.bpf_map_lookup_elem(&pid_map, &0u32)
        .filter(|x| **x == current.get_pid())
        .ok_or(0)?;
    let errno = *obj.bpf_map_lookup_elem(&errno_map, &0u32).ok_or(0)?;

    obj.bpf_override_return(ctx, errno);

    Ok(0)
}
