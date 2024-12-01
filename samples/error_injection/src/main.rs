#![no_std]
#![no_main]

use rex::kprobe::kprobe;
use rex::map::RexHashMap;
use rex::pt_regs::PtRegs;
use rex::rex_kprobe;
use rex::rex_map;
use rex::Result;

#[allow(non_upper_case_globals)]
#[rex_map]
static pid_to_errno: RexHashMap<i32, u64> = RexHashMap::new(1, 0);

#[rex_kprobe]
pub fn err_injector(obj: &kprobe, ctx: &mut PtRegs) -> Result {
    let pid = obj.bpf_get_current_task().map(|t| t.get_pid()).ok_or(0)?;
    obj.bpf_map_lookup_elem(&pid_to_errno, &pid)
        .map(|e| obj.bpf_override_return(ctx, *e))
        .ok_or(0)
}
