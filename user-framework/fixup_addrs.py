import subprocess
import sys

funcs = [
    'bpf_get_current_pid_tgid',
    'bpf_trace_printk',
    'bpf_map_lookup_elem_iu',
    'bpf_map_update_elem_iu'
]

c_func_fmt = """static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)0x%s;
static long (*bpf_trace_printk)(const char *fmt, __u32 fmt_size, __u64 arg1, __u64 arg2, __u64 arg3) = (void *)0x%s;
"""

rs_func_fmt = """pub const STUB_BPF_GET_CURRENT_PID_TGID: u64 = 0x%s;
pub const STUB_BPF_TRACE_PRINTK: u64 = 0x%s;
pub const STUB_BPF_LOOKUP_ELEM: u64 = 0x%s;
pub const STUB_BPF_UPDATE_ELEM: u64 = 0x%s;
/* flags for BPF_MAP_UPDATE_ELEM command */
pub const BPF_ANY: u64 = 0;
pub const BPF_NOEXIST: u64 = 1;
pub const BPF_EXIST: u64 = 2;
pub const BPF_F_LOCK: u64 = 4;
"""

def filter_text(nm_line):
    # T/t means text(code) symbol
    return len(nm_line) == 3 and nm_line[1].lower() == 't'

def get_symbols(vmlinux):
    result = subprocess.run(['nm', vmlinux], check=True, capture_output=True)
    return map(lambda l: l.strip().split(),
               result.stdout.decode('utf-8').split('\n'))

def main(argv):
    text_syms = dict(map(lambda l: (l[2], l[0]),
                     filter(filter_text, get_symbols(argv[1]))))
    with open('interface-kernel.h', 'w') as fd:
        fd.write(c_func_fmt % tuple(map(lambda f: text_syms[f], funcs[:2])))
    with open('rust_test/src/interface.rs', 'w') as fd:
        fd.write(rs_func_fmt % tuple(map(lambda f: text_syms[f], funcs)))

if __name__ == '__main__':
    main(sys.argv)
