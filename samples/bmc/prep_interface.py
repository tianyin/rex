import subprocess
import sys
import os

helpers = [
           'bpf_map_lookup_elem',
           'bpf_spin_lock',
           'bpf_spin_unlock',
           'bpf_xdp_adjust_head',
           'bpf_xdp_adjust_tail',
           'bpf_trace_printk', # for debugging
]

# TODO: this is not configured automatically, fix this on your machine first
types = {
         '::std::os::raw::c_char': 'i8',
         '::std::os::raw::c_double': 'f64',
         '::std::os::raw::c_float': 'f32',
         '::std::os::raw::c_int': 'i32',
         '::std::os::raw::c_longlong': 'i64',
         '::std::os::raw::c_long': 'i64',
         '::std::os::raw::c_schar': 'i8',
         '::std::os::raw::c_short': 'i16',
         '::std::os::raw::c_uchar': 'u8',
         '::std::os::raw::c_uint': 'u32',
         '::std::os::raw::c_ulonglong': 'u64',
         '::std::os::raw::c_ulong': 'u64',
         '::std::os::raw::c_ushort': 'u16'
}

headers = [
           'linux/bpf.h',
           'linux/if_ether.h',
           'linux/ip.h',
           'linux/udp.h',
           'linux/tcp.h',
]

stubs = """
pub const STUB_BPF_MAP_LOOKUP_ELEM: u64 = 0x%s;
pub const STUB_BPF_SPIN_LOCK: u64 = 0x%s;
pub const STUB_BPF_SPIN_UNLOCK: u64 = 0x%s;
pub const STUB_BPF_XDP_ADJUST_HEAD: u64 = 0x%s;
pub const STUB_BPF_XDP_ADJUST_TAIL: u64 = 0x%s;
pub const STUB_BPF_TRACE_PRINTK: u64 = 0x%s;
"""

# https://github.com/rust-lang/rust-bindgen
bindgen_cmd = 'bindgen --size_t-is-usize --use-core --no-doc-comments '\
'--translate-enum-integer-types --no-layout-tests'.split()

# These 2 functions are from the old fixup_addrs.py
def filter_text(nm_line):
    # T/t means text(code) symbol
    return len(nm_line) == 3 and nm_line[1].lower() == 't'

def get_symbols(vmlinux):
    result = subprocess.run(['nm', vmlinux], check=True, capture_output=True)
    return map(lambda l: l.strip().split(),
               result.stdout.decode('utf-8').split('\n'))

def gen_stubs(vmlinux):
    # Construct a func -> addr map
    text_syms = dict(map(lambda l: (l[2], l[0]),
                         filter(filter_text, get_symbols(vmlinux))))
    output = stubs % tuple(map(lambda f: text_syms[f], helpers))
    with open(os.path.join('src', 'stub.rs'), 'w') as stub_f:
        stub_f.write(output)

# Generates Rust binding from C/C++ header
def bindgen(header):
    p = subprocess.run([*bindgen_cmd, header], check=True, capture_output=True)
    output = p.stdout.decode('utf-8')
    for ctype, rtype in types.items():
        output = output.replace(ctype, rtype)
    assert 'std::' not in output # sanity check
    return output

def prep_headers(usr_include):
    for h in headers:
        output = bindgen(os.path.join(usr_include, h))

        dir, file = h.split('/')
        dir = os.path.join('src', dir)
        if not os.path.exists(dir):
            os.makedirs(dir)

        with open(os.path.join(dir, '%s.rs' % file[:-2]), 'w') as bind_f:
            bind_f.write(output)

    for _, dirs, _ in os.walk('./src'):
        for d in dirs:
            d = os.path.join('./src', d)
            mod_rs = ''
            for _, _, files in os.walk(d):
                mod_rs += '\n'.join(["pub mod %s;" % f[:-3]\
                                    for f in files if f != 'mod.rs'])

        with open(os.path.join(d, 'mod.rs'), 'w') as mod_f:
            mod_f.write(mod_rs)

def main(argv):
    linux_path = argv[1]
    gen_stubs(os.path.join(linux_path, 'vmlinux'))
    prep_headers(os.path.join(linux_path, 'usr/include'))
    return 0

if __name__ == '__main__':
    exit(main(sys.argv))
