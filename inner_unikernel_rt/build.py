import os
import subprocess
import sys

if sys.version_info >= (3, 11):
    import tomllib
    toml_flag = 'rb'
else:
    import toml as tomllib
    toml_flag = 'r'

# https://github.com/rust-lang/rust-bindgen
bindgen_cmd = 'bindgen --size_t-is-usize --use-core --no-doc-comments '\
        '--translate-enum-integer-types --no-layout-tests '\
        '--no-prepend-enum-name --blocklist-type pt_regs'.split()

stub_skel = """#[inline(always)]
pub(crate) const unsafe fn %s_addr() -> u64 {
    0x%%s
}
"""

# These 2 functions are from the old fixup_addrs.py
def filter_symbol(nm_line):
    # T/t means text(code) symbol
    # D/d means data
    if len(nm_line) != 3:
        return False;
    sym_ty = nm_line[1].lower()
    return sym_ty == 't' or sym_ty == 'd'

def get_symbols(vmlinux):
    result = subprocess.run(['nm', vmlinux], check=True, capture_output=True)
    return map(lambda l: l.strip().split(),
            result.stdout.decode('utf-8').split('\n'))

def gen_stubs(vmlinux, helpers, out_dir):
    if len(helpers) == 0:
        return

    # Construct a func -> addr map
    text_syms = dict(map(lambda l: (l[2], l[0]),
                         filter(filter_symbol, get_symbols(vmlinux))))
    stubs = '\n'.join(map(lambda h: stub_skel % h.lower(), helpers))
    output = stubs % tuple(map(lambda f: text_syms[f], helpers))
    with open(os.path.join(out_dir, 'stub.rs'), 'w') as stub_f:
        stub_f.write(output)

# Generates Rust binding from C/C++ header
def bindgen(header):
    p = subprocess.run([*bindgen_cmd, header], check=True, capture_output=True)
    output = p.stdout.decode('utf-8')
    assert 'std::' not in output # sanity check
    return output

def prep_headers(usr_include, headers, out_dir):
    if len(headers) == 0:
        return

    for h in headers:
        output = bindgen(os.path.join(usr_include, h))

        subdir, file = os.path.split(h)
        subdir = os.path.join(out_dir, subdir)
        if not os.path.exists(subdir):
            os.makedirs(subdir)

        with open(os.path.join(subdir, '%s.rs' % file[:-2]), 'w') as bind_f:
            bind_f.write(output)

def parse_config(cargo_toml):
    with open(cargo_toml, toml_flag) as toml_f:
        config = tomllib.load(toml_f)

    if not 'inner_unikernel' in config:
        return [], []

    ksyms = config['inner_unikernel'].get('ksyms', [])
    uheaders = config['inner_unikernel'].get('uheaders', [])
    kheaders = config['inner_unikernel'].get('kheaders', [])

    return ksyms, uheaders, kheaders

def main(argv):
    linux_path = argv[1]
    out_dir = argv[2]
    target_path = os.getcwd()
    result = parse_config(os.path.join(target_path, 'Cargo.toml'))
    ksyms, uheaders, kheaders = result
    gen_stubs(os.path.join(linux_path, 'vmlinux'), ksyms, out_dir)
    u_out_dir = os.path.join(out_dir, 'uapi')
    prep_headers(os.path.join(linux_path, 'usr/include'), uheaders, u_out_dir)
    prep_headers(os.path.join(linux_path, 'include'), kheaders, out_dir)
    return 0

if __name__ == '__main__':
    exit(main(sys.argv))
