project('rex-compile', 
  ['c', 'cpp', 'rust'],
  version: '0.1.0',
  default_options : [
    'buildtype=debugoptimized',
    'warning_level=1',
    'b_lto=true',
    'b_lto_mode=thin',
    'b_pie=true',
    'c_std=c17',
    'cpp_std=c++23'
  ]
)

cpp = meson.get_compiler('cpp')

make = find_program('make')

kernel_build = custom_target(
  'build-kernel',
  output: ['vmlinux', 'bpf.h'],
  command: [
    'make', '-C','@SOURCE_ROOT@/linux','-j', '32'
  ],
  env: ['LLVM=1'],
  console: true,
  build_by_default: true
)

kernel_libbpf = custom_target(
  'build-libbpf',
  output: 'libbpf.a', # some placeholder here
  command: [
    make, '-C', '@SOURCE_ROOT@/linux/tools/lib/bpf/', '-j', '32'
  ],
  env: ['LLVM=1'],
  console: true,
  depends: kernel_build,
  build_by_default: true,
)

python3_bin = find_program('python3')
rust_bootstrap_config = files('./rust/rex-config.toml')
rust_bootstrap = custom_target(
  'rust_bootstrap',
  output : ['cargo', 'rustc'],
  command: [python3_bin, '@SOURCE_ROOT@/rust/x.py', 'install',
    '--config=@SOURCE_ROOT@/rust/rex-config.toml',
    '--build-dir=@SOURCE_ROOT@/rust/build', 
    '--set', 'install.prefix=@SOURCE_ROOT@/rust/dist'],
  console: true,
  build_by_default: true
)

ln = find_program('ln')

libbpf = custom_target(
  'symlink-libbpf',
  output: 'libbpf.so',
  command: ['ln', '-s', '@CURRENT_SOURCE_DIR@/linux/tools/lib/bpf/libbpf.so', '@OUTPUT@'],
  console: true,
  depends: kernel_libbpf,
  build_by_default: true,
)

subdir('librex')
