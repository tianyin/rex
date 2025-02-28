project('rex-compile',
  ['c', 'cpp'],
  version: '0.1.0',
  default_options : [
    'buildtype=debugoptimized',
    'warning_level=1',
    'b_lto=true',
    'b_lto_mode=thin',
    'b_pie=true',
    'c_std=gnu17',
    'cpp_std=c++23'
  ]
)

add_project_arguments(
  [
    '-pipe',
    '-march=native',
    '-ffunction-sections',
    '-fdata-sections',
    '-fno-semantic-interposition'
  ],
  language: ['c', 'cpp']
)

add_project_link_arguments(
  [
    '-Wl,-O1',
    '-Wl,--gc-sections',
    '-Wl,-znow',
    '-Wl,-zrelro'
  ],
  language: ['c', 'cpp']
)

subdir('linux')
subdir('librex')

python3_bin = find_program('python3')
rust_bootstrap_config = files('./rust/rex-config.toml')
rust_bootstrap = custom_target(
  'rust',
  output : ['cargo', 'rustc'],
  command: [
    python3_bin, '@SOURCE_ROOT@/rust/x.py', 'install',
    '--config=@SOURCE_ROOT@/rust/rex-config.toml',
    '--build-dir=@OUTDIR@/rust-build',
    '--set', 'install.prefix=@OUTDIR@/rust-dist'
  ],
  console: true,
  build_by_default: false
)

all_programs = custom_target('build_deps',
    output: ['kernel', 'kernel_libbpf', 'rust'],
    command: ['echo', 'Build all depends'],
    depends: [kernel_build, kernel_libbpf, rust_bootstrap],
    console: true
)

perl = find_program('perl')

rust_bin = join_paths(meson.current_build_dir(), 'rust-dist/bin')
cargo_wrapper = join_paths(meson.project_source_root(), 'scripts/cargo-wrapper.pl')


realpath = find_program('realpath')

subdir('samples')
