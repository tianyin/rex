
sample_clippy = custom_target(
  'hello-clippy',
  output: ['target'],
  command: [
    cargo_bin,'-Z',
    'unstable-options', 
    '-C', meson.current_source_dir(),
    'clippy','-r',
  ],
  env: env,
  console: true,
  build_by_default: true
)

env.set('CARGO_TARGET_DIR', '../../build/samples/hello/target')
sample_build = custom_target(
  'hello-build',
  output: ['hello'],
  command: [
    cargo_bin,'-Z',
    'unstable-options', 
    '-C', meson.current_source_dir(),
    'rustc','-r','--',
    '-Cenable_rex'
  ],
  depends: sample_clippy,
  env: env,
  console: true,
  build_by_default: true
)

rex_rootdir = '../../'
loader_includes = [
  join_paths(rex_rootdir, 'linux/usr/include'),
  join_paths(rex_rootdir, 'linux/tools/lib')
]

cflags = [
    '-pipe',
    '-march=native',
    '-ffunction-sections',
    '-fdata-sections',
    '-fno-semantic-interposition'
]

executable(
  'loader', 
  'loader.c',
  build_by_default: true,
  build_rpath: join_paths(kernel_dir, 'tools/lib/bpf'),
  c_args: cflags,
  dependencies: [librex_dep],
  include_directories: loader_includes,
  link_args: [
    '-Wl,-O1',
    '-Wl,--gc-sections',
  ],
  link_with: [libbpf],
  pie: true,
)

executable(
  'event-trigger', 
  'event-trigger.c',
  build_by_default: true,
  c_args: cflags,
  include_directories: loader_includes,
  link_args: [
    '-Wl,-O1',
    '-Wl,--gc-sections',
  ],
  install: false,
  pie: true,
)

