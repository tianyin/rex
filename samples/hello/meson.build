build_dir = run_command(
  realpath,
  '--relative-to',
  meson.current_source_dir(),
  meson.current_build_dir(),
  capture: true,
  check: true
).stdout().strip()

env.set('CARGO_TARGET_DIR', join_paths(build_dir, 'target'))

sample_clippy = custom_target(
  'hello-clippy',
  output: ['target'],
  command: [
    'cargo', '-Z',
    'unstable-options',
    '-C', meson.current_source_dir(),
    'clippy', '-r'
  ],
  env: env,
  console: true,
  build_by_default: true
)

sample_build = custom_target(
  'hello-build',
  output: ['hello'],
  command: [
    'cargo', '-Z',
    'unstable-options',
    '-C', meson.current_source_dir(),
    'rustc', '-r', '--',
    '-Cenable_rex'
  ],
  depends: sample_clippy,
  env: env,
  console: true,
  build_by_default: true
)

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
  c_args: cflags,
  dependencies: [librex_dep, libbpf_dep, kernel_dep],
  link_args: [
    '-Wl,-O1',
    '-Wl,--gc-sections'
  ],
  pie: true
)

executable(
  'event-trigger',
  'event-trigger.c',
  build_by_default: true,
  c_args: cflags,
  dependencies: [kernel_dep],
  link_args: [
    '-Wl,-O1',
    '-Wl,--gc-sections'
  ],
  pie: true
)

