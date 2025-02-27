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
  'error_injector-clippy',
  output: ['target'],
  command: [
    'cargo', '-Z',
    'unstable-options',
    '-C', meson.current_source_dir(),
    'clippy', '-r',
  ],
  env: env,
  console: true,
  build_by_default: true
)

sample_build = custom_target(
  'error_injector-build',
  output: ['error_injector'],
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

executable(
  'loader',
  'loader.c',
  build_by_default: true,
  dependencies: [librex_dep, libbpf_dep, kernel_dep],
  pie: true
)

executable(
  'userapp',
  'userapp.c',
  build_by_default: true,
  dependencies: [kernel_dep],
  pie: true
)

