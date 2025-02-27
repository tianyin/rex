build_dir = run_command(
  realpath,
  '--relative-to',
  meson.current_source_dir(),
  meson.current_build_dir(),
  capture: true,
  check: true
).stdout().strip()

env = environment()
env.prepend('PATH', rust_bin)
env.set('LINUX_OBJ', kbuild_dir)
env.set('LINUX_SRC', join_paths(meson.project_source_root(), './linux'))
env.set('CARGO_TARGET_DIR', join_paths(build_dir, 'target'))

sample_clippy = custom_target(
  'xdp_test-clippy',
  output: ['target'],
  command: [
    cargo_bin, '-Z',
    'unstable-options',
    '-C', meson.current_source_dir(),
    'clippy', '-r'
  ],
  env: env,
  console: true,
  build_by_default: true
)

sample_build = custom_target(
  'xdp_test-build',
  output: ['xdp_test'],
  command: [
    cargo_bin, '-Z',
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
  'entry',
  'entry.c',
  build_by_default: true,
  dependencies: [librex_dep, libbpf_dep, kernel_dep],
  pie: true
)
