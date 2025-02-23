sample_build = custom_target(
  'sample',
  output: ['target'],
  command: [
    cargo_bin,'-Z',
    'unstable-options', 
    '-C', join_paths(meson.project_source_root(),'samples/hello'),
    'rustc','-r','--',
    '-Funsafe_code',
    '-Finternal_features',
    '-Fincomplete_features',
    '-Funstable_features',
    '-Cenable_rex'
  ],
  env: env,
  console: true,
  build_by_default: true
)

executable(
  'loader', 
  'loader.c',
  include_directories: librex_inc,
  link_with: [librex, libbpf],
  build_rpath: join_paths(meson.project_source_root(), 'linux/tools/lib/bpf'),
  install: true,
  pie: true,
  )

