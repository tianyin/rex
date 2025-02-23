rex_rootdir = '../../'

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

loader_includes = [
  join_paths(rex_rootdir, 'linux/usr/include'),
  join_paths(rex_rootdir, 'linux/tools/lib')
]

executable(
  'loader', 
  'loader.c',
  build_by_default: true,
  build_rpath: join_paths(meson.project_source_root(), 'linux/tools/lib/bpf'),
  c_args: [
    '-pipe',
    '-march=native',
    '-ffunction-sections',
    '-fdata-sections',
    '-fno-semantic-interposition'
  ],
  dependencies: [librex_dep],
  include_directories: loader_includes,
  link_args: [
    '-Wl,-O1',
    '-Wl,--gc-sections',
  ],
  link_with: [libbpf],
  pie: true,
)

