rex_rootdir = '..'

llvm_dep = dependency('llvm', version : '>=18')
elf_dep = dependency('libelf')

librex_includes = [
  './include',
  join_paths(rex_rootdir, 'linux/usr/include'),
  join_paths(rex_rootdir, 'linux/tools/lib')
]

librex_sources = [
  'lib/librex.cpp',
  kernel_build[1]
]

librex = library(
  'rex',
  librex_sources,
  cpp_args: [
    '-pipe',
    '-march=native',
    '-ffunction-sections',
    '-fdata-sections',
    '-fno-semantic-interposition'
  ],
  build_rpath: join_paths(meson.project_source_root(), 'linux/tools/lib/bpf'),
  build_by_default: true,
  dependencies: [elf_dep, llvm_dep],
  gnu_symbol_visibility: 'hidden',
  include_directories: librex_includes,
  link_args: [
    '-Wl,-O1',
    '-Wl,--gc-sections',
  ],
  link_with: [libbpf],
  pic: true,
)
