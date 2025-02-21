project('rex-compile', 
  ['c', 'rust'],
  version: '0.1.0')

kernel_build = custom_target(
  'build-kernel',
  output: 'vmlinux',
  command: [
    'make', '-C','@CURRENT_SOURCE_DIR@/linux','-j', '32'
  ],
  env: ['LLVM=1'],
  console: true,
  build_by_default: true
)
kernel_libbpf = custom_target(
  'build-libbpf',
  output: 'libbpf.so', 
  command: [
    'make', '-C', '@CURRENT_SOURCE_DIR@/linux/tools/lib/bpf/', '-j', '32'
  ],
  env: ['LLVM=1'],
  console: true,
  depends: kernel_build,
  build_by_default: true
)
