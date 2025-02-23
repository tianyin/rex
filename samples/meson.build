cargo_bin = join_paths(meson.project_source_root(), 'rust/dist/bin/cargo')
rust_bin = join_paths(meson.project_source_root(), 'rust/dist/bin')
kernel_dir = join_paths(meson.project_source_root(), 'linux')

env = environment()
env.prepend('PATH', rust_bin)
env.set('LINUX', kernel_dir)

subdir('hello')
