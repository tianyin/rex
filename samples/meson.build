cargo_bin = join_paths(meson.project_source_root(), 'rust/dist/bin/cargo')
rust_bin = join_paths(meson.project_source_root(), 'rust/dist/bin')

env = environment()
env.prepend('PATH', rust_bin)

subdir('hello')
