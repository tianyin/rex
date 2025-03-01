export LINUX=$(realpath ./linux)
if [[ -f "./build/rust-dist/bin/rustc" ]]; then
	export PATH=$(realpath ./build/rust-dist/bin):$PATH
fi
export RUST_BACKTRACE=1
