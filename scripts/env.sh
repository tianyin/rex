export LINUX=$(realpath ./linux)
if [[ -f "./rust/dist/bin/rustc" ]]; then
	export PATH=$(realpath ./rust/dist/bin):$PATH
fi
export RUST_BACKTRACE=1
