export LINUX=$(realpath ./linux)
if [[ -z "./rust/dist/bin" ]]; then
	export PATH=$(realpath ./rust/dist/bin):$PATH
fi
export RUST_BACKTRACE=1
