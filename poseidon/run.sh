OS_ARCH=$(uname -a)
TIME=/usr/bin/time
if [[ $OS_ARCH == *"Darwin"*"arm64"* ]]; then
  TIME=/opt/homebrew/bin/gtime
fi
which $TIME

RUSTFLAGS=-Ctarget-cpu=native $TIME -f "Peak memory: %M kb CPU usage: %P" cargo run --release --package halo2_bench_poseidon --bin halo2_bench_poseidon
