### Spec requirement
- At least 16 GB memory
	- 32 GB recommended 
- XDP supported NIC
	- https://github.com/xdp-project/xdp-project/blob/master/areas/drivers/README.org

### Run BMC
- clone repo https://github.com/xlab-uiuc/bmc-cache
```bash
cd bmc-cache/bmc
ln -s <linux folder> .
make
./bmc <interface_id> # get interface_id from `ip a` command
```

#### TC egress hook

BMC doesn't attach the tx_filter eBPF program to the egress hook of TC, it needs to be attached manually.

To do so, you first need to make sure that the BPF filesystem is mounted, if it isn't you can mount it with the following command:
```bash
mount -t bpf none /sys/fs/bpf/
```

Once BMC is running and the tx_filter program has been pinned to /sys/fs/bpf/bmc_tx_filter, you can attach it using the tc command line:
```bash
tc qdisc add dev <interface_name> clsact
tc filter add dev <interface_name> egress bpf object-pinned /sys/fs/bpf/bmc_tx_filter
```

After you are done using BMC, you can detach the program with these commands:
```bash
tc filter del dev <interface_name> egress
tc qdisc del dev <interface_name> clsact
```
And unpin the program with `rm /sys/fs/bpf/bmc_tx_filter`
### Rust extension
Follow the steps on https://github.com/rosalab/inner_unikernels, after the step  "Run `hello` example":
Build the rust version bmc
```bash
cd samples/bmc
make
./entry <interface_id>
```
The instructions are most the same with bmc except we are using xdp_tx_filter instead of bmc_tx_filter
```bash
mount -t bpf none /sys/fs/bpf/
tc qdisc add dev <interface_name> clsact # interface_name (e.g., eth0) not interface_id
tc filter add dev <interface_name> egress bpf object-pinned /sys/fs/bpf/xdp_tx_filter
```
### Run benchmark
You need to binding a BMC or Rust extension program and compare the results without these XDP programs.
Start Memcached server via:
```bash
memcached -p 11211 -U 11211 -m 10240
```
Build the benchmark program
```bash
git clone https://github.com/rosalab/inner_unikernels
cd inner_unikernels/samples/memcached_benchmark
cargo build -r
```
Check the help message
```bash
cargo run -r -- -h
Usage: memcached_benchmark [OPTIONS]
Options:
  -s, --server-address <SERVER_ADDRESS>
          [default: 127.0.0.1]
  -p, --port <PORT>
          [default: 11211]
  -k, --key-size <KEY_SIZE>
          key size to generate random memcached key [default: 16]
  -v, --value-size <VALUE_SIZE>
          value size to generate random memcached value [default: 32]
  -d, --validate
          verify the value after get command
  -n, --nums <NUMS>
          number of test entries to generate [default: 100000]
  -t, --threads <THREADS>
          [default: 4]
  -l, --protocol <PROTOCOL>
          udp or tcp protocol for memcached [default: udp] [possible values: udp, tcp]
  -h, --help
          Print help
  -V, --version
          Print version

```
Example usage:
```bash
# test on memcached server 10.0.1.254 with 1000000 get requests 
cargo run -r -- -n 1000000 -s 10.0.1.254 -p 11211
```
