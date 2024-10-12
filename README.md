# eBPF-examples

### Lima VM

```sh
limactl start ebpf-examples.yaml
limactl shell ebpf-examples

# To be root for examples
sudo -s
```

### Building libbpf and installing header files

```sh
cd libbpf/src
make install 
cd ../..
```

### Watch the output 

```sh
cat /sys/kernel/tracing/trace_pipe.
```
