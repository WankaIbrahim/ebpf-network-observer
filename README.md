# ebpf-network-observer

A Kernel-level network observability agent using eBPF and Go that captures per-process TCP flows with near-zero overhead.

## What it does

Most networking tools like tcpdump worl by copying every packet into userspace for processing which can be expesive at scale. This tool takes adifferent approach by utilising small eBPF programs run inside the linux kernel itself, capturing connection ecents and accumulating byte counts at the source and only pushing summaries to userspace. The result is a liveview of every TCP connection on the machine showing which process opened it, where it went, and how much data flowed in each direction all while mainting a low profile on the system being observed.

## Architecture

The tool uses two eBPF map types, each chosen for a specific reason.

A ring buffer is used for connection events. These events are discrete and once read in the userspace, there is no reason to keep them. Storing them any longer would be an unecessary overhead.

A hash map is used for per connection byte and packet countss. Unlike events, these are running totals that are continuosly updates as data flows. A hash map provides O(1) keyed lookup meaning that any connections stats can be updated instnaly wihtout searching the entire map.

Rather than sending every individual send/receive event to userspace, the tool aggregates values in the kernel. On a busy maching tcp_sendmsg/tcp_recvmsg can fire thousands of times each requiring a contexxt switch. By accumulating and polling these values every two seconds, context switching overhead is set at a fixed rate regardless of traffic volume.

## How it works

When the agent starts, it loads compiled eBPF bytecode into the kernel and attaches three probes.

- tcp_connect: fires when any proccess opens a TCP connection, capturing the PID, proccess name, source IP, destination IP, and port. It sends these values to userspace via a ring buffer.

- tcp_sendmsg: fires on every send, atomically incrementing the TX byte and packet counters for that connection in a hash map.

- tcp_recvmsg: fire on every receive, doing the same for RX counters.

The Go agent loads and attaches these programs,reads new connection events off the ring buffer as they arrive, and poills the hash map every two seconds to print a liver throughput summary

## Tech Stack

- Go
- eBPF/C (compiled with clang, loaded via cilium/ebpf)
- Linux kernel 6.x+ with BTF enabled
- CO-RE (Compile Once, Run Everywhere) for kernel portability

## Prerequisites

- Linux with kernel 6.x+ and BTF enabled
- Go 1.22+
- clang/LLVM
- libbpf-dev
- bpftool

Install dependencies on Ubuntu:
```bash
sudo apt install -y clang llvm libbpf-dev linux-headers-$(uname -r) linux-tools-$(uname -r) bpftool
```

## Build and run

```bash
git clone https://github.com/WankaIbrahim/ebpf-network-observer.git
cd ebpf-network-observer/cmd/observer
go generate ./...
go build .
sudo ./observer
```

## Current features

- Per-process TCP connection tracking (PID, process name, source/destination IP and port)
- Per-connection byte and packet counting in both directions (TX/RX)
- Live throughput stats polled from the kernel every two seconds
- Clean shutdown on Ctrl+C with automatic kprobe detachment
- Connection establishment latency measurement (SYN_SENT → ESTABLISHED)

## Planned

- Prometheus metrics endpoint
- Grafana dashboard
- Kubernetes DaemonSet deployment with pod-level flow attribution
- Heuristic anomaly detection (port scan detection, DNS entropy analysis)