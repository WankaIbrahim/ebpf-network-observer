# ebpf-network-observer

A kernel-level network observability agent using eBPF and Go that captures per-process TCP flows with near-zero overhead.

## What it does

Most networking tools like tcpdump work by copying every packet into userspace for processing, which can be expensive at scale. This tool takes a different approach by utilising small eBPF programs that run inside the Linux kernel itself, capturing connection events and accumulating byte counts at the source, and only pushing summaries to userspace. The result is a live view of every TCP connection on the machine showing which process opened it, where it went, and how much data flowed in each direction, all while maintaining a low profile on the system being observed.

## Architecture

The tool uses two eBPF map types, each chosen for a specific reason.

A ring buffer is used for connection events. These events are discrete and once read in userspace, there is no reason to keep them. Storing them any longer would be an unnecessary overhead.

A hash map is used for per-connection byte and packet counts. Unlike events, these are running totals that are continuously updated as data flows. A hash map provides O(1) keyed lookup, meaning that any connection's stats can be updated instantly without searching the entire map.

Rather than sending every individual send/receive event to userspace, the tool aggregates values in the kernel. On a busy machine tcp_sendmsg/tcp_recvmsg can fire thousands of times a second, each requiring a context switch. By accumulating in kernel maps and polling these values every two seconds, context switching overhead is set at a fixed rate regardless of traffic volume.

Detection logic runs in userspace rather than in the kernel. The analysis is stateful and needs floating point arithmetic, both of which are awkward under the eBPF verifier, and detection latency of a few seconds is acceptable for an observability tool. The kernel side stays minimal and does only what must be done in-kernel.

## How it works

When the agent starts, it loads compiled eBPF bytecode into the kernel and attaches five probes.

- **tcp_connect** - fires when any process opens a TCP connection, capturing the PID, process name, source IP, destination IP, and port. It sends these values to userspace via a ring buffer, and records the owning process so later probes can attribute traffic to it.

- **tcp_sendmsg** - fires on every send, atomically incrementing the TX byte and packet counters for that connection in a hash map.

- **tcp_recvmsg** - fires on every receive, doing the same for RX counters.

- **inet_csk_accept** (kretprobe) - fires when a process accepts an inbound connection, recording the owning process so inbound traffic is attributed as well as outbound.

- **sock/inet_sock_set_state** (tracepoint) - fires on every TCP state transition. Timestamps recorded at SYN_SENT and ESTABLISHED give connection establishment latency and connection lifetime, and the CLOSE transition is used to clean up map entries.

The Go agent loads and attaches these programs, reads new connection events off the ring buffer as they arrive, and polls the hash map every two seconds. Metrics are exposed on a Prometheus endpoint at `:2112/metrics` and visualised in Grafana.

## Known limitations

**Process attribution is best-effort.** Connection ownership is captured at tcp_connect and inet_csk_accept, where the calling process context is reliable, and stored in a separate map that the send and receive probes look up.

Connections already established before the agent started, sockets where the local port is not yet bound, and overwritten entries will show no owner. Unattributed traffic is grouped under the `unknown` label rather than being discarded.

**Connection counts may overcount.** During the cleanup after a connection is closed, the key used for the connection may not be reconstructable, or the connection may not close cleanly. These entries are eventually removed by the LRU policy. Note also that `ss -tn` shows only established connections, while the map may still hold entries for sockets in transitional states.

**IPv4 only**, as addresses are read as 32-bit values throughout. IPv6 sockets carrying IPv4 traffic are handled, but native IPv6 connections are not tracked.

**Process label cardinality is capped** at 100 distinct names, after which further processes are grouped as `other` to prevent unbounded time series growth.

## Tech stack

- Go
- eBPF/C (compiled with clang, loaded via cilium/ebpf)
- Linux kernel 6.x+ with BTF enabled
- CO-RE (Compile Once, Run Everywhere) for kernel portability
- Prometheus and Grafana, run via Docker Compose

## Prerequisites

- Linux with kernel 6.x+ and BTF enabled
- Go 1.22+
- clang/LLVM
- libbpf-dev
- bpftool
- Docker and Docker Compose (for the metrics stack)

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

Run with `-v` to print individual connection events and periodic stats to stdout.

To bring up Prometheus and Grafana:

```bash
cd deploy
docker compose up -d
```

Grafana is then available at `http://localhost:3000` (admin/admin) and Prometheus at `http://localhost:9090`. Import `deploy/grafana-dashboard.json` via Dashboards → New → Import and select the Prometheus data source.

## Current features

- Per-process TCP connection tracking (PID, process name, source/destination IP and port), for both inbound and outbound connections
- Per-connection byte and packet counting in both directions (TX/RX)
- Connection establishment latency (SYN_SENT → ESTABLISHED) and connection lifetime
- Prometheus metrics endpoint with bounded label cardinality
- Grafana dashboard covering throughput, connection rate, latency percentiles, and top talkers by process
- Port scan detection using a sliding window of distinct destinations per process
- Clean shutdown on Ctrl+C with automatic probe detachment

## Planned

- Latency spike detection using EWMA baselines and z-score thresholds
- DNS visibility and entropy analysis for exfiltration patterns
- Kubernetes DaemonSet deployment with pod-level flow attribution