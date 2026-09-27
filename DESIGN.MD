# Building an eBPF Network Observer

**Design Decisions and Debugging**

Ibrahim Wanka

This is a write-up of the design decisions behind `ebpf-network-observer`, a kernel-level network observability agent, and three bugs that were only found by looking at the data rather than reading the code.

Repository: [github.com/WankaIbrahim/ebpf-network-observer](https://github.com/WankaIbrahim/ebpf-network-observer)

## Why eBPF

Most network monitoring tools work by copying packets into userspace and filtering them there. tcpdump and anything built on libpcap do this. It works, but the cost scales with traffic volume, which makes it fine for debugging and expensive as always-on telemetry.

eBPF lets you run small programs inside the Linux kernel itself, attached to specific hooks. The programs are verified before they are allowed to load, so they cannot crash the kernel or read memory they should not. This means the filtering and aggregation can happen at the source, and only summaries need to cross into userspace.

That distinction is the whole point of this tool. The monitoring cost does not scale with traffic volume.

## Aggregate in the kernel, poll from userspace

The tool uses two eBPF map types, each for a different job.

Connection events go into a ring buffer: a new connection opening, a latency measurement, a connection closing. These are discrete and one-shot. Once userspace has read them there is no reason to keep them, and a ring buffer is built for that pattern.

Per-connection byte and packet counts go into a hash map. Unlike events, these are running totals that are updated continuously as data flows, so they need to be found and modified repeatedly, which a stream cannot do. A hash map gives O(1) keyed lookup, so updating any connection is instant regardless of how many are being tracked.

The alternative would have been to send every send and receive event through the ring buffer and aggregate in Go. On a busy machine `tcp_sendmsg` and `tcp_recvmsg` fire thousands of times a second, and each one crossing the kernel boundary would mean a context switch. By accumulating in kernel maps and polling every two seconds, the boundary is crossed at a fixed rate no matter how much traffic there is.

## Where detection runs

Anomaly detection runs in userspace, not in the kernel. The analysis is stateful and needs floating point, both of which are painful under the verifier, which allows no unbounded loops, no floating point, and only fixed-size maps for any history you want to keep. Writing an EWMA baseline in eBPF C would be a fight for no real benefit.

Kernel-side detection could react in microseconds instead of seconds, and could act on traffic rather than just observe it. That matters for a security enforcement tool. This is an observability tool, so it does not.

## Three bugs

All three of these were found the same way: by dumping the eBPF maps with `bpftool` and looking at the actual values, rather than by rereading the code. In every case the code looked correct and the failure was silent.

### Truncated addresses

Connection latency is measured by recording a timestamp when a socket enters SYN_SENT and reading it back when it reaches ESTABLISHED, using the `sock/inet_sock_set_state` tracepoint. After implementing it, no latency events were ever emitted. The program compiled, loaded and attached without error, the tracepoint was confirmed to be firing, and the map storing start times was being written to. Nothing surfaced an error. The feature just produced no output.

Dumping the map showed keys where the addresses were a single byte, `saddr: 192` rather than the full 32-bit value. The tracepoint declares its address fields as `__u8 saddr[4]`, four individual bytes rather than a u32, so reading `saddr[0]` returned exactly one byte and discarded the rest. The fix was to use `bpf_probe_read_kernel` to copy all four bytes in one read and reinterpret them as a u32.

The same dump showed a second problem: the source port was 0 on every entry. The local port is not yet bound when SYN_SENT fires, so by the time ESTABLISHED arrived the port had a real value and the two transitions were building different keys. The lookup never matched, which is why no latency was ever calculated. The fix was to key the latency maps on source address, destination address and destination port only.

That carries a deliberate tradeoff. Without the source port, two concurrent connections to the same destination collide on one map entry and one can overwrite the other's start timestamp. For this use case the loss of precision in that edge case is acceptable, but it is a real limitation of the keying rather than an oversight.

### A byte-swapped source port

While cleaning up stale map entries, I wanted to know whether the kprobes and the tracepoint could agree on a key. The kprobes read the source port as `bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_num))`, converting from network to host byte order.

Comparing the tool's output against `ss -tn` for the same live connections settled it. Five of six connections matched exactly once the tool's value was byte-swapped. The kprobes were wrong: `skc_num` is stored in host byte order, unlike `skc_dport` which is network order, so applying `bpf_ntohs` to it swapped a value that was already correct. Removing the conversion fixed it.

The bug survived as long as it did because destination ports were always right. Those are the ones you look at. 443, 80 and 53 all appeared correctly and gave the impression the port handling was sound. Source ports are ephemeral and look like arbitrary five-digit numbers whether they are correct or not, so nothing looked wrong until there was something to compare against.

Fixing it also unblocked the connection cleanup, which had been impossible while the two hooks disagreed on the key.

### IPv4-mapped IPv6 sockets

Process attribution initially only worked for outbound connections, because the owning process is captured at `tcp_connect`, which only fires on the client side. Adding a kretprobe on `inet_csk_accept` should have covered the inbound side.

It did not. The probe loaded and attached, and `bpftrace` confirmed the hook was firing, but nothing was ever written to the map. The cause was a guard rejecting anything that was not AF_INET. Printing the socket state on return showed `family=10`, which is AF_INET6, on every accept. The Go HTTP server binds to the dual-stack wildcard address, so Linux accepts IPv4 connections onto an IPv6 socket, and every accept was being rejected before it did anything.

The addresses were still sitting in the IPv4 fields, so the fix was to stop rejecting family 10 rather than to extract mapped addresses from the IPv6 fields.

## What I would do differently

Field ordering in C structs has consequences that Java completely hides. Struct alignment padding caused deserialisation mismatches on the Go side more than once, because the compiler silently inserts bytes to keep fields aligned and Go's binary reader knows nothing about them. Ordering struct fields largest-first from the start would have avoided it.

More generally, every one of these bugs was silent. Nothing errored, nothing crashed, and the code looked right in all three cases. What actually found them was dumping the maps and comparing against a source of truth: `ss` for ports and `bpftrace` for socket state. In kernel programming you cannot attach a debugger and print statements are awkward, so inspecting live state is how you debug.
