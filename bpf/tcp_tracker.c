//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

struct event {
    u32 pid;
    u32 saddr;
    u32 daddr;
    u16 dport;
    u8 comm[16];
};

struct conn_key {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport; 
} __attribute__((packed));

struct conn_stats {
    u64 tx_bytes;
    u64 rx_bytes;
    u64 tx_packets;
    u64 rx_packets;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct conn_key);
    __type(value, struct conn_stats);
} conn_stats_map SEC(".maps");

SEC("kprobe/tcp_connect")
int BPF_KPROBE(trace_tcp_connect, struct sock *sk) {
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    e->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    e->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    bpf_ringbuf_submit(e, 0);
    return 0;
} 

char LICENSE[] SEC("license") = "GPL";