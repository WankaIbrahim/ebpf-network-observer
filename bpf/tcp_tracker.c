//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

struct event {
    u64 latency_ns;
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

struct latency_key {
    u32 saddr;
    u32 daddr;
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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct latency_key);
    __type(value, u64);
} conn_start_time SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct latency_key);
    __type(value, u64);
} conn_connect_time SEC(".maps");

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

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(trace_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size){
    struct conn_key key = {};
    key.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    key.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    key.sport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_num));
    key.dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    struct conn_stats *stats = bpf_map_lookup_elem(&conn_stats_map, &key);
    if (!stats) {
        struct conn_stats new_stats = {};
        bpf_map_update_elem(&conn_stats_map, &key, &new_stats, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&conn_stats_map, &key);
        if (!stats) return 0;
    }

    __sync_fetch_and_add(&stats->tx_bytes, size);
    __sync_fetch_and_add(&stats->tx_packets, 1);
    return 0;
}

SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(trace_tcp_recvmsg, struct sock *sk, struct msghdr *msg, size_t len, int flags, int *addr_len){
    struct conn_key  key = {};
    key.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    key.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    key.sport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_num));
    key.dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    struct conn_stats *stats = bpf_map_lookup_elem(&conn_stats_map, &key);
    if (!stats) {
        struct conn_stats new_stats = {};
        bpf_map_update_elem(&conn_stats_map, &key, &new_stats, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&conn_stats_map, &key);
        if (!stats) return 0;
    }

    __sync_fetch_and_add(&stats->rx_bytes, len);
    __sync_fetch_and_add(&stats->rx_packets, 1);
    return 0;
}

SEC("tracepoint/sock/inet_sock_set_state")
int trace_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx) {    
    u64 now = bpf_ktime_get_ns();
    u32 newstate = BPF_CORE_READ(ctx, newstate);
    u32 protocol = BPF_CORE_READ(ctx, protocol);
    u16 family = BPF_CORE_READ(ctx, family);

    if (family != 2)
        return 0;
    if (protocol != IPPROTO_TCP)
        return 0;

    struct latency_key key = {};
    u8 saddr_bytes[4];
    u8 daddr_bytes[4];
    bpf_probe_read_kernel(&saddr_bytes, sizeof(saddr_bytes), &ctx->saddr);
    bpf_probe_read_kernel(&daddr_bytes, sizeof(daddr_bytes), &ctx->daddr);

    key.saddr = *(u32 *)saddr_bytes;
    key.daddr = *(u32 *)daddr_bytes;
    key.dport = BPF_CORE_READ(ctx, dport);

    if (newstate == BPF_TCP_SYN_SENT) {
        bpf_map_update_elem(&conn_start_time, &key, &now, BPF_ANY);
    }

    if (newstate == BPF_TCP_ESTABLISHED) {
        u64 *start = bpf_map_lookup_elem(&conn_start_time, &key);
        if (start) {
            u64 latency = now - *start;
            bpf_map_update_elem(&conn_connect_time, &key, &now, BPF_ANY);
            bpf_map_delete_elem(&conn_start_time, &key);

            struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
            if (e) {
                e->saddr = key.saddr;
                e->daddr = key.daddr;
                e->dport = key.dport;
                e->latency_ns = latency;

                bpf_ringbuf_submit(e, 0);
            }
        }
    }

    if (newstate == BPF_TCP_CLOSE) {
        u64 *connected_at = bpf_map_lookup_elem(&conn_connect_time, &key);
        if (connected_at) {
            bpf_map_delete_elem(&conn_connect_time, &key);
            bpf_map_delete_elem(&conn_stats_map, &key);
        }
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";