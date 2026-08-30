package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var bytesTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "ebpf_network_bytes_total",
		Help: "Total bytes transferred, by direction.",
	},
	[]string{"direction"},
)

var packetsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "ebpf_network_packets_total",
		Help: "Total packets transferred, by direction",
	},
	[]string{"direction"},
)

var connectionsTotal = promauto.NewCounter(
	prometheus.CounterOpts{
		Name: "ebpf_network_connections_total",
		Help: "Total TCP connections opened.",
	},
)

var activeConnections = promauto.NewGauge(
	prometheus.GaugeOpts{
		Name: "ebpf_network_active_connections",
		Help: "Number of connections currently tracked",
	},
)

var connectLatency = promauto.NewHistogram(
	prometheus.HistogramOpts{
		Name:    "ebpf_network_connect_latency_seconds",
		Help:    "TCP connection establishment latency in seconds",
		Buckets: prometheus.ExponentialBuckets(0.0001, 2, 14),
	},
)

var connectionDuration = promauto.NewHistogram(
	prometheus.HistogramOpts{
		Name:    "ebpf_network_connection_duration_seconds",
		Help:    "TCP connection lifetime in seconds.",
		Buckets: prometheus.ExponentialBuckets(0.001, 3, 12),
	},
)
