package main

//go:generate bpf2go -cc clang -cflags "-O2 -g -Wall -target bpf -D__TARGET_ARCH_x86" TcpTracker ../../bpf/tcp_tracker.c -- -I/usr/include/bpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	eventTypeConnect = 0
	eventTypeLatency = 1
	eventTypeClose   = 2

	metricsAddr  = ":2112"
	pollInterval = 2 * time.Second

	maxProcessLabels = 150
)

var (
	verbose = flag.Bool("v", false, "print individual events to stdout")

	seenProcessesMu sync.Mutex
	seenProcesses = make(map[string]bool)

	scanner = newScanDetector()
)

type Event struct {
	LatencyNs  uint64
	DurationNs uint64
	Pid        uint32
	Saddr      uint32
	Daddr      uint32
	Dport      uint16
	EventType  uint8
	Comm       [16]byte
}

type ConnKey struct {
	Saddr uint32
	Daddr uint32
	Sport uint16
	Dport uint16
}

type ConnStats struct {
	TxBytes   uint64
	RxBytes   uint64
	TxPackets uint64
	RxPackets uint64
	Pid       uint32
	Comm      [16]byte
	_         [4]byte
}

type reported struct {
	txBytes   uint64
	rxBytes   uint64
	txPackets uint64
	rxPackets uint64
}

func main() {
	flag.Parse()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("removing memlock: %v", err)
	}

	objs := TcpTrackerObjects{}
	if err := LoadTcpTrackerObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	links, err := attachProbes(&objs)
	if err != nil {
		log.Fatalf("attaching probes: %v", err)
	}
	defer closeLinks(links)

	stopc := make(chan os.Signal, 1)
	signal.Notify(stopc, syscall.SIGINT, syscall.SIGTERM)

	rd, err := ringbuf.NewReader(objs.TcpTrackerMaps.Events)
	if err != nil {
		log.Fatalf("opening ring buffer: %v", err)
	}
	defer rd.Close()

	go servePrometheus(metricsAddr)
	go pollStats(objs.TcpTrackerMaps.ConnStatsMap, stopc)

	go func() {
		<-stopc
		rd.Close()
	}()

	fmt.Println("Listening for TCP connections... Press Ctrl+c to stop")
	handleEvents(rd)
}

// attachProbes attaches all eBPF programs to their kernel hooks and returns
// the resulting links so they can be detached on shutdown.
func attachProbes(objs *TcpTrackerObjects) ([]link.Link, error) {
	var links []link.Link

	kpConnect, err := link.Kprobe("tcp_connect", objs.TcpTrackerPrograms.TraceTcpConnect, nil)
	if err != nil {
		closeLinks(links)
		return nil, fmt.Errorf("tcp_connect kprobe: %w", err)
	}
	links = append(links, kpConnect)

	kpSend, err := link.Kprobe("tcp_sendmsg", objs.TcpTrackerPrograms.TraceTcpSendmsg, nil)
	if err != nil {
		closeLinks(links)
		return nil, fmt.Errorf("tcp_sendmsg kprobe: %w", err)
	}
	links = append(links, kpSend)

	kpRecv, err := link.Kprobe("tcp_recvmsg", objs.TcpTrackerPrograms.TraceTcpRecvmsg, nil)
	if err != nil {
		closeLinks(links)
		return nil, fmt.Errorf("tcp_recvmsg kprobe: %w", err)
	}
	links = append(links, kpRecv)

	tp, err := link.Tracepoint("sock", "inet_sock_set_state", objs.TcpTrackerPrograms.TraceInetSockSetState, nil)
	if err != nil {
		closeLinks(links)
		return nil, fmt.Errorf("inet_sock_set_state tracepoint: %w", err)
	}
	links = append(links, tp)

	krAccept, err := link.Kretprobe("inet_csk_accept", objs.TcpTrackerPrograms.TraceInetCskAccept, nil)
	if err != nil {
		closeLinks(links)
		return nil, fmt.Errorf("inet_csk_accept kretprobe: %w", err)
	}
	links = append(links, krAccept)

	return links, nil
}

func closeLinks(links []link.Link) {
	for _, l := range links {
		l.Close()
	}
}

// servePrometheus exposes the metrics endpoint. Blocks until the server exits.
func servePrometheus(addr string) {
	http.Handle("/metrics", promhttp.Handler())
	log.Printf("Serving metrics on %s/metrics", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("serving metrics: %v", err)
	}
}

// pollStats periodically reads the per-connection stats map and publishes the
// deltas since the previous poll as Prometheus counters.
func pollStats(m *ebpf.Map, stopc <-chan os.Signal) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	lastReported := make(map[ConnKey]reported)

	for {
		select {
		case <-stopc:
			return
		case <-ticker.C:
			if *verbose {
				fmt.Println("\n--- Connection Stats ---")
			}

			var key ConnKey
			var stats ConnStats
			var count int
			procCounts := make(map[string]int)

			iter := m.Iterate()
			for iter.Next(&key, &stats) {
				count++
				last := lastReported[key]
				if stats.TxBytes < last.txBytes {
					last = reported{}
				}

				bytesTotal.WithLabelValues("tx").Add(float64(stats.TxBytes - last.txBytes))
				bytesTotal.WithLabelValues("rx").Add(float64(stats.RxBytes - last.rxBytes))
				packetsTotal.WithLabelValues("tx").Add(float64(stats.TxPackets - last.txPackets))
				packetsTotal.WithLabelValues("rx").Add(float64(stats.RxPackets - last.rxPackets))

				comm := processLabel(string(bytes.TrimRight(stats.Comm[:], "\x00")))
				procCounts[comm]++

				processBytesTotal.WithLabelValues(comm, "tx").Add(float64(stats.TxBytes - last.txBytes))
				processBytesTotal.WithLabelValues(comm, "rx").Add(float64(stats.RxBytes - last.rxBytes))

				lastReported[key] = reported{
					txBytes:   stats.TxBytes,
					rxBytes:   stats.RxBytes,
					txPackets: stats.TxPackets,
					rxPackets: stats.RxPackets,
				}

				if *verbose {
					src := net.IP(intToBytes(key.Saddr))
					dst := net.IP(intToBytes(key.Daddr))
					fmt.Printf("SRC: %-20s DST: %-20s COMM: %-16s TX: %d bytes (%d packets) RX: %d bytes (%d packets)\n",
						fmt.Sprintf("%s:%d", src, key.Sport),
						fmt.Sprintf("%s:%d", dst, key.Dport),
						comm,
						stats.TxBytes, stats.TxPackets,
						stats.RxBytes, stats.RxPackets)
				}
			}

			activeConnections.Set(float64(count))

			processConnectionsActive.Reset()
			for p, n := range procCounts {
				processConnectionsActive.WithLabelValues(p).Set(float64(n))
			}

			if err := iter.Err(); err != nil {
				log.Printf("iterating map: %v", err)
			}
		}
	}
}

// handleEvents reads connection events off the ring buffer until it is closed.
func handleEvents(rd *ringbuf.Reader) {
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				fmt.Println("Shutting down.")
				return
			}
			log.Printf("reading ring buffer: %v", err)
			continue
		}

		var event Event
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing event: %v", err)
			continue
		}

		recordEvent(event)
	}
}

// recordEvent publishes a single event to Prometheus and optionally prints it.
func recordEvent(event Event) {
	src := net.IP(intToBytes(event.Saddr))
	dst := net.IP(intToBytes(event.Daddr))

	switch event.EventType {
	case eventTypeConnect:
		connectionsTotal.Inc()
		comm := string(bytes.TrimRight(event.Comm[:], "\x00"))
		dest := fmt.Sprintf("%s:%d", dst, event.Dport)

		if scanner.observe(comm, dest) {
			label := processLabel(comm)
			anomaliesTotal.WithLabelValues("port_scan", label).Inc()
			log.Printf("ANOMALY: possible scan. Process %q contacted %d distinct destinations in %s",
				comm, scanThreshold, scanWindow)
		}

		if *verbose {
			comm := string(bytes.TrimRight(event.Comm[:], "\x00"))
			fmt.Printf("PID: %-6d COMM: %-20s SRC: %-20s DST: %s:%d\n",
				event.Pid, comm, src, dst, event.Dport)
		}
	case eventTypeLatency:
		connectLatency.Observe(float64(event.LatencyNs) / 1e9)
		if *verbose {
			fmt.Printf("LATENCY: %s -> %s:%d took %.2fms to establish\n",
				src, dst, event.Dport, float64(event.LatencyNs)/1e6)
		}
	case eventTypeClose:
		connectionDuration.Observe(float64(event.DurationNs) / 1e9)
		if *verbose {
			fmt.Printf("CLOSED: %s -> %s:%d lasted %.2fs\n",
				src, dst, event.Dport, float64(event.DurationNs)/1e9)
		}
	}
}

// processLabel bound label cardinallity by bucketing uattributed connections
// as "unknown" and any process beyond maxProcessLabels as "other".
func processLabel(comm string) string {
	seenProcessesMu.Lock()
	defer seenProcessesMu.Unlock()

	if comm == "" {
		return "unknown"
	}

	if seenProcesses[comm] {
		return comm
	}

	if len(seenProcesses) >= maxProcessLabels {
		return "other"
	}

	seenProcesses[comm] = true
	return comm
}

func intToBytes(ip uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, ip)
	return b
}
