package main

//go:generate bpf2go -cc clang -cflags "-O2 -g -Wall -target bpf -D__TARGET_ARCH_x86" TcpTracker ../../bpf/tcp_tracker.c -- -I/usr/include/bpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("removing memlock: %v", err)
	}

	objs := TcpTrackerObjects{}
	if err := LoadTcpTrackerObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	kpConnect, err := link.Kprobe("tcp_connect", objs.TcpTrackerPrograms.TraceTcpConnect, nil)
	if err != nil {
		log.Fatalf("attaching tcp_connect kprobe: %v", err)
	}
	defer kpConnect.Close()

	kpSend, err := link.Kprobe("tcp_sendmsg", objs.TcpTrackerPrograms.TraceTcpSendmsg, nil)
	if err != nil {
		log.Fatalf("attaching tcp_sendmsg kprobe: %v", err)
	}
	defer kpSend.Close()

	kpRecv, err := link.Kprobe("tcp_recvmsg", objs.TcpTrackerPrograms.TraceTcpRecvmsg, nil)
	if err != nil {
		log.Fatalf("attaching tcp_recvmsg kprobe: %v", err)
	}
	defer kpRecv.Close()

	stopc := make(chan os.Signal, 1)
	signal.Notify(stopc, syscall.SIGINT, syscall.SIGTERM)

	rd, err := ringbuf.NewReader(objs.TcpTrackerMaps.Events)
	if err != nil {
		log.Fatalf("opening ring buffer: %v", err)
	}

	defer rd.Close()

	type Event struct {
		Pid   uint32
		Saddr uint32
		Daddr uint32
		Dport uint16
		Comm  [16]byte
	}

	type ConnKey struct {
		Saddr uint32
		Daddr uint32
		Sport uint16
		Dport uint16
	}

	type ConnStats struct {
		TxBytes uint64
		RxBytes uint64
		TxPackets uint64
		RxPackets uint64
	}

	fmt.Println("Listening for TCP connections... Press Ctrl+c to stop")

	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <- stopc:
				return
			case <- ticker.C:
				fmt.Println("\n--- Connection Stats ---")

				var key ConnKey
				var stats ConnStats
			
				iter := objs.TcpTrackerMaps.ConnStatsMap.Iterate()
				for iter.Next(&key, &stats) {
					src := net.IP(intToBytes(key.Saddr))
					dst := net.IP(intToBytes(key.Daddr))
					fmt.Printf("SRC: %-20s DST: %-20s TX: %d bytes (%d packets) RX: %d bytes (%d packets)\n",
						fmt.Sprintf("%s:%d", src, key.Sport),
						fmt.Sprintf("%s:%d", dst, key.Dport),
						stats.TxBytes, stats.TxPackets,
						stats.RxBytes, stats.RxPackets	)
				}

				if err := iter.Err(); err != nil {
					log.Printf("iterating map: %v", err)
				}			
			}
		}

	}()

	go func() {
		<-stopc
		rd.Close()
	}()

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

		src := net.IP(intToBytes(event.Saddr))
		dst := net.IP(intToBytes(event.Daddr))
		comm := string(bytes.TrimRight(event.Comm[:], "\x00"))

		fmt.Printf("PID: %-6d COMM: %-20s SRC: %-20s DST: %s:%d\n",
			event.Pid, comm, src, dst, event.Dport)

	}

}

func intToBytes(ip uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, ip)
	return b
}
