package main

//go:generate bpf2go -cc clang -cflags "-O2 -g -Wall -target bpf -D__TARGET_ARCH_x86" TcpConnect ../../bpf/tcp_connect.c -- -I/usr/include/bpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("removing memlock: %v", err)
	}

	objs := TcpConnectObjects{}
	if err := LoadTcpConnectObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	kp, err := link.Kprobe("tcp_connect", objs.TcpConnectPrograms.TraceTcpConnect, nil)
	if err != nil {
		log.Fatalf("attaching kprobe: %v", err)
	}
	defer kp.Close()

	stopc := make(chan os.Signal, 1)
	signal.Notify(stopc, syscall.SIGINT, syscall.SIGTERM)

	rd, err := ringbuf.NewReader(objs.TcpConnectMaps.Events)
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

	fmt.Println("Listening for TCP connections... Press Ctrl+c to stop")

	for {
		select {
		case <-stopc:
			fmt.Println("Shutting down.")
			return

		default:
			record, err := rd.Read()
			if err != nil {
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

}

func intToBytes(ip uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, ip)
	return b
}
