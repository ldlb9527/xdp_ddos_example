package main

import (
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"log"
	"net"
	"net/netip"
	"strings"
	"time"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf xdp_parse.c

func main() {

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	//The network interface by name.
	ifaceName := "eth0"
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
	}

	// Load pre-compiled programs into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	// Attach the program.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpParserFunc,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer l.Close()

	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s, err := formatMapContents(&objs)
		if err != nil {
			log.Printf("Error reading map: %s", err)
			continue
		}
		log.Printf("Map contents:\n%s", s)
	}

}

func formatMapContents(obj *bpfObjects) (string, error) {
	var (
		sb  strings.Builder
		key netip.Addr
		val uint32
	)
	iter := obj.XdpStatsMap.Iterate()
	for iter.Next(&key, &val) {
		sourceIP := key // IPv4 source address in network byte order.
		packetCount := val
		sb.WriteString(fmt.Sprintf("\t%s => %d\n", sourceIP, packetCount))

		if packetCount > 200 {
			err := obj.XdpBlackListMap.Update(&key, &val, ebpf.UpdateAny)
			if err != nil {
				return "", nil
			}
		}
	}
	return sb.String(), iter.Err()
}
