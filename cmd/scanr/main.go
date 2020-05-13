package main

import (
	"flag"
	"fmt"
	"github.com/dvdtoth/scanr/internal/scanr"
	"log"
	"math/rand"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

func main() {
	rand.Seed(time.Now().UnixNano())

	iface, ip, ports := parseCmd()
	s, err := scanr.NewScanr(iface, ip)

	if err != nil {
		log.Printf("unable to create scanner for %v: %v", ip, err)
	}
	if err := s.SYNscan(ports); err != nil {
		log.Printf("unable to scan %v: %v", ip, err)
	}
	s.Close()
}

func parseCmd() (iface *net.Interface, ip net.IP, ports []uint16) {

	var ifName = flag.String("i", "en0", "network adapter")
	var targetIP = flag.String("t", "127.0.0.1", "target IPv4 address")
	var targetPorts = flag.String("p", "80,443", "single port, or comma separated list [80,443], or range [0-65535] of target ports")

	flag.Parse()
	if flag.NFlag() != 3 {
		fmt.Fprintf(os.Stdout, "Usage: %s -i <interface> -t <target IPv4> -p <port>\n", os.Args[0])
		os.Exit(1)
	}

	iface, err := net.InterfaceByName(*ifName)
	if err != nil {
		panic(err)
	}

	if ip = net.ParseIP(*targetIP); ip == nil {
		log.Printf("non-ip target: %q", *targetIP)
		os.Exit(1)
	} else if ip = ip.To4(); ip == nil {
		log.Printf("non-ipv4 target: %q", *targetIP)
		os.Exit(1)
	}

	if strings.Count(*targetPorts, "-") == 1 {
		portStrings := strings.Split(*targetPorts, "-")
		var portRange []uint64
		for _, p := range portStrings {
			i, err := strconv.ParseUint(p, 10, 16)
			if err != nil {
				panic(err)
			}
			portRange = append(portRange, i)
		}
		sort.Slice(portRange, func(i, j int) bool { return portRange[i] < portRange[j] })

		for i := portRange[0]; i <= portRange[1]; i++ {
			ports = append(ports, uint16(i))
		}
	} else if strings.Count(*targetPorts, ",") > 0 {
		portList := strings.Split(*targetPorts, ",")
		for _, p := range portList {
			portUInt, _ := strconv.ParseUint(p, 10, 16)
			ports = append(ports, uint16(portUInt))
		}
	} else {
		port, err := strconv.ParseUint(*targetPorts, 10, 16)
		if err != nil {
			panic(err)
		}
		ports = append(ports, uint16(port))
	}

	return iface, ip, ports
}
