package scanr

import (
	"errors"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"math/rand"
	"net"
	"time"
)

const (
	// IANA ephemeral port range
	min = 49152
	max = 65535
)

// Scanr struct
type Scanr struct {
	iface        *net.Interface
	dst, gw, src net.IP
	handle       *pcap.Handle
	opts         gopacket.SerializeOptions
	buf          gopacket.SerializeBuffer
	timeout      int
}

// NewScanr creates a new scanner
func NewScanr(iface *net.Interface, ip net.IP) (s *Scanr, err error) {

	s = &Scanr{
		dst: ip,
		opts: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		buf:     gopacket.NewSerializeBuffer(),
		timeout: 5,
	}

	// Darwin || Linux
	gw, src, err := s.getRoute()
	if err != nil {
		return nil, err
	}

	s.gw, s.src, s.iface = gw, src, iface

	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	s.handle = handle
	return s, nil
}

// Close a scan
func (s *Scanr) Close() {
	s.handle.Close()
}

// SYNscan ports
func (s *Scanr) SYNscan(dstPorts []uint16) error {

	srcPort := layers.TCPPort(randomPort())
	hwaddr, err := s.getHwAddr()
	if err != nil {
		return err
	}

	// Construct all the network layers
	eth := layers.Ethernet{
		SrcMAC:       s.iface.HardwareAddr,
		DstMAC:       hwaddr,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := layers.IPv4{
		SrcIP:    s.src,
		DstIP:    s.dst,
		Version:  4,
		TTL:      255,
		Protocol: layers.IPProtocolTCP,
		Flags:    0x02,
	}
	tcp := layers.TCP{
		SrcPort: srcPort,
		DstPort: layers.TCPPort(dstPorts[0]),
		SYN:     true,
		Window:  65535,
	}
	tcp.SetNetworkLayerForChecksum(&ip4)

	report := make(map[layers.TCPPort]string)
	ipFlow := gopacket.NewFlow(layers.EndpointIPv4, s.dst, s.src)
	start := time.Now()
	timeout := time.Duration(s.timeout)
	log.Printf("SYN Scanning %v", s.dst)

	i := 0
	for {
		if len(report) == len(dstPorts) {
			//log.Println("Scan finished.")
			return nil
		}
		// Send one packet per iteration
		if i <= len(dstPorts)-1 {
			tcp.DstPort = layers.TCPPort(dstPorts[i])
			start = time.Now()
			if err := s.send(&eth, &ip4, &tcp); err != nil {
				log.Printf("error sending to port %v: %v", tcp.DstPort, err)
			}
			i++
		}
		if time.Since(start) > time.Second*timeout {
			log.Printf("%v scan timed out", s.dst)
			return nil
		}

		// Read in the next packet.
		data, _, err := s.handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		} else if err != nil {
			log.Printf("error reading packet: %v", err)
			continue
		}

		// Parse the packet.  TODO use DecodingLayerParser
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)

		if net := packet.NetworkLayer(); net == nil {
			// log.Printf("packet has no network layer")
		} else if net.NetworkFlow() != ipFlow {
			// log.Printf("packet does not match our ip src/dst")
		} else if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer == nil {
			// log.Printf("packet has not tcp layer")
		} else if tcp, ok := tcpLayer.(*layers.TCP); !ok {
			// We panic here because this is guaranteed to never
			// happen.
			panic("tcp layer is not tcp layer :-/")
		} else if tcp.DstPort != srcPort {
			// log.Printf("dst port %v does not match", tcp.DstPort)
		} else if tcp.RST {
			if _, in := report[tcp.SrcPort]; !in {
				report[tcp.SrcPort] = "closed"
				//fmt.Fprintf(os.Stdout, "Scanning... Port %v closed\r", tcp.SrcPort)
			}
		} else if tcp.SYN && tcp.ACK {
			if _, in := report[tcp.SrcPort]; !in {
				report[tcp.SrcPort] = "open"
				log.Printf("port %v open\n", tcp.SrcPort)
			}
		} else {
			// log.Printf("ignoring useless packet")
		}
	}
}

func (s *Scanr) send(l ...gopacket.SerializableLayer) error {
	if err := gopacket.SerializeLayers(s.buf, s.opts, l...); err != nil {
		return err
	}
	return s.handle.WritePacketData(s.buf.Bytes())
}

func (s *Scanr) getHwAddr() (net.HardwareAddr, error) {
	start := time.Now()
	arpDst := s.dst
	if s.gw != nil {
		arpDst = s.gw
	}
	// Prepare the layers to send for an ARP request.
	eth := layers.Ethernet{
		SrcMAC:       s.iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(s.iface.HardwareAddr),
		SourceProtAddress: []byte(s.src),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(arpDst),
	}

	if err := s.send(&eth, &arp); err != nil {
		return nil, err
	}
	// Wait 3 seconds for an ARP reply.
	for {
		if time.Since(start) > time.Second*3 {
			return nil, errors.New("timeout getting ARP reply")
		}
		data, _, err := s.handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		} else if err != nil {
			return nil, err
		}
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
		if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
			arp := arpLayer.(*layers.ARP)
			if net.IP(arp.SourceProtAddress).Equal(net.IP(arpDst)) {
				return net.HardwareAddr(arp.SourceHwAddress), nil
			}
		}
	}
}

// Random port
func randomPort() uint16 {
	return uint16(rand.Intn(max-min) + min)
}
