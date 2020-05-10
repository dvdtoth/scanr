package scanr

// +build linux

import (
	"github.com/google/gopacket/routing"
	"net"
)

func (s *Scanr) getRoute() (gw net.IP, src net.IP, err error) {

	router, err := routing.New()
	if err != nil {
		return nil, nil, err
	}

	_, gw, src, err = router.Route(s.dst)
	if err != nil {
		return nil, nil, err
	}

	return gw, src, nil
}
