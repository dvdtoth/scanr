package scanr

// +build darwin dragonfly freebsd netbsd openbsd

import (
	"golang.org/x/net/route"
	"net"
)

func (s *Scanr) getRoute() (gw net.IP, src net.IP, err error) {

	var defaultRoute = [4]byte{0, 0, 0, 0}

	rib, err := route.FetchRIB(0, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, nil, err
	}

	messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil, nil, err
	}

	for _, message := range messages {
		routeMessage := message.(*route.RouteMessage)
		addresses := routeMessage.Addrs
		var source, destination, gateway *route.Inet4Addr
		ok := false

		if destination, ok = addresses[0].(*route.Inet4Addr); !ok {
			continue
		}
		if gateway, ok = addresses[1].(*route.Inet4Addr); !ok {
			continue
		}
		if destination == nil || gateway == nil {
			continue
		}
		if source, ok = addresses[5].(*route.Inet4Addr); !ok {
			continue
		}

		if destination.IP == defaultRoute {
			gw, src = net.IP(gateway.IP[:]), net.IP(source.IP[:])
		}
	}

	return gw, src, nil
}
