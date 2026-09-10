package forwarder

import (
	"net"
	"regexp"
	"strconv"
	"sync"

	log "github.com/sirupsen/logrus"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

type udpAction int

const (
	udpBlock udpAction = iota
	udpDirect
)

// udpRoutingAction decides what to do with an inbound UDP packet based on
// the destination address, port, and active filtering configuration.
// gatewayPortAllow names the only ports on gatewayAddr reachable while the
// allowlist is active (default: none) — gatewayAddr is otherwise filtered
// exactly like any other destination, never exempted outright.
func udpRoutingAction(
	localAddress tcpip.Address,
	localPort uint16,
	blockAllOutbound bool,
	allowlistActive bool,
	gatewayAddr tcpip.Address,
	gatewayPortAllow map[uint16]bool,
) udpAction {
	if blockAllOutbound {
		return udpBlock
	}
	if allowlistActive {
		if localAddress == gatewayAddr {
			if gatewayPortAllow[localPort] {
				return udpDirect
			}
			return udpBlock
		}
		return udpBlock
	}
	return udpDirect
}

func UDP(s *stack.Stack, nat map[tcpip.Address]tcpip.Address, natLock *sync.Mutex, blockAllOutbound bool, outboundAllow []*regexp.Regexp, gatewayIP net.IP, gatewayPortAllow map[uint16]bool) *udp.Forwarder {
	allowlistActive := len(outboundAllow) > 0
	var gatewayAddr tcpip.Address
	if gatewayIP != nil {
		gatewayAddr = tcpip.AddrFrom4Slice(gatewayIP.To4())
	}

	return udp.NewForwarder(s, func(r *udp.ForwarderRequest) bool {
		localAddress := r.ID().LocalAddress
		localPort := r.ID().LocalPort

		action := udpRoutingAction(localAddress, localPort, blockAllOutbound, allowlistActive, gatewayAddr, gatewayPortAllow)
		if action == udpBlock {
			switch {
			case blockAllOutbound:
				log.Debugf("Blocking outbound UDP to %s:%d (blockAllOutbound=true)",
					localAddress.String(), localPort)
			case localAddress == gatewayAddr:
				log.Debugf("Blocking outbound UDP to gateway %s:%d (not in gatewayPortAllow)",
					localAddress.String(), localPort)
			default:
				log.Debugf("Blocking outbound UDP to %s:%d (outboundAllow active, non-gateway)",
					localAddress.String(), localPort)
			}
			// Mark handled so the stack does not send back an ICMP port
			// unreachable for a deliberately blocked destination.
			return true
		}

		if linkLocal().Contains(localAddress) || localAddress == header.IPv4Broadcast {
			return true
		}

		natLock.Lock()
		if replaced, ok := nat[localAddress]; ok {
			localAddress = replaced
		}
		natLock.Unlock()

		var wq waiter.Queue
		ep, tcpErr := r.CreateEndpoint(&wq)
		if tcpErr != nil {
			if _, ok := tcpErr.(*tcpip.ErrConnectionRefused); ok {
				// transient error
				log.Debugf("r.CreateEndpoint() = %v", tcpErr)
			} else {
				log.Errorf("r.CreateEndpoint() = %v", tcpErr)
			}
			return false
		}

		p, _ := NewUDPProxy(&autoStoppingListener{underlying: gonet.NewUDPConn(&wq, ep)}, func() (net.Conn, error) {
			return net.Dial("udp", net.JoinHostPort(localAddress.String(), strconv.Itoa(int(r.ID().LocalPort))))
		})
		go func() {
			p.Run()

			// note that at this point packets that are sent to the current forwarder session
			// will be dropped. We will start processing the packets again when we get a new
			// forwarder request.
			ep.Close()
		}()
		return true
	})
}
