package forwarder

import (
	"github.com/containers/gvisor-tap-vsock/pkg/services/egresslog"
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
// the destination address and active filtering configuration.
func udpRoutingAction(
	localAddress tcpip.Address,
	localPort uint16,
	blockAllOutbound bool,
	allowlistActive bool,
	gatewayAddr tcpip.Address,
	gatewayPorts []int,
) udpAction {
	if gatewayAddr.Len() != 0 && localAddress == gatewayAddr {
		if gatewayPortAllowed(localPort, gatewayPorts) {
			return udpDirect
		}
		return udpBlock
	}
	if blockAllOutbound {
		return udpBlock
	}
	if allowlistActive {
		return udpBlock
	}
	return udpDirect
}

func UDP(s *stack.Stack, nat map[tcpip.Address]tcpip.Address, natLock *sync.Mutex, blockAllOutbound bool, outboundAllow []*regexp.Regexp, gatewayIP net.IP, gatewayPorts []int) *udp.Forwarder {
	allowlistActive := len(outboundAllow) > 0
	var gatewayAddr tcpip.Address
	if gatewayIP != nil {
		gatewayAddr = tcpip.AddrFrom4Slice(gatewayIP.To4())
	}

	return udp.NewForwarder(s, func(r *udp.ForwarderRequest) {
		localAddress := r.ID().LocalAddress

		action := udpRoutingAction(localAddress, r.ID().LocalPort, blockAllOutbound, allowlistActive, gatewayAddr, gatewayPorts)
		if action == udpBlock {
			egresslog.Default.Denied(egresslog.UDP, "Blocking outbound UDP to %s:%d (%s)", localAddress.String(), r.ID().LocalPort, denialReason(localAddress, gatewayAddr, blockAllOutbound))
			return
		}

		if linkLocal().Contains(localAddress) || localAddress == header.IPv4Broadcast {
			return
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
			return
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
	})
}
