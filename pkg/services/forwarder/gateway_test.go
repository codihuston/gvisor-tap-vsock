package forwarder

import (
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
)

func TestGatewayDefaultNone(t *testing.T) {
	gateway := tcpip.AddrFrom4([4]byte{192, 168, 200, 2})
	for _, active := range []bool{false, true} {
		for _, port := range []uint16{22, 80, 443, 8080, 65535} {
			if got := tcpRoutingAction(gateway, port, false, active, gateway, nil); got != tcpBlock {
				t.Errorf("TCP gateway:%d allowlist=%v: got %v, want blocked", port, active, got)
			}
		}
		if got := udpRoutingAction(gateway, 8080, false, active, gateway, nil); got != udpBlock {
			t.Errorf("UDP gateway allowlist=%v: got %v, want blocked", active, got)
		}
	}
}
