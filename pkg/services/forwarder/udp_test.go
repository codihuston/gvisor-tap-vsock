package forwarder

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// Exercise both production routing functions across independent gateway and
// external policies. A broker exception never opens that port on other hosts.
func TestRoutingPolicies(t *testing.T) {
	gateway := tcpip.AddrFrom4([4]byte{192, 168, 200, 2})
	other := tcpip.AddrFrom4([4]byte{8, 8, 8, 8})
	for _, denyAll := range []bool{false, true} {
		for _, filtering := range []bool{false, true} {
			for _, configured := range [][]int{nil, {}, {8080}, {443, 8080, 65535}, {0, -1, 65536}} {
				for _, port := range []uint16{0, 1, 22, 53, 80, 443, 8080, 65535} {
					name := fmt.Sprintf("deny=%v/filter=%v/ports=%v/port=%d", denyAll, filtering, configured, port)
					t.Run(name, func(t *testing.T) {
						tcpWant, udpWant := tcpBlock, udpBlock
						for _, allowed := range configured {
							if port != 0 && int(port) == allowed {
								tcpWant, udpWant = tcpDirect, udpDirect
							}
						}
						require.Equal(t, tcpWant, tcpRoutingAction(gateway, port, denyAll, filtering, gateway, configured))
						require.Equal(t, udpWant, udpRoutingAction(gateway, port, denyAll, filtering, gateway, configured))
						tcpWant, udpWant = tcpDirect, udpDirect
						if denyAll || filtering {
							tcpWant, udpWant = tcpBlock, udpBlock
						}
						if !denyAll && filtering && port == 443 {
							tcpWant = tcpTLSAllowlist
						}
						require.Equal(t, tcpWant, tcpRoutingAction(other, port, denyAll, filtering, gateway, configured))
						require.Equal(t, udpWant, udpRoutingAction(other, port, denyAll, filtering, gateway, configured))
					})
				}
			}
		}
	}
}

func TestUnconfiguredGatewayHasNoException(t *testing.T) {
	var unset tcpip.Address
	require.Equal(t, tcpBlock, tcpRoutingAction(unset, 8080, false, true, unset, []int{8080}))
	require.Equal(t, udpBlock, udpRoutingAction(unset, 8080, false, true, unset, []int{8080}))
	require.Equal(t, tcpTLSAllowlist, tcpRoutingAction(unset, 443, false, true, unset, []int{443}))
}
