package forwarder

import "gvisor.dev/gvisor/pkg/tcpip"

func gatewayPortAllowed(port uint16, ports []int) bool {
	if port == 0 {
		return false
	}
	for _, allowed := range ports {
		if int(port) == allowed {
			return true
		}
	}
	return false
}

func denialReason(address, gateway tcpip.Address, denyAll bool) string {
	if gateway.Len() != 0 && address == gateway {
		return "gateway port not in gatewayAllowedPorts"
	}
	if denyAll {
		return "blockAllOutbound=true"
	}
	return "outboundAllow active"
}
