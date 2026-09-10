package forwarder

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
)

func TestUDPRoutingAction(t *testing.T) {
	gateway := tcpip.AddrFrom4([4]byte{192, 168, 1, 1})
	other := tcpip.AddrFrom4([4]byte{8, 8, 8, 8})

	tests := []struct {
		name             string
		localAddress     tcpip.Address
		localPort        uint16
		blockAllOutbound bool
		allowlistActive  bool
		gatewayPortAllow map[uint16]bool
		expected         udpAction
	}{
		// --- No filtering (baseline) ---
		{
			name:             "NoFiltering",
			localAddress:     other,
			localPort:        80,
			blockAllOutbound: false,
			allowlistActive:  false,
			expected:         udpDirect,
		},
		{
			name:             "NoFilteringGateway",
			localAddress:     gateway,
			localPort:        80,
			blockAllOutbound: false,
			allowlistActive:  false,
			expected:         udpDirect,
		},

		// --- blockAllOutbound: normal cases ---
		{
			name:             "BlockAllOutbound",
			localAddress:     other,
			localPort:        80,
			blockAllOutbound: true,
			allowlistActive:  false,
			expected:         udpBlock,
		},

		// --- blockAllOutbound: overrides allowlist ---
		{
			name:             "BlockAllOverridesAllow",
			localAddress:     other,
			localPort:        80,
			blockAllOutbound: true,
			allowlistActive:  true,
			expected:         udpBlock,
		},

		// --- blockAllOutbound: blocks even gateway ---
		{
			name:             "BlockAllOutboundBlocksGateway",
			localAddress:     gateway,
			localPort:        80,
			blockAllOutbound: true,
			allowlistActive:  false,
			expected:         udpBlock,
		},
		{
			name:             "BlockAllOutboundBlocksGatewayWithAllowlist",
			localAddress:     gateway,
			localPort:        80,
			blockAllOutbound: true,
			allowlistActive:  true,
			expected:         udpBlock,
		},
		{
			name:             "BlockAllOutboundBlocksGatewayEvenWithPortAllow",
			localAddress:     gateway,
			localPort:        53,
			blockAllOutbound: true,
			allowlistActive:  true,
			gatewayPortAllow: map[uint16]bool{53: true},
			expected:         udpBlock,
		},

		// --- blockAllOutbound: special addresses ---
		{
			name:             "BlockAllOutboundLoopback",
			localAddress:     tcpip.AddrFrom4([4]byte{127, 0, 0, 1}),
			localPort:        80,
			blockAllOutbound: true,
			allowlistActive:  false,
			expected:         udpBlock,
		},
		{
			name:             "BlockAllOutboundBroadcast",
			localAddress:     tcpip.AddrFrom4([4]byte{255, 255, 255, 255}),
			localPort:        80,
			blockAllOutbound: true,
			allowlistActive:  false,
			expected:         udpBlock,
		},
		{
			name:             "BlockAllOutboundLinkLocal",
			localAddress:     tcpip.AddrFrom4([4]byte{169, 254, 169, 254}),
			localPort:        80,
			blockAllOutbound: true,
			allowlistActive:  false,
			expected:         udpBlock,
		},
		{
			name:             "BlockAllOutboundZeroAddress",
			localAddress:     tcpip.AddrFrom4([4]byte{0, 0, 0, 0}),
			localPort:        80,
			blockAllOutbound: true,
			allowlistActive:  false,
			expected:         udpBlock,
		},
		{
			name:             "BlockAllOutboundPrivateClassA",
			localAddress:     tcpip.AddrFrom4([4]byte{10, 0, 0, 1}),
			localPort:        80,
			blockAllOutbound: true,
			allowlistActive:  false,
			expected:         udpBlock,
		},
		{
			name:             "BlockAllOutboundPrivateClassC",
			localAddress:     tcpip.AddrFrom4([4]byte{192, 168, 0, 1}),
			localPort:        80,
			blockAllOutbound: true,
			allowlistActive:  false,
			expected:         udpBlock,
		},

		// --- blockAllOutbound: all exemptions combined ---
		{
			name:             "BlockAllOutboundOverridesEverything",
			localAddress:     gateway,
			localPort:        80,
			blockAllOutbound: true,
			allowlistActive:  true,
			expected:         udpBlock,
		},

		// --- Allowlist tests: gateway with no ports configured (default none) ---
		{
			name:             "AllowlistGatewayNoPortConfigured",
			localAddress:     gateway,
			localPort:        80,
			blockAllOutbound: false,
			allowlistActive:  true,
			expected:         udpBlock,
		},
		{
			name:             "AllowlistGatewayNoPortConfiguredPort53",
			localAddress:     gateway,
			localPort:        53,
			blockAllOutbound: false,
			allowlistActive:  true,
			expected:         udpBlock,
		},

		// --- Allowlist tests: gateway port allowlist ---
		{
			name:             "AllowlistGatewayConfiguredPortReachable",
			localAddress:     gateway,
			localPort:        53,
			blockAllOutbound: false,
			allowlistActive:  true,
			gatewayPortAllow: map[uint16]bool{53: true},
			expected:         udpDirect,
		},
		{
			name:             "AllowlistGatewayUnconfiguredPortRefused",
			localAddress:     gateway,
			localPort:        80,
			blockAllOutbound: false,
			allowlistActive:  true,
			gatewayPortAllow: map[uint16]bool{53: true},
			expected:         udpBlock,
		},

		{
			name:             "AllowlistNonGateway",
			localAddress:     other,
			localPort:        80,
			blockAllOutbound: false,
			allowlistActive:  true,
			expected:         udpBlock,
		},
		{
			name:             "AllowlistNonGatewayEvenWithGatewayPortAllow",
			localAddress:     other,
			localPort:        53,
			blockAllOutbound: false,
			allowlistActive:  true,
			gatewayPortAllow: map[uint16]bool{53: true},
			expected:         udpBlock,
		},
		{
			name:             "AllowlistBlocksLoopback",
			localAddress:     tcpip.AddrFrom4([4]byte{127, 0, 0, 1}),
			localPort:        80,
			blockAllOutbound: false,
			allowlistActive:  true,
			expected:         udpBlock,
		},
		{
			name:             "AllowlistBlocksPrivate",
			localAddress:     tcpip.AddrFrom4([4]byte{10, 0, 0, 1}),
			localPort:        80,
			blockAllOutbound: false,
			allowlistActive:  true,
			expected:         udpBlock,
		},

		// --- No filtering: special addresses ---
		{
			name:             "NoFilteringLoopback",
			localAddress:     tcpip.AddrFrom4([4]byte{127, 0, 0, 1}),
			localPort:        80,
			blockAllOutbound: false,
			allowlistActive:  false,
			expected:         udpDirect,
		},
		{
			name:             "NoFilteringZeroAddress",
			localAddress:     tcpip.AddrFrom4([4]byte{0, 0, 0, 0}),
			localPort:        80,
			blockAllOutbound: false,
			allowlistActive:  false,
			expected:         udpDirect,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := udpRoutingAction(tt.localAddress, tt.localPort, tt.blockAllOutbound, tt.allowlistActive, gateway, tt.gatewayPortAllow)
			require.Equal(t, tt.expected, got)
		})
	}
}

// TestUDPBlockAllOutboundIsAbsolute verifies that blockAllOutbound blocks
// every possible address — no exemptions exist, not even the gateway, even
// with a gatewayPortAllow entry for the port under test.
func TestUDPBlockAllOutboundIsAbsolute(t *testing.T) {
	gateway := tcpip.AddrFrom4([4]byte{192, 168, 1, 1})

	addresses := []tcpip.Address{
		gateway,
		tcpip.AddrFrom4([4]byte{8, 8, 8, 8}),
		tcpip.AddrFrom4([4]byte{0, 0, 0, 0}),
		tcpip.AddrFrom4([4]byte{127, 0, 0, 1}),
		tcpip.AddrFrom4([4]byte{255, 255, 255, 255}),
		tcpip.AddrFrom4([4]byte{169, 254, 169, 254}),
		tcpip.AddrFrom4([4]byte{10, 0, 0, 1}),
		tcpip.AddrFrom4([4]byte{172, 16, 0, 1}),
		tcpip.AddrFrom4([4]byte{192, 168, 0, 1}),
	}
	gatewayPortAllow := map[uint16]bool{53: true}

	for _, addr := range addresses {
		for _, allowlist := range []bool{false, true} {
			action := udpRoutingAction(addr, 53, true, allowlist, gateway, gatewayPortAllow)
			require.Equal(t, udpBlock, action,
				"blockAllOutbound must block addr=%s allowlist=%v",
				addr.String(), allowlist)
		}
	}
}

// TestUDPNoFilteringAlwaysAllows verifies that with both blockAllOutbound=false
// and no allowlist, all traffic is forwarded regardless of address.
func TestUDPNoFilteringAlwaysAllows(t *testing.T) {
	gateway := tcpip.AddrFrom4([4]byte{192, 168, 1, 1})

	addresses := []tcpip.Address{
		gateway,
		tcpip.AddrFrom4([4]byte{8, 8, 8, 8}),
		tcpip.AddrFrom4([4]byte{0, 0, 0, 0}),
		tcpip.AddrFrom4([4]byte{127, 0, 0, 1}),
		tcpip.AddrFrom4([4]byte{255, 255, 255, 255}),
	}

	for _, addr := range addresses {
		action := udpRoutingAction(addr, 80, false, false, gateway, nil)
		require.Equal(t, udpDirect, action,
			"no filtering must allow addr=%s", addr.String())
	}
}

// TestUDPAllowlistBlocksAllNonGateway verifies that when the allowlist is
// active (without blockAllOutbound), no non-gateway address is ever
// forwarded over UDP, regardless of port or gatewayPortAllow.
func TestUDPAllowlistBlocksAllNonGateway(t *testing.T) {
	gateway := tcpip.AddrFrom4([4]byte{192, 168, 1, 1})

	blocked := []tcpip.Address{
		tcpip.AddrFrom4([4]byte{8, 8, 8, 8}),
		tcpip.AddrFrom4([4]byte{1, 1, 1, 1}),
		tcpip.AddrFrom4([4]byte{0, 0, 0, 0}),
		tcpip.AddrFrom4([4]byte{127, 0, 0, 1}),
		tcpip.AddrFrom4([4]byte{255, 255, 255, 255}),
		tcpip.AddrFrom4([4]byte{10, 0, 0, 1}),
		tcpip.AddrFrom4([4]byte{192, 168, 0, 1}),   // close to gateway but different
		tcpip.AddrFrom4([4]byte{192, 168, 1, 2}),   // same subnet, different host
		tcpip.AddrFrom4([4]byte{192, 168, 1, 0}),   // same subnet, network address
		tcpip.AddrFrom4([4]byte{192, 168, 1, 255}), // same subnet, broadcast
	}
	gatewayPortAllow := map[uint16]bool{53: true}

	for _, addr := range blocked {
		action := udpRoutingAction(addr, 53, false, true, gateway, gatewayPortAllow)
		require.Equal(t, udpBlock, action,
			"allowlist must block non-gateway addr=%s even on an allowed gateway port", addr.String())
	}
}

// TestUDPGatewayPortAllowlist verifies the register #1 fix in both
// directions: with the allowlist active and a gatewayPortAllow configured,
// a named port on the gateway address is reachable and every other port is
// refused — including with no gatewayPortAllow configured at all (default
// none), where every port on the gateway is refused.
func TestUDPGatewayPortAllowlist(t *testing.T) {
	gateway := tcpip.AddrFrom4([4]byte{192, 168, 1, 1})

	t.Run("DefaultNoneRefusesEveryPort", func(t *testing.T) {
		for _, port := range []uint16{0, 1, 53, 80, 443, 8080, 65535} {
			action := udpRoutingAction(gateway, port, false, true, gateway, nil)
			require.Equal(t, udpBlock, action,
				"gateway port=%d must be refused with no gatewayPortAllow configured", port)
		}
	})

	t.Run("ConfiguredPortReachable", func(t *testing.T) {
		gatewayPortAllow := map[uint16]bool{53: true, 8443: true}
		for _, port := range []uint16{53, 8443} {
			action := udpRoutingAction(gateway, port, false, true, gateway, gatewayPortAllow)
			require.Equal(t, udpDirect, action,
				"configured gateway port=%d must be reachable", port)
		}
	})

	t.Run("UnconfiguredPortRefused", func(t *testing.T) {
		gatewayPortAllow := map[uint16]bool{53: true}
		for _, port := range []uint16{0, 1, 52, 54, 80, 443, 65535} {
			action := udpRoutingAction(gateway, port, false, true, gateway, gatewayPortAllow)
			require.Equal(t, udpBlock, action,
				"unconfigured gateway port=%d must be refused", port)
		}
	})
}

// TestUDPRoutingActionZeroGateway verifies behavior when no gateway IP is
// configured (zero-value address). No address should match the gateway
// port-allowlist path except the zero address itself, and even that stays
// blocked with no gatewayPortAllow configured.
func TestUDPRoutingActionZeroGateway(t *testing.T) {
	var zeroGateway tcpip.Address
	other := tcpip.AddrFrom4([4]byte{8, 8, 8, 8})

	// Non-zero address is blocked when allowlist active
	action := udpRoutingAction(other, 80, false, true, zeroGateway, nil)
	require.Equal(t, udpBlock, action)

	// Zero address matches zero gateway, but no port is allowed by default
	action = udpRoutingAction(zeroGateway, 80, false, true, zeroGateway, nil)
	require.Equal(t, udpBlock, action)

	// Zero address matches zero gateway and its port is explicitly allowed
	action = udpRoutingAction(zeroGateway, 80, false, true, zeroGateway, map[uint16]bool{80: true})
	require.Equal(t, udpDirect, action)

	// blockAllOutbound still blocks everything
	action = udpRoutingAction(other, 80, true, false, zeroGateway, nil)
	require.Equal(t, udpBlock, action)

	action = udpRoutingAction(zeroGateway, 80, true, true, zeroGateway, map[uint16]bool{80: true})
	require.Equal(t, udpBlock, action)
}
