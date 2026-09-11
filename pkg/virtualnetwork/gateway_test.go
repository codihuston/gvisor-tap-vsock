package virtualnetwork

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/containers/gvisor-tap-vsock/pkg/services/forwarder"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/tap"
	"github.com/containers/gvisor-tap-vsock/pkg/types"
	dnswire "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const gatewayIP = "192.168.200.2"
const guestIP = "192.168.200.3"

// Real guest and router stacks exchange IP packets. Only the Ethernet/VM link is
// replaced; the production services, forwarders, DNS, NAT and host dials run.
func testNetwork(t *testing.T, config types.Configuration) (*stack.Stack, *stack.Stack) {
	t.Helper()
	if config.Subnet == "" {
		config.Subnet = "192.168.200.0/24"
	}
	if config.GatewayIP == "" {
		config.GatewayIP = gatewayIP
	}
	if config.NAT == nil {
		config.NAT = map[string]string{config.GatewayIP: "127.0.0.1"}
	}
	config.GatewayMacAddress = "5a:94:ef:e4:0c:dd"
	routerLink := channel.New(128, 1500, "")
	guestLink := channel.New(128, 1500, "")
	router, err := createStack(&config, routerLink)
	require.NoError(t, err)
	guestConfig := config
	guestAddr := net.ParseIP(config.GatewayIP).To4()
	guestAddr[3]++
	guestConfig.GatewayIP = guestAddr.String()
	guest, err := createStack(&guestConfig, guestLink)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); guest.Close(); router.Close(); guestLink.Close(); routerLink.Close() })
	pump := func(from, to *channel.Endpoint) {
		for {
			p := from.ReadContext(ctx)
			if p == nil {
				return
			}
			inbound := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithView(p.ToView())})
			to.InjectInbound(p.NetworkProtocolNumber, inbound)
			inbound.DecRef()
			p.DecRef()
		}
	}
	go pump(guestLink, routerLink)
	go pump(routerLink, guestLink)
	_, subnet, err := net.ParseCIDR(config.Subnet)
	require.NoError(t, err)
	_, err = addServices(&config, router, tap.NewIPPool(subnet))
	require.NoError(t, err)
	return guest, router
}

func TestGatewayForwarding(t *testing.T) {
	for _, transport := range []string{"tcp", "udp"} {
		for _, mode := range []string{"unfiltered", "filtering", "deny-all", "deny-all-with-patterns"} {
			t.Run(transport+"/"+mode, func(t *testing.T) {
				port := echoHost(t, transport)
				config := types.Configuration{}
				if mode == "filtering" || mode == "deny-all-with-patterns" {
					config.OutboundAllow = []string{`^allowed\.example$`}
				}
				config.BlockAllOutbound = mode == "deny-all" || mode == "deny-all-with-patterns"
				for _, allowed := range []bool{true, false} {
					t.Run(fmt.Sprint("allowed=", allowed), func(t *testing.T) {
						config.GatewayAllowedPorts = nil
						if allowed {
							config.GatewayAllowedPorts = []int{port}
						}
						guest, _ := testNetwork(t, config)
						remote := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4Slice(net.ParseIP(gatewayIP).To4()), Port: uint16(port)}
						var conn net.Conn
						var err error
						if transport == "tcp" {
							ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
							defer cancel()
							conn, err = gonet.DialContextTCP(ctx, guest, remote, ipv4.ProtocolNumber)
						} else {
							conn, err = gonet.DialUDP(guest, nil, &remote, ipv4.ProtocolNumber)
						}
						if !allowed && transport == "tcp" {
							require.Error(t, err)
							return
						}
						require.NoError(t, err)
						defer conn.Close()
						deadline := 10 * time.Second
						if !allowed {
							deadline = 300 * time.Millisecond
						}
						require.NoError(t, conn.SetDeadline(time.Now().Add(deadline)))
						_, err = conn.Write([]byte("broker"))
						require.NoError(t, err)
						buf := make([]byte, 6)
						_, err = io.ReadFull(conn, buf)
						if allowed {
							require.NoError(t, err)
							require.Equal(t, "broker", string(buf))
						} else {
							require.Error(t, err)
						}
					})
				}
			})
		}
	}
}

func echoHost(t *testing.T, transport string) int {
	t.Helper()
	if transport == "tcp" {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() { defer c.Close(); io.Copy(c, c) }()
			}
		}()
		return ln.Addr().(*net.TCPAddr).Port
	}
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	go func() {
		var buf [256]byte
		for {
			n, addr, err := conn.ReadFrom(buf[:])
			if err != nil {
				return
			}
			conn.WriteTo(buf[:n], addr)
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

func TestDenyAllPreservesInStackDNSAndHostToGuest(t *testing.T) {
	guest, router := testNetwork(t, types.Configuration{BlockAllOutbound: true, DNS: []types.Zone{{Name: "test.", Records: []types.Record{{Name: "broker", IP: net.ParseIP(guestIP)}}}}})
	addr := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4Slice(net.ParseIP(gatewayIP).To4()), Port: 53}
	for _, network := range []string{"tcp", "udp"} {
		var conn net.Conn
		var err error
		if network == "tcp" {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			conn, err = gonet.DialContextTCP(ctx, guest, addr, ipv4.ProtocolNumber)
		} else {
			conn, err = gonet.DialUDP(guest, nil, &addr, ipv4.ProtocolNumber)
		}
		require.NoError(t, err)
		defer conn.Close()
		require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))
		wire := &dnswire.Conn{Conn: conn}
		msg := new(dnswire.Msg)
		msg.SetQuestion("broker.test.", dnswire.TypeA)
		require.NoError(t, wire.WriteMsg(msg))
		reply, err := wire.ReadMsg()
		require.NoError(t, err)
		require.Len(t, reply.Answer, 1)
		require.Equal(t, guestIP, reply.Answer[0].(*dnswire.A).A.String())
	}
	addr.Addr = tcpip.AddrFrom4Slice(net.ParseIP(guestIP).To4())
	addr.Port = 2222
	ln, err := gonet.ListenTCP(guest, addr, ipv4.ProtocolNumber)
	require.NoError(t, err)
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.Write([]byte("guest"))
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := gonet.DialContextTCP(ctx, router, addr, ipv4.ProtocolNumber)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))
	buf := make([]byte, 5)
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err)
	require.Equal(t, "guest", string(buf))
}

func TestInvalidGatewayPortFailsBeforeServices(t *testing.T) {
	for _, port := range []int{-1, 0, 65536} {
		_, err := addServices(&types.Configuration{GatewayAllowedPorts: []int{port}}, nil, nil)
		require.Error(t, err)
	}
}

// Inputs come from real Kitchen rendering followed by Lima's strict decoder
// and production netstackConfig. The assertions run the actual fork forwarder.
func TestKitchenRenderedGateway(t *testing.T) {
	dir := os.Getenv("KITCHEN_FORK_FIXTURES")
	if dir == "" {
		t.Skip("run Kitchen make fork-test for the cross-repository contract")
	}
	data, err := os.ReadFile(filepath.Join(dir, "stack-configs.json"))
	require.NoError(t, err)
	var configs map[string]types.Configuration
	require.NoError(t, json.Unmarshal(data, &configs))
	require.Len(t, configs["kitchen-filter"].GatewayAllowedPorts, 1)
	port := configs["kitchen-filter"].GatewayAllowedPorts[0]
	address := fmt.Sprintf("127.0.0.1:%d", port)
	tcpHost, err := net.Listen("tcp4", address)
	require.NoError(t, err)
	defer tcpHost.Close()
	go func() {
		for {
			c, err := tcpHost.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	udpHost, err := net.ListenPacket("udp4", address)
	require.NoError(t, err)
	defer udpHost.Close()
	go func() {
		var b [256]byte
		for {
			n, a, err := udpHost.ReadFrom(b[:])
			if err != nil {
				return
			}
			udpHost.WriteTo(b[:n], a)
		}
	}()
	for _, name := range []string{"kitchen-filter", "kitchen-deny", "kitchen-default"} {
		t.Run(name, func(t *testing.T) {
			config, ok := configs[name]
			require.True(t, ok)
			guest, _ := testNetwork(t, config)
			for _, network := range []string{"tcp", "udp"} {
				remote := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4Slice(net.ParseIP(config.GatewayIP).To4()), Port: uint16(port)}
				var c net.Conn
				var err error
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				if network == "tcp" {
					c, err = gonet.DialContextTCP(ctx, guest, remote, ipv4.ProtocolNumber)
				} else {
					c, err = gonet.DialUDP(guest, nil, &remote, ipv4.ProtocolNumber)
				}
				if name == "kitchen-default" && network == "tcp" {
					require.Error(t, err)
					continue
				}
				require.NoError(t, err)
				defer c.Close()
				deadline := 10 * time.Second
				if name == "kitchen-default" {
					deadline = 300 * time.Millisecond
				}
				require.NoError(t, c.SetDeadline(time.Now().Add(deadline)))
				_, err = c.Write([]byte("rendered"))
				require.NoError(t, err)
				b := make([]byte, 8)
				_, err = io.ReadFull(c, b)
				if name == "kitchen-default" {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
					require.Equal(t, "rendered", string(b))
				}
			}
		})
	}
	data, err = os.ReadFile(filepath.Join(dir, "corpus.json"))
	require.NoError(t, err)
	var corpus []struct {
		Name    string
		Host    string
		Allowed bool
	}
	require.NoError(t, json.Unmarshal(data, &corpus))
	for i, tc := range corpus {
		t.Run(tc.Name, func(t *testing.T) {
			config, ok := configs[fmt.Sprintf("kitchen-corpus-%d", i)]
			require.True(t, ok)
			var patterns []*regexp.Regexp
			for _, p := range config.OutboundAllow {
				re, err := regexp.Compile(p)
				require.NoError(t, err)
				patterns = append(patterns, re)
			}
			require.Equal(t, tc.Allowed, forwarder.MatchesAllowlist(tc.Host, patterns))
		})
	}
}
