package forwarder

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/inetaf/tcpproxy"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// ---------------------------------------------------------------------------
// SNI matches destination (DNS cross-check pure function)
// ---------------------------------------------------------------------------

func TestSNIMatchesDestination_ExactMatch(t *testing.T) {
	dest := tcpip.AddrFrom4([4]byte{1, 2, 3, 4})
	resolved := []net.IPAddr{{IP: net.ParseIP("1.2.3.4")}}
	require.True(t, sniMatchesDestination(dest, resolved))
}

func TestSNIMatchesDestination_NoMatch(t *testing.T) {
	dest := tcpip.AddrFrom4([4]byte{1, 2, 3, 4})
	resolved := []net.IPAddr{{IP: net.ParseIP("5.6.7.8")}}
	require.False(t, sniMatchesDestination(dest, resolved))
}

func TestSNIMatchesDestination_MultipleIPs(t *testing.T) {
	dest := tcpip.AddrFrom4([4]byte{10, 0, 0, 1})
	resolved := []net.IPAddr{
		{IP: net.ParseIP("5.6.7.8")},
		{IP: net.ParseIP("10.0.0.1")},
		{IP: net.ParseIP("192.168.1.1")},
	}
	require.True(t, sniMatchesDestination(dest, resolved),
		"should match when any resolved IP matches destination")
}

func TestSNIMatchesDestination_EmptyResolved(t *testing.T) {
	dest := tcpip.AddrFrom4([4]byte{1, 2, 3, 4})
	require.False(t, sniMatchesDestination(dest, nil))
	require.False(t, sniMatchesDestination(dest, []net.IPAddr{}))
}

// ---------------------------------------------------------------------------
// Byte-replay proxy tests
//
// These tests exercise the exact byte-replay path from handleTLSWithAllowlist
// (tcp.go lines 211-226): bufio.Reader → PeekSNI → br.Peek(br.Buffered()) →
// copy → tcpproxy.Conn{Peeked} → DialProxy.HandleConn.
// ---------------------------------------------------------------------------

// generateSelfSignedCert creates an ECDSA P-256 self-signed certificate for
// "example.com", suitable for end-to-end TLS handshake tests.
func generateSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	return cert
}

// proxyReplay replicates the exact proxy logic from handleTLSWithAllowlist:
// creates bufio.ReaderSize(guestConn, 65565), calls PeekSNI, does
// br.Peek(br.Buffered()) + copy, wraps in tcpproxy.Conn, calls
// DialProxy.HandleConn. Returns PeekSNI error (if any); HandleConn errors
// are not observable (they are logged in production).
func proxyReplay(guestConn, serverConn net.Conn) error {
	br := bufio.NewReaderSize(guestConn, maxClientHelloLen+5*5+4)
	_, _, _, err := PeekSNI(br)
	if err != nil {
		guestConn.Close()
		serverConn.Close()
		return fmt.Errorf("PeekSNI: %w", err)
	}

	peeked, _ := br.Peek(br.Buffered())
	peekedCopy := make([]byte, len(peeked))
	copy(peekedCopy, peeked)

	wrappedConn := &tcpproxy.Conn{
		Peeked: peekedCopy,
		Conn:   guestConn,
	}

	remote := tcpproxy.DialProxy{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return serverConn, nil
		},
	}
	remote.HandleConn(wrappedConn)
	return nil
}

// ---------------------------------------------------------------------------
// Section F — Byte-replay tests (raw bytes through proxy)
// ---------------------------------------------------------------------------

// TestByteReplay_SmallClientHello verifies that a small (~100B) TLS 1.2
// ClientHello passes through the proxy byte-for-byte.
func TestByteReplay_SmallClientHello(t *testing.T) {
	ch := buildClientHello(defaultOpts())

	guest, proxyGuest := net.Pipe()
	proxyServer, server := net.Pipe()

	proxyErr := make(chan error, 1)
	go func() {
		proxyErr <- proxyReplay(proxyGuest, proxyServer)
	}()

	go func() {
		defer guest.Close()
		guest.Write(ch)
	}()

	// Read exactly the ClientHello bytes from the server side.
	received := make([]byte, len(ch))
	_, err := io.ReadFull(server, received)
	require.NoError(t, err)
	require.Equal(t, ch, received, "server must receive exact ClientHello bytes")

	// Close server to unblock proxy's server→guest direction.
	server.Close()

	require.NoError(t, <-proxyErr)
}

// TestByteReplay_LargeClientHello verifies byte-for-byte integrity for a
// ~1400B ClientHello with multiple extensions (key_share, supported_versions,
// supported_groups, ALPN, padding).
func TestByteReplay_LargeClientHello(t *testing.T) {
	opts := defaultOpts()
	opts.extensions = []tlsExtension{
		buildSNIExtension("example.com"),
		buildKeyShareExtension(),
		buildSupportedVersionsExtension(0x0304, 0x0303),
		buildSupportedGroupsExtension(),
		buildALPNExtension(),
		{typ: 0x0015, data: make([]byte, 1000)}, // padding extension
	}
	ch := buildClientHello(opts)
	require.Greater(t, len(ch), 1000, "ClientHello should be >1000 bytes")

	guest, proxyGuest := net.Pipe()
	proxyServer, server := net.Pipe()

	proxyErr := make(chan error, 1)
	go func() {
		proxyErr <- proxyReplay(proxyGuest, proxyServer)
	}()

	go func() {
		defer guest.Close()
		guest.Write(ch)
	}()

	received := make([]byte, len(ch))
	_, err := io.ReadFull(server, received)
	require.NoError(t, err)
	require.Equal(t, ch, received, "server must receive exact large ClientHello bytes")

	server.Close()
	require.NoError(t, <-proxyErr)
}

// TestByteReplay_FragmentedTLSRecords verifies that a ClientHello split across
// 2 TLS records is replayed byte-for-byte.
func TestByteReplay_FragmentedTLSRecords(t *testing.T) {
	opts := defaultOpts()
	opts.extensions = []tlsExtension{
		buildSNIExtension("example.com"),
		buildKeyShareExtension(),
		buildSupportedVersionsExtension(0x0304, 0x0303),
		buildSupportedGroupsExtension(),
		buildALPNExtension(),
	}
	opts.fragmentAt = []int{30} // split handshake across 2 TLS records
	ch := buildClientHello(opts)

	guest, proxyGuest := net.Pipe()
	proxyServer, server := net.Pipe()

	proxyErr := make(chan error, 1)
	go func() {
		proxyErr <- proxyReplay(proxyGuest, proxyServer)
	}()

	go func() {
		defer guest.Close()
		guest.Write(ch)
	}()

	received := make([]byte, len(ch))
	_, err := io.ReadFull(server, received)
	require.NoError(t, err)
	require.Equal(t, ch, received, "server must receive exact fragmented ClientHello bytes")

	server.Close()
	require.NoError(t, <-proxyErr)
}

// TestByteReplay_ClientHelloFollowedByTraffic verifies bidirectional proxy
// operation: guest sends ClientHello then application data; server echoes
// a response. Asserts bytes don't leak between Peeked and live-read paths.
func TestByteReplay_ClientHelloFollowedByTraffic(t *testing.T) {
	ch := buildClientHello(defaultOpts())
	appData := []byte("hello from guest after ClientHello")

	guest, proxyGuest := net.Pipe()
	proxyServer, server := net.Pipe()

	proxyErr := make(chan error, 1)
	go func() {
		proxyErr <- proxyReplay(proxyGuest, proxyServer)
	}()

	// Server: reads ClientHello + app data, sends response.
	serverResponse := []byte("hello from server")
	serverDone := make(chan error, 1)
	go func() {
		defer server.Close()

		// Read ClientHello.
		chBuf := make([]byte, len(ch))
		if _, err := io.ReadFull(server, chBuf); err != nil {
			serverDone <- fmt.Errorf("read ClientHello: %w", err)
			return
		}

		// Read app data.
		appBuf := make([]byte, len(appData))
		if _, err := io.ReadFull(server, appBuf); err != nil {
			serverDone <- fmt.Errorf("read app data: %w", err)
			return
		}

		// Send response.
		if _, err := server.Write(serverResponse); err != nil {
			serverDone <- fmt.Errorf("write response: %w", err)
			return
		}
		serverDone <- nil
	}()

	// Guest: write ClientHello, then app data.
	_, err := guest.Write(ch)
	require.NoError(t, err, "guest write ClientHello")

	_, err = guest.Write(appData)
	require.NoError(t, err, "guest write app data")

	// Read server response through proxy.
	buf := make([]byte, len(serverResponse))
	_, err = io.ReadFull(guest, buf)
	require.NoError(t, err, "guest read response")
	require.Equal(t, serverResponse, buf)

	// Shutdown.
	guest.Close()
	require.NoError(t, <-serverDone)
	require.NoError(t, <-proxyErr)
}

// TestByteReplay_PeekedMatchesBuffered verifies that br.Peek(br.Buffered())
// returns exactly the ClientHello bytes for various sizes. This catches
// bufio.Reader read-ahead issues.
func TestByteReplay_PeekedMatchesBuffered(t *testing.T) {
	tests := []struct {
		name string
		opts clientHelloOpts
	}{
		{
			name: "SmallDefault",
			opts: defaultOpts(),
		},
		{
			name: "WithMultipleExtensions",
			opts: func() clientHelloOpts {
				o := defaultOpts()
				o.extensions = []tlsExtension{
					buildSNIExtension("example.com"),
					buildKeyShareExtension(),
					buildSupportedVersionsExtension(0x0304, 0x0303),
					buildSupportedGroupsExtension(),
					buildALPNExtension(),
				}
				return o
			}(),
		},
		{
			name: "WithPadding1400B",
			opts: func() clientHelloOpts {
				o := defaultOpts()
				o.extensions = []tlsExtension{
					buildSNIExtension("example.com"),
					{typ: 0x0015, data: make([]byte, 1200)},
				}
				return o
			}(),
		},
		{
			name: "Fragmented",
			opts: func() clientHelloOpts {
				o := defaultOpts()
				o.extensions = []tlsExtension{
					buildSNIExtension("example.com"),
					buildKeyShareExtension(),
					buildSupportedVersionsExtension(0x0304, 0x0303),
				}
				o.fragmentAt = []int{20}
				return o
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ch := buildClientHello(tt.opts)

			guest, proxyGuest := net.Pipe()
			go func() {
				defer guest.Close()
				guest.Write(ch)
			}()

			br := bufio.NewReaderSize(proxyGuest, maxClientHelloLen+5*5+4)
			_, _, _, err := PeekSNI(br)
			require.NoError(t, err)

			peeked, err := br.Peek(br.Buffered())
			require.NoError(t, err)
			require.Equal(t, ch, peeked,
				"br.Peek(br.Buffered()) must return exactly the ClientHello bytes")

			proxyGuest.Close()
		})
	}
}

// ---------------------------------------------------------------------------
// Section G — End-to-end TLS handshake tests through the proxy
// ---------------------------------------------------------------------------

// TestByteReplay_EndToEndTLS12 verifies that a full TLS 1.2 handshake
// completes through the proxy and application data round-trips correctly.
func TestByteReplay_EndToEndTLS12(t *testing.T) {
	cert := generateSelfSignedCert(t)

	guest, proxyGuest := net.Pipe()
	proxyServer, server := net.Pipe()

	// Set deadlines to prevent hangs on failure.
	deadline := time.Now().Add(5 * time.Second)
	guest.SetDeadline(deadline)
	server.SetDeadline(deadline)

	proxyErr := make(chan error, 1)
	go func() {
		proxyErr <- proxyReplay(proxyGuest, proxyServer)
	}()

	// TLS server (echo).
	serverDone := make(chan error, 1)
	go func() {
		tlsServer := tls.Server(server, &tls.Config{
			Certificates: []tls.Certificate{cert},
			MaxVersion:   tls.VersionTLS12,
		})
		defer tlsServer.Close()

		buf := make([]byte, 1024)
		n, err := tlsServer.Read(buf)
		if err != nil {
			serverDone <- fmt.Errorf("server read: %w", err)
			return
		}
		if _, err := tlsServer.Write(buf[:n]); err != nil {
			serverDone <- fmt.Errorf("server write: %w", err)
			return
		}
		serverDone <- nil
	}()

	// TLS client.
	tlsClient := tls.Client(guest, &tls.Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true,
		MaxVersion:         tls.VersionTLS12,
	})

	msg := []byte("hello TLS 1.2")
	_, err := tlsClient.Write(msg)
	require.NoError(t, err, "TLS 1.2 client write")

	buf := make([]byte, 1024)
	n, err := tlsClient.Read(buf)
	require.NoError(t, err, "TLS 1.2 client read")
	require.Equal(t, msg, buf[:n])

	state := tlsClient.ConnectionState()
	require.Equal(t, uint16(tls.VersionTLS12), state.Version,
		"must negotiate TLS 1.2")

	tlsClient.Close()
	require.NoError(t, <-serverDone)
	require.NoError(t, <-proxyErr)
}

// TestByteReplay_EndToEndTLS13 verifies that a full TLS 1.3 handshake
// completes through the proxy. This is the test most likely to reproduce
// the observed bun/TLS 1.3 failure through the proxy.
func TestByteReplay_EndToEndTLS13(t *testing.T) {
	cert := generateSelfSignedCert(t)

	guest, proxyGuest := net.Pipe()
	proxyServer, server := net.Pipe()

	deadline := time.Now().Add(5 * time.Second)
	guest.SetDeadline(deadline)
	server.SetDeadline(deadline)

	proxyErr := make(chan error, 1)
	go func() {
		proxyErr <- proxyReplay(proxyGuest, proxyServer)
	}()

	// TLS server (echo), TLS 1.3 only.
	serverDone := make(chan error, 1)
	go func() {
		tlsServer := tls.Server(server, &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		})
		defer tlsServer.Close()

		buf := make([]byte, 1024)
		n, err := tlsServer.Read(buf)
		if err != nil {
			serverDone <- fmt.Errorf("server read: %w", err)
			return
		}
		if _, err := tlsServer.Write(buf[:n]); err != nil {
			serverDone <- fmt.Errorf("server write: %w", err)
			return
		}
		serverDone <- nil
	}()

	// TLS client, TLS 1.3 only.
	tlsClient := tls.Client(guest, &tls.Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
	})

	msg := []byte("hello TLS 1.3")
	_, err := tlsClient.Write(msg)
	require.NoError(t, err, "TLS 1.3 client write")

	buf := make([]byte, 1024)
	n, err := tlsClient.Read(buf)
	require.NoError(t, err, "TLS 1.3 client read")
	require.Equal(t, msg, buf[:n])

	state := tlsClient.ConnectionState()
	require.Equal(t, uint16(tls.VersionTLS13), state.Version,
		"must negotiate TLS 1.3")

	tlsClient.Close()
	require.NoError(t, <-serverDone)
	require.NoError(t, <-proxyErr)
}

// TestByteReplay_EndToEndTLS13ClientTLS12Server verifies that a TLS client
// offering TLS 1.3 successfully downgrades to TLS 1.2 when the server only
// supports TLS 1.2, through the proxy. This matches the scenario where bun
// offered TLS 1.3 but the server only supports TLS 1.2.
func TestByteReplay_EndToEndTLS13ClientTLS12Server(t *testing.T) {
	cert := generateSelfSignedCert(t)

	guest, proxyGuest := net.Pipe()
	proxyServer, server := net.Pipe()

	deadline := time.Now().Add(5 * time.Second)
	guest.SetDeadline(deadline)
	server.SetDeadline(deadline)

	proxyErr := make(chan error, 1)
	go func() {
		proxyErr <- proxyReplay(proxyGuest, proxyServer)
	}()

	// TLS server: TLS 1.2 only.
	serverDone := make(chan error, 1)
	go func() {
		tlsServer := tls.Server(server, &tls.Config{
			Certificates: []tls.Certificate{cert},
			MaxVersion:   tls.VersionTLS12,
		})
		defer tlsServer.Close()

		buf := make([]byte, 1024)
		n, err := tlsServer.Read(buf)
		if err != nil {
			serverDone <- fmt.Errorf("server read: %w", err)
			return
		}
		if _, err := tlsServer.Write(buf[:n]); err != nil {
			serverDone <- fmt.Errorf("server write: %w", err)
			return
		}
		serverDone <- nil
	}()

	// TLS client: offers TLS 1.3 but accepts down to TLS 1.2.
	tlsClient := tls.Client(guest, &tls.Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		// MaxVersion defaults to TLS 1.3.
	})

	msg := []byte("hello downgrade")
	_, err := tlsClient.Write(msg)
	require.NoError(t, err, "downgrade client write")

	buf := make([]byte, 1024)
	n, err := tlsClient.Read(buf)
	require.NoError(t, err, "downgrade client read")
	require.Equal(t, msg, buf[:n])

	state := tlsClient.ConnectionState()
	require.Equal(t, uint16(tls.VersionTLS12), state.Version,
		"must negotiate TLS 1.2 (downgrade from 1.3 offer)")

	tlsClient.Close()
	require.NoError(t, <-serverDone)
	require.NoError(t, <-proxyErr)
}

// ---------------------------------------------------------------------------
// Section H — ECH GREASE proxy tests
//
// Chrome (since v117) and Firefox (since v119) send ECH GREASE by default
// — a dummy encrypted_client_hello extension (0xfe0d) with random data.
// Per RFC 9849 Section 8.1.2, the proxy acts based on the outer SNI,
// ignoring the ECH extension. The outer SNI is validated against the
// allowlist and DNS cross-checked before forwarding.
// ---------------------------------------------------------------------------

// TestByteReplay_ECHGreaseAllowed verifies that the proxy forwards
// ClientHellos containing the ECH extension (0xfe0d) byte-for-byte.
func TestByteReplay_ECHGreaseAllowed(t *testing.T) {
	ch := buildClientHelloWithECH("example.com")

	guest, proxyGuest := net.Pipe()
	proxyServer, server := net.Pipe()

	proxyErr := make(chan error, 1)
	go func() {
		proxyErr <- proxyReplay(proxyGuest, proxyServer)
	}()

	go func() {
		defer guest.Close()
		guest.Write(ch)
	}()

	received := make([]byte, len(ch))
	_, err := io.ReadFull(server, received)
	require.NoError(t, err)
	require.Equal(t, ch, received, "server must receive exact ClientHello bytes")
	server.Close()
	require.NoError(t, <-proxyErr)
}

// TestByteReplay_ECHGreaseWithTLS13Extensions verifies that a well-formed
// TLS 1.3 ClientHello with ECH GREASE is forwarded byte-for-byte.
func TestByteReplay_ECHGreaseWithTLS13Extensions(t *testing.T) {
	opts := defaultOpts()
	opts.extensions = []tlsExtension{
		buildSNIExtension("example.com"),
		buildKeyShareExtension(),
		buildSupportedVersionsExtension(0x0304, 0x0303), // TLS 1.3 + 1.2
		buildSupportedGroupsExtension(),
		buildALPNExtension(),
		buildECHExtension(), // ECH GREASE (0xfe0d)
	}
	ch := buildClientHello(opts)

	guest, proxyGuest := net.Pipe()
	proxyServer, server := net.Pipe()

	proxyErr := make(chan error, 1)
	go func() {
		proxyErr <- proxyReplay(proxyGuest, proxyServer)
	}()

	go func() {
		defer guest.Close()
		guest.Write(ch)
	}()

	received := make([]byte, len(ch))
	_, err := io.ReadFull(server, received)
	require.NoError(t, err)
	require.Equal(t, ch, received, "server must receive exact ClientHello bytes")
	server.Close()
	require.NoError(t, <-proxyErr)
}

// TestByteReplay_LegacyESNIAllowed verifies that the proxy forwards
// ClientHellos with the legacy ESNI extension (0xffce) byte-for-byte.
func TestByteReplay_LegacyESNIAllowed(t *testing.T) {
	opts := defaultOpts()
	opts.extensions = []tlsExtension{
		buildSNIExtension("example.com"),
		buildESNIExtension(), // legacy ESNI (0xffce)
	}
	ch := buildClientHello(opts)

	guest, proxyGuest := net.Pipe()
	proxyServer, server := net.Pipe()

	proxyErr := make(chan error, 1)
	go func() {
		proxyErr <- proxyReplay(proxyGuest, proxyServer)
	}()

	go func() {
		defer guest.Close()
		guest.Write(ch)
	}()

	received := make([]byte, len(ch))
	_, err := io.ReadFull(server, received)
	require.NoError(t, err)
	require.Equal(t, ch, received, "server must receive exact ClientHello bytes")
	server.Close()
	require.NoError(t, <-proxyErr)
}

// ---------------------------------------------------------------------------
// Section H (continued) — Spec-compliant ECH proxy-level tests
//
// These tests exercise the full proxy byte-replay path with spec-compliant
// ECH extensions (RFC 9849 wire format), verifying that the proxy forwards
// them the same way it forwards non-ECH connections. The outer SNI is used
// for allowlist validation; the ECH extension is ignored.
// ---------------------------------------------------------------------------

// P1: Chrome GREASE ECH + full TLS 1.3 extensions through proxyReplay.
func TestByteReplay_ECHGreaseChromeAllowed(t *testing.T) {
	opts := clientHelloOpts{
		version:            0x0301,
		handshakeVersion:   0x0303,
		sessionID:          make([]byte, 32),
		cipherSuites:       []uint16{0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xcca9, 0xcca8},
		compressionMethods: []byte{0x00},
		extensions: []tlsExtension{
			buildGREASEExtension(0x0a0a),
			buildSNIExtension("www.google.com"),
			buildKeyShareExtension(),
			buildSupportedVersionsExtension(0x0a0a, 0x0304, 0x0303),
			buildSupportedGroupsExtension(),
			buildALPNExtension(),
			buildChromeECHGreaseExtension(),
		},
	}
	ch := buildClientHello(opts)

	guest, proxyGuest := net.Pipe()
	proxyServer, server := net.Pipe()

	proxyErr := make(chan error, 1)
	go func() {
		proxyErr <- proxyReplay(proxyGuest, proxyServer)
	}()

	go func() {
		defer guest.Close()
		guest.Write(ch)
	}()

	received := make([]byte, len(ch))
	_, err := io.ReadFull(server, received)
	require.NoError(t, err)
	require.Equal(t, ch, received, "server must receive exact ClientHello bytes")
	server.Close()
	require.NoError(t, <-proxyErr)
}

// P2: Firefox GREASE ECH + TLS 1.3 extensions through proxyReplay.
func TestByteReplay_ECHGreaseFirefoxAllowed(t *testing.T) {
	opts := clientHelloOpts{
		version:            0x0301,
		handshakeVersion:   0x0303,
		sessionID:          make([]byte, 32),
		cipherSuites:       []uint16{0x1301, 0x1303, 0x1302, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xcca9, 0xcca8},
		compressionMethods: []byte{0x00},
		extensions: []tlsExtension{
			buildSNIExtension("www.mozilla.org"),
			buildSupportedVersionsExtension(0x0304, 0x0303),
			buildKeyShareExtension(),
			buildSupportedGroupsExtension(),
			buildALPNExtension(),
			buildFirefoxECHGreaseExtension(),
		},
	}
	ch := buildClientHello(opts)

	guest, proxyGuest := net.Pipe()
	proxyServer, server := net.Pipe()

	proxyErr := make(chan error, 1)
	go func() {
		proxyErr <- proxyReplay(proxyGuest, proxyServer)
	}()

	go func() {
		defer guest.Close()
		guest.Write(ch)
	}()

	received := make([]byte, len(ch))
	_, err := io.ReadFull(server, received)
	require.NoError(t, err)
	require.Equal(t, ch, received, "server must receive exact ClientHello bytes")
	server.Close()
	require.NoError(t, <-proxyErr)
}

// P3: Chrome GREASE ECH, fragmented across 2 records, through proxyReplay.
func TestByteReplay_ECHGreaseFragmentedAllowed(t *testing.T) {
	opts := defaultOpts()
	opts.extensions = []tlsExtension{
		buildSNIExtension("example.com"),
		buildKeyShareExtension(),
		buildSupportedVersionsExtension(0x0304, 0x0303),
		buildChromeECHGreaseExtension(),
	}
	opts.fragmentAt = []int{50}
	ch := buildClientHello(opts)

	guest, proxyGuest := net.Pipe()
	proxyServer, server := net.Pipe()

	proxyErr := make(chan error, 1)
	go func() {
		proxyErr <- proxyReplay(proxyGuest, proxyServer)
	}()

	go func() {
		defer guest.Close()
		guest.Write(ch)
	}()

	received := make([]byte, len(ch))
	_, err := io.ReadFull(server, received)
	require.NoError(t, err)
	require.Equal(t, ch, received, "server must receive exact ClientHello bytes")
	server.Close()
	require.NoError(t, <-proxyErr)
}

// P4: Spec-compliant ECH outer (config_id=42, non-GREASE) through proxyReplay.
func TestByteReplay_ECHOuterAllowed(t *testing.T) {
	opts := defaultOpts()
	opts.extensions = []tlsExtension{
		buildSNIExtension("cover.example.com"),
		buildECHOuterExtension(42, 32, 256),
	}
	ch := buildClientHello(opts)

	guest, proxyGuest := net.Pipe()
	proxyServer, server := net.Pipe()

	proxyErr := make(chan error, 1)
	go func() {
		proxyErr <- proxyReplay(proxyGuest, proxyServer)
	}()

	go func() {
		defer guest.Close()
		guest.Write(ch)
	}()

	received := make([]byte, len(ch))
	_, err := io.ReadFull(server, received)
	require.NoError(t, err)
	require.Equal(t, ch, received, "server must receive exact ClientHello bytes")
	server.Close()
	require.NoError(t, <-proxyErr)
}

// P5: Legacy ESNI (0xffce) with 512B payload through proxyReplay.
func TestByteReplay_LegacyESNILargePayloadAllowed(t *testing.T) {
	opts := defaultOpts()
	opts.extensions = []tlsExtension{
		buildSNIExtension("example.com"),
		buildLegacyESNIExtensionWithPayload(512),
	}
	ch := buildClientHello(opts)

	guest, proxyGuest := net.Pipe()
	proxyServer, server := net.Pipe()

	proxyErr := make(chan error, 1)
	go func() {
		proxyErr <- proxyReplay(proxyGuest, proxyServer)
	}()

	go func() {
		defer guest.Close()
		guest.Write(ch)
	}()

	received := make([]byte, len(ch))
	_, err := io.ReadFull(server, received)
	require.NoError(t, err)
	require.Equal(t, ch, received, "server must receive exact ClientHello bytes")
	server.Close()
	require.NoError(t, <-proxyErr)
}

// P6: ECH inner (type=0x01) through proxyReplay.
func TestByteReplay_ECHInnerTypeAllowed(t *testing.T) {
	opts := defaultOpts()
	opts.extensions = []tlsExtension{
		buildSNIExtension("example.com"),
		buildECHInnerExtension(),
	}
	ch := buildClientHello(opts)

	guest, proxyGuest := net.Pipe()
	proxyServer, server := net.Pipe()

	proxyErr := make(chan error, 1)
	go func() {
		proxyErr <- proxyReplay(proxyGuest, proxyServer)
	}()

	go func() {
		defer guest.Close()
		guest.Write(ch)
	}()

	received := make([]byte, len(ch))
	_, err := io.ReadFull(server, received)
	require.NoError(t, err)
	require.Equal(t, ch, received, "server must receive exact ClientHello bytes")
	server.Close()
	require.NoError(t, <-proxyErr)
}
