package relay

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"slices"

	"iprd/internal/progress"

	"github.com/sagernet/quic-go"

	rpktls "github.com/sagernet/quic-go/rpktls"
)

// dialQUIC performs an RFC 7250 handshake over the supplied packet path. The
// caller owns socket and closes it with its route, including on dial failure.
func dialQUIC(ctx context.Context, socket net.PacketConn, remote net.Addr, hop Hop, logf LogFunc, observer progress.Observer) (_ *quic.Conn, err error) {
	observer.Emit(progress.Event{Stage: "quic", Hop: hop.Name, Network: "udp", Status: progress.Running, Detail: remote.String()})
	defer func() {
		if err != nil {
			observer.Emit(progress.Event{Stage: "quic", Hop: hop.Name, Network: "udp", Status: progress.Failed, Err: err})
		}
	}()
	serverName, err := hop.hostname()
	if err != nil {
		return nil, err
	}
	keys, err := hop.publicKeys()
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%s has no configured TLS public keys", hop.Name)
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	tlsConfig := &tls.Config{ServerName: serverName, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	_, tunneled := socket.(*h3PacketConn)
	quicConfig := &quic.Config{
		EnableDatagrams:         true,
		DisablePathMTUDiscovery: tunneled,
		RPKConfig: &rpktls.Config{
			CurvePreferences:   hop.curvePreferences(),
			InsecureSkipVerify: true, // Raw SPKI is verified against the signed config below.
			VerifyPeerCertificate: func(rawKeys [][]byte, _ [][]*x509.Certificate) error {
				if len(rawKeys) == 0 || !slices.ContainsFunc(keys, func(key []byte) bool { return bytes.Equal(key, rawKeys[0]) }) {
					return fmt.Errorf("%s QUIC TLS public key does not match configuration", hop.Name)
				}
				return nil
			},
		},
	}
	if tunneled {
		// Fit inner QUIC packets inside the outer QUIC initial datagram payload
		// budget (1243 bytes before outer DPLPMTUD completes).
		quicConfig.InitialPacketSize = 1200
	}
	logf("%s: opening QUIC upstream to %s", hop.Name, remote)
	conn, err := quic.Dial(ctx, socket, remote, tlsConfig, quicConfig)
	if err != nil {
		return nil, fmt.Errorf("%s RPK QUIC: %w", hop.Name, err)
	}
	if protocol := conn.ConnectionState().TLS.NegotiatedProtocol; protocol != "h3" {
		_ = conn.CloseWithError(0, "relay did not negotiate h3")
		return nil, fmt.Errorf("%s: relay did not negotiate h3", hop.Name)
	}
	logf("%s: RPK QUIC established, ALPN=h3", hop.Name)
	observer.Emit(progress.Event{Stage: "quic", Hop: hop.Name, Network: "udp", Status: progress.OK, Detail: "raw SPKI matched; ALPN=h3"})
	return conn, nil
}
