package relay

import (
	"bytes"
	"context"
	stdtls "crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"sync"

	"time"

	"iprd/internal/progress"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"

	rpktls "github.com/sagernet/quic-go/rpktls"
)

type LogFunc func(format string, args ...any)

const connectTimeout = 30 * time.Second

type Dialer struct {
	ctx      context.Context
	cancel   context.CancelFunc
	source   Source
	logf     LogFunc
	observer progress.Observer
	mu       sync.Mutex
	current  map[string]*route
	routes   map[*route]struct{}
	closed   bool
}

type route struct {
	config              Config
	ingressH2, egressH2 *h2Client
	ingressH3, egressH3 *h3Client
	retired             bool
}

func NewManaged(ctx context.Context, source Source, logf LogFunc, observers ...progress.Observer) (*Dialer, error) {
	if source == nil {
		return nil, fmt.Errorf("missing relay credential source")
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	ctx, cancel := context.WithCancel(ctx)
	var observer progress.Observer
	if len(observers) != 0 {
		observer = observers[0]
	}
	return &Dialer{ctx: ctx, cancel: cancel, source: source, logf: logf, observer: observer, current: make(map[string]*route), routes: make(map[*route]struct{})}, nil
}

func newHop(ctx context.Context, hop Hop, upstream N.Dialer, source Source, logf LogFunc, observer progress.Observer) (*h2Client, error) {
	serverName, err := hop.hostname()
	if err != nil || serverName == "" {
		return nil, fmt.Errorf("%s: invalid endpoint", hop.Name)
	}
	keys, err := hop.publicKeys()
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%s: missing TLS raw public keys", hop.Name)
	}
	tlsDialer := &rpkDialer{upstream: upstream, hop: hop, serverName: serverName, keys: keys, logf: logf, observer: observer}
	return newH2Client(ctx, hop, tlsDialer, source, logf, observer), nil
}

func (d *Dialer) routeFor(config Config) (*route, error) {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil, net.ErrClosed
	}
	var next *route
	for candidate := range d.routes {
		if candidate.config.Revision == config.Revision && !candidate.retired {
			next = candidate
			break
		}
	}
	if next == nil {
		ingress, err := newHop(d.ctx, config.Ingress, N.SystemDialer, d.source, d.logf, d.observer)
		if err != nil {
			d.mu.Unlock()
			return nil, err
		}
		egress, err := newHop(d.ctx, config.Egress, ingress, d.source, d.logf, d.observer)
		if err != nil {
			d.mu.Unlock()
			ingress.Close()
			return nil, err
		}
		ingressH3 := newH3Client(d.ctx, config.Ingress, systemPacketDialer, d.source, d.logf, d.observer)
		egressH3 := newH3Client(d.ctx, config.Egress, ingressH3.DialPacket, d.source, d.logf, d.observer)
		next = &route{config: config, ingressH2: ingress, egressH2: egress, ingressH3: ingressH3, egressH3: egressH3}
		d.routes[next] = struct{}{}
	}
	d.mu.Unlock()
	return next, nil
}

func (d *Dialer) promote(next *route, network string) {
	d.mu.Lock()
	if next.retired || d.closed {
		d.mu.Unlock()
		return
	}
	old := d.current[network]
	d.current[network] = next
	retire := old != nil && old != next
	for _, current := range d.current {
		if current == old {
			retire = false
		}
	}
	if retire {
		old.retired = true
	}
	d.mu.Unlock()
	d.observer.Emit(progress.Event{Stage: "route", Hop: next.config.Egress.Name, Network: network, Status: progress.OK, Detail: next.config.Ingress.Server + " -> " + next.config.Egress.Server})
	if retire {
		d.retire(old)
	}
}

func (d *Dialer) retire(r *route) {
	egressDone, ingressDone := r.egressH2.Retire(), r.ingressH2.Retire()
	egressUDPDone, ingressUDPDone := r.egressH3.Retire(), r.ingressH3.Retire()
	go func() {
		<-egressDone
		<-ingressDone
		<-egressUDPDone
		<-ingressUDPDone
		d.mu.Lock()
		delete(d.routes, r)
		d.mu.Unlock()
	}()
}

func (d *Dialer) pruneRoutes(configurations []Config) {
	published := make(map[string]bool, len(configurations))
	for _, config := range configurations {
		published[config.Revision] = true
	}
	d.mu.Lock()
	var retired []*route
	for candidate := range d.routes {
		if candidate.retired || published[candidate.config.Revision] {
			continue
		}
		referenced := false
		for _, current := range d.current {
			referenced = referenced || current == candidate
		}
		if !referenced {
			candidate.retired = true
			retired = append(retired, candidate)
		}
	}
	d.mu.Unlock()
	for _, candidate := range retired {
		d.retire(candidate)
	}
}

// Route returns the public metadata of the last successful route for a network.
func (d *Dialer) Route(network string) (Config, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	r := d.current[N.NetworkName(network)]
	if r == nil {
		return Config{}, false
	}
	return r.config, true
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	network = N.NetworkName(network)
	if network != N.NetworkTCP && network != N.NetworkUDP {
		return nil, os.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()
	for range 2 {
		if network == N.NetworkUDP {
			if source, ok := d.source.(AlternativeSource); ok {
				conn, err := d.dialUDP(ctx, source, address)
				if errors.Is(err, ErrConfigurationChanged) {
					continue
				}
				return conn, err
			}
		}
		config, err := d.source.Current(ctx)
		if err != nil {
			return nil, err
		}
		d.observer.Emit(progress.Event{Stage: "route", Hop: config.Egress.Name, Network: network, Status: progress.Running, Detail: config.Ingress.Server + " -> " + config.Egress.Server})
		r, err := d.routeFor(config)
		if err != nil {
			return nil, err
		}
		var conn net.Conn
		if network == N.NetworkUDP {
			var packet net.PacketConn
			var remote net.Addr
			packet, remote, err = r.egressH3.DialPacket(ctx, M.ParseSocksaddr(address))
			if err == nil {
				conn = &udpConn{packet, remote}
			}
		} else {
			conn, err = r.egressH2.DialContext(ctx, network, M.ParseSocksaddr(address))
		}
		if errors.Is(err, ErrConfigurationChanged) {
			continue
		}
		if err == nil {
			d.promote(r, network)
		}
		return conn, err
	}
	return nil, ErrConfigurationChanged
}

func (d *Dialer) dialUDP(ctx context.Context, source AlternativeSource, address string) (net.Conn, error) {
	configurations, err := source.Alternatives(ctx)
	if err != nil {
		return nil, err
	}
	d.pruneRoutes(configurations)
	d.mu.Lock()
	current := d.current[N.NetworkUDP]
	d.mu.Unlock()
	if current != nil {
		for i, config := range configurations {
			if config.Revision == current.config.Revision {
				copy(configurations[1:i+1], configurations[:i])
				configurations[0] = config
				break
			}
		}
	}
	var failures []error
	for i, config := range configurations {
		if err := source.ActivateRoute(ctx, config); err != nil {
			return nil, err
		}
		d.observer.Emit(progress.Event{Stage: "route", Hop: config.Egress.Name, Network: N.NetworkUDP, Status: progress.Running, Detail: config.Ingress.Server + " -> " + config.Egress.Server})
		r, err := d.routeFor(config)
		if err != nil {
			return nil, err
		}
		packet, remote, err := r.egressH3.DialPacket(ctx, M.ParseSocksaddr(address))
		if err == nil {
			d.promote(r, N.NetworkUDP)
			d.logf("UDP route: %s (%s) -> %s (%s)", config.Ingress.Name, config.Ingress.Server, config.Egress.Name, config.Egress.Server)
			return &udpConn{packet, remote}, nil
		}
		if errors.Is(err, ErrConfigurationChanged) {
			return nil, err
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		failures = append(failures, err)
		if i+1 < len(configurations) {
			d.observer.Emit(progress.Event{Stage: "route", Hop: config.Egress.Name, Network: N.NetworkUDP, Status: progress.Retry, Detail: "trying the next published path", Err: err})
			d.logf("UDP via %s unavailable; trying the next published path: %v", config.Egress.Server, err)
		} else {
			d.observer.Emit(progress.Event{Stage: "route", Hop: config.Egress.Name, Network: N.NetworkUDP, Status: progress.Failed, Detail: "all published paths failed", Err: err})
		}
	}
	return nil, fmt.Errorf("no published route could establish CONNECT-UDP: %w", errors.Join(failures...))
}

func (d *Dialer) Close() error {
	d.cancel()
	d.mu.Lock()
	d.closed = true
	routes := make([]*route, 0, len(d.routes))
	for r := range d.routes {
		routes = append(routes, r)
	}
	d.mu.Unlock()
	var closing sync.WaitGroup
	for _, r := range routes {
		for _, hop := range []*h3Client{r.egressH3, r.ingressH3} {
			closing.Add(1)
			go func() { defer closing.Done(); hop.Close() }()
		}
		for _, hop := range []*h2Client{r.egressH2, r.ingressH2} {
			closing.Add(1)
			go func() { defer closing.Done(); hop.Close() }()
		}
	}
	closing.Wait()
	return nil
}

// rpkDialer adapts a TLS implementation with RFC 7250 support to sing's TLS
// dialer interface. The upstream can itself be an HTTP/2 CONNECT client.
type rpkDialer struct {
	upstream   N.Dialer
	hop        Hop
	serverName string
	keys       [][]byte
	logf       LogFunc
	observer   progress.Observer
}

func (d *rpkDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) != N.NetworkTCP {
		return nil, os.ErrInvalid
	}
	return d.DialTLSContext(ctx, destination)
}

func (d *rpkDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

func (d *rpkDialer) DialTLSContext(ctx context.Context, destination M.Socksaddr) (aTLS.Conn, error) {
	d.logf("%s: opening upstream to %s", d.hop.Name, destination)
	conn, err := d.upstream.DialContext(ctx, N.NetworkTCP, destination)
	if err != nil {
		d.observer.Emit(progress.Event{Stage: "tls", Hop: d.hop.Name, Network: N.NetworkTCP, Status: progress.Failed, Err: err})
		return nil, fmt.Errorf("%s upstream: %w", d.hop.Name, err)
	}
	d.observer.Emit(progress.Event{Stage: "tls", Hop: d.hop.Name, Network: N.NetworkTCP, Status: progress.Running, Detail: destination.String()})
	config := &rpktls.Config{
		ServerName:         d.serverName,
		NextProtos:         []string{"h2"},
		MinVersion:         rpktls.VersionTLS13,
		MaxVersion:         rpktls.VersionTLS13,
		CurvePreferences:   []rpktls.CurveID{rpktls.X25519},
		RawPublicKeys:      true,
		InsecureSkipVerify: true, // Raw SPKI is verified against the signed config below.
		VerifyPeerCertificate: func(rawKeys [][]byte, _ [][]*x509.Certificate) error {
			if len(rawKeys) == 0 || !slices.ContainsFunc(d.keys, func(key []byte) bool {
				return bytes.Equal(key, rawKeys[0])
			}) {
				return fmt.Errorf("%s TLS public key does not match configuration", d.hop.Name)
			}
			return nil
		},
	}
	tlsConn := rpktls.Client(conn, config)
	if err = tlsConn.HandshakeContext(ctx); err != nil {
		d.observer.Emit(progress.Event{Stage: "tls", Hop: d.hop.Name, Network: N.NetworkTCP, Status: progress.Failed, Err: err})
		conn.Close()
		return nil, fmt.Errorf("%s RPK TLS: %w", d.hop.Name, err)
	}
	if tlsConn.ConnectionState().NegotiatedProtocol != "h2" {
		tlsConn.Close()
		err = fmt.Errorf("%s: relay did not negotiate h2", d.hop.Name)
		d.observer.Emit(progress.Event{Stage: "tls", Hop: d.hop.Name, Network: N.NetworkTCP, Status: progress.Failed, Err: err})
		return nil, err
	}
	d.logf("%s: RPK TLS established, ALPN=%s", d.hop.Name, tlsConn.ConnectionState().NegotiatedProtocol)
	d.observer.Emit(progress.Event{Stage: "tls", Hop: d.hop.Name, Network: N.NetworkTCP, Status: progress.OK, Detail: "raw SPKI matched; ALPN=h2"})
	return &rpkConn{Conn: tlsConn}, nil
}

type rpkConn struct {
	*rpktls.Conn
}

func (c *rpkConn) ConnectionState() stdtls.ConnectionState {
	s := c.Conn.ConnectionState()
	return stdtls.ConnectionState{
		Version: s.Version, HandshakeComplete: s.HandshakeComplete,
		CipherSuite: s.CipherSuite, NegotiatedProtocol: s.NegotiatedProtocol,
		NegotiatedProtocolIsMutual: s.NegotiatedProtocolIsMutual,
		ServerName:                 s.ServerName,
	}
}

var _ aTLS.Conn = (*rpkConn)(nil)
