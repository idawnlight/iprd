package relay

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"iprd/internal/progress"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/pipe"
)

type packetDialer func(context.Context, M.Socksaddr) (net.PacketConn, net.Addr, error)

// h3Client authenticates one relay hop. Its packet path is either a local UDP
// socket or another h3Client's CONNECT-UDP stream.
type h3Client struct {
	ctx       context.Context
	cancel    context.CancelFunc
	hop       Hop
	upstream  packetDialer
	source    Source
	geohash   func() string
	onGeohash func(string)
	logf      LogFunc
	observer  progress.Observer
	mu       sync.Mutex
	current  *h3Session
	sessions map[*h3Session]struct{}
	opening  *h3Opening
	retired  bool
	done     chan struct{}
	doneOnce sync.Once
}

type h3Opening struct {
	done   chan struct{}
	cancel context.CancelFunc
	err    error
}

type h3Session struct {
	client        *http3.ClientConn
	socket        net.PacketConn
	token         Credential
	authenticated atomic.Bool
	streams       sync.WaitGroup
	draining      bool
	closeOnce     sync.Once
}

func newH3Client(ctx context.Context, hop Hop, upstream packetDialer, source Source, logf LogFunc, observer progress.Observer) *h3Client {
	ctx, cancel := context.WithCancel(ctx)
	return &h3Client{ctx: ctx, cancel: cancel, hop: hop, upstream: upstream, source: source, logf: logf, observer: observer, sessions: make(map[*h3Session]struct{}), done: make(chan struct{})}
}

func (c *h3Client) observe(stage string, status progress.Status, detail string, err error) {
	c.observer.Emit(progress.Event{Stage: stage, Hop: c.hop.Name, Network: "udp", Status: status, Detail: detail, Err: err})
}

func (c *h3Client) acquire(ctx context.Context) (*h3Session, error) {
	for {
		c.mu.Lock()
		if c.retired || c.ctx.Err() != nil {
			c.mu.Unlock()
			return nil, ErrConfigurationChanged
		}
		if s := c.current; s != nil {
			expired := !s.token.ExpiresAt.IsZero() && !time.Now().Before(s.token.ExpiresAt)
			if !s.draining && !expired && s.client.Context().Err() == nil {
				s.streams.Add(1)
				c.mu.Unlock()
				return s, nil
			}
			c.drainLocked(s)
			c.current = nil
		}
		opening := c.opening
		if opening == nil {
			openCtx, cancel := context.WithTimeout(c.ctx, connectTimeout)
			opening = &h3Opening{done: make(chan struct{}), cancel: cancel}
			c.opening = opening
			go c.open(openCtx, opening)
		}
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-c.ctx.Done():
			return nil, c.ctx.Err()
		case <-opening.done:
			if opening.err != nil {
				return nil, opening.err
			}
		}
	}
}

func (c *h3Client) open(ctx context.Context, opening *h3Opening) {
	defer opening.cancel()
	session, err := c.openSession(ctx)
	c.mu.Lock()
	c.opening = nil
	if session != nil {
		c.sessions[session] = struct{}{}
		if c.retired || c.ctx.Err() != nil {
			c.drainLocked(session)
			err = ErrConfigurationChanged
		} else {
			c.current = session
		}
	}
	opening.err = err
	close(opening.done)
	c.completeLocked()
	c.mu.Unlock()
}

func (c *h3Client) openSession(ctx context.Context) (_ *h3Session, err error) {
	s := &h3Session{}
	defer func() {
		if err != nil {
			s.close()
		}
	}()
	var remote net.Addr
	s.socket, remote, err = c.upstream(ctx, M.ParseSocksaddr(c.hop.Server))
	if err != nil {
		return nil, err
	}
	connection, err := dialQUIC(ctx, s.socket, remote, c.hop, c.logf, c.observer)
	if err != nil {
		return nil, err
	}
	transport := &http3.Transport{EnableDatagrams: true, DisableCompression: true}
	s.client = transport.NewClientConn(connection)
	c.observe("tokens", progress.Running, "acquiring connection token", nil)
	s.token, err = c.source.TakeToken(ctx, c.hop.ID)
	if err != nil {
		c.observe("tokens", progress.Failed, "", err)
		return nil, err
	}
	c.observe("tokens", progress.OK, "connection token acquired", nil)
	c.logf("%s: new H3 session with a fresh token", c.hop.Name)
	return s, nil
}

func (c *h3Client) DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	request := &http.Request{Method: http.MethodConnect, URL: &url.URL{Host: destination.String()}, Host: destination.String(), Header: make(http.Header)}
	stream, _, err := c.openStream(ctx, "connect", "CONNECT", destination, request)
	if err != nil {
		return nil, err
	}
	return newH3StreamConn(c.ctx, stream.stream, destination, stream.onClose), nil
}

func (c *h3Client) DialPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, net.Addr, error) {
	header := make(http.Header)
	header.Set("Capsule-Protocol", "?1")
	request := &http.Request{Method: http.MethodConnect, Proto: "connect-udp", URL: connectUDPURL(c.hop.Server, destination.AddrString(), destination.Port), Host: c.hop.Server, Header: header}
	stream, datagrams, err := c.openStream(ctx, "connect-udp", "CONNECT-UDP", destination, request)
	if err != nil {
		return nil, nil, err
	}
	return newH3PacketConn(c.ctx, stream.stream, destination, datagrams, stream.onClose), destination, nil
}

type openedH3Stream struct {
	stream  *http3.RequestStream
	onClose func()
}

func (c *h3Client) openStream(ctx context.Context, stage, protocol string, destination M.Socksaddr, template *http.Request) (openedH3Stream, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()
	for attempt := 0; attempt < 2; attempt++ {
		s, err := c.acquire(ctx)
		if err != nil {
			return openedH3Stream{}, false, err
		}
		request := template.Clone(ctx)
		if !s.authenticated.Load() {
			request.Header.Set("Proxy-Authorization", s.token.Authorization)
		}
		if c.geohash != nil {
			if gh := c.geohash(); gh != "" {
				request.Header.Set("Sec-CH-Geohash", gh)
			}
		}
		c.observe(stage, progress.Running, destination.String(), nil)
		stream, status, err := openH3Request(ctx, s.client, c.hop, protocol, request, c.onGeohash)
		if err == nil {
			s.authenticated.Store(true)
			c.observe(stage, progress.OK, destination.String(), nil)
			c.logf("%s: H3 %s established to %s (HTTP %d)", c.hop.Name, protocol, destination, status)
			return openedH3Stream{stream: stream, onClose: s.streams.Done}, s.client.Settings().EnableDatagrams, nil
		}
		s.streams.Done()
		c.observe(stage, progress.Failed, destination.String(), err)
		if status == http.StatusUnauthorized || status == http.StatusProxyAuthRequired {
			c.source.Rejected(c.hop.ID)
			c.observe("tokens", progress.Retry, "relay rejected session token; replacing session", err)
			c.invalidate(s)
			continue
		}
		// This also replaces a connection that received GOAWAY. Its existing
		// request streams remain alive while the replacement session opens.
		if status == 0 && ctx.Err() == nil {
			c.invalidate(s)
			if attempt == 0 {
				c.observe(stage, progress.Retry, "replacing session", err)
				continue
			}
		}
		return openedH3Stream{}, false, err
	}
	return openedH3Stream{}, false, fmt.Errorf("%s: H3 authentication failed after token replacement", c.hop.Name)
}

func (c *h3Client) invalidate(s *h3Session) {
	c.mu.Lock()
	c.drainLocked(s)
	if c.current == s {
		c.current = nil
	}
	c.mu.Unlock()
}

func (c *h3Client) drainLocked(s *h3Session) {
	if s.draining {
		return
	}
	s.draining = true
	go func() {
		s.streams.Wait()
		s.close()
		c.mu.Lock()
		delete(c.sessions, s)
		c.completeLocked()
		c.mu.Unlock()
	}()
}

func (c *h3Client) completeLocked() {
	if c.retired && c.opening == nil && len(c.sessions) == 0 {
		c.doneOnce.Do(func() { c.cancel(); close(c.done) })
	}
}

func (c *h3Client) Retire() <-chan struct{} {
	c.mu.Lock()
	c.retired = true
	if c.opening != nil {
		c.opening.cancel()
	}
	for s := range c.sessions {
		c.drainLocked(s)
	}
	c.completeLocked()
	c.mu.Unlock()
	return c.done
}

func (c *h3Client) Close() error {
	c.cancel()
	done := c.Retire()
	c.mu.Lock()
	sessions := make([]*h3Session, 0, len(c.sessions))
	for s := range c.sessions {
		sessions = append(sessions, s)
	}
	c.mu.Unlock()
	for _, s := range sessions {
		s.close()
	}
	<-done
	return nil
}

func (s *h3Session) close() {
	s.closeOnce.Do(func() {
		if s.client != nil {
			_ = s.client.CloseWithError(0, "")
		}
		if s.socket != nil {
			_ = s.socket.Close()
		}
	})
}

func systemPacketDialer(ctx context.Context, destination M.Socksaddr) (net.PacketConn, net.Addr, error) {
	remote, err := resolveQUICAddr(ctx, destination.String())
	if err != nil {
		return nil, nil, err
	}
	network, address := "udp4", "0.0.0.0:0"
	if remote.IP.To4() == nil {
		network, address = "udp6", "[::]:0"
	}
	socket, err := (&net.ListenConfig{}).ListenPacket(ctx, network, address)
	return socket, remote, err
}

func resolveQUICAddr(ctx context.Context, address string) (*net.UDPAddr, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no address for %s", host)
	}
	ip := ips[0]
	for _, candidate := range ips {
		if candidate.Is4() {
			ip = candidate
			break
		}
	}
	return &net.UDPAddr{IP: net.IP(ip.AsSlice()), Port: int(n), Zone: ip.Zone()}, nil
}

func openH3Request(ctx context.Context, client *http3.ClientConn, hop Hop, protocol string, request *http.Request, onGeohash func(string)) (*http3.RequestStream, int, error) {
	select {
	case <-client.ReceivedSettings():
	case <-ctx.Done():
		return nil, 0, ctx.Err()
	case <-client.Context().Done():
		return nil, 0, context.Cause(client.Context())
	}
	// Apple publishes RFC 9298 but omits SETTINGS_ENABLE_CONNECT_PROTOCOL.
	stream, err := client.OpenRequestStream(ctx)
	if err != nil {
		return nil, 0, err
	}
	stop := context.AfterFunc(ctx, func() { stream.CancelRead(0); stream.CancelWrite(0) })
	err = stream.SendRequestHeader(request)
	var response *http.Response
	if err == nil {
		response, err = stream.ReadResponse()
	}
	if !stop() && err == nil {
		err = ctx.Err()
	}
	if err != nil {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return nil, 0, fmt.Errorf("%s H3 %s: %w", hop.Name, protocol, err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return nil, response.StatusCode, fmt.Errorf("%s H3 %s: HTTP %d", hop.Name, protocol, response.StatusCode)
	}
	if onGeohash != nil {
		if gh := response.Header.Get("Client-Geohash"); gh != "" {
			onGeohash(gh)
		}
	}
	return stream, response.StatusCode, nil
}

type h3StreamConn struct {
	*http3.RequestStream
	stop      func() bool
	remote    net.Addr
	closeOnce sync.Once
	onClose   func()
}

func newH3StreamConn(ctx context.Context, stream *http3.RequestStream, remote net.Addr, onClose func()) *h3StreamConn {
	c := &h3StreamConn{RequestStream: stream, remote: remote, onClose: onClose}
	initialized := make(chan struct{})
	c.stop = context.AfterFunc(ctx, func() {
		<-initialized
		_ = c.Close()
	})
	close(initialized)
	return c
}

func (c *h3StreamConn) CloseWrite() error { return c.RequestStream.Close() }

func (c *h3StreamConn) Close() error {
	c.closeOnce.Do(func() {
		c.stop()
		c.RequestStream.CancelRead(0)
		_ = c.RequestStream.Close()
		if c.onClose != nil {
			c.onClose()
		}
	})
	return nil
}

func (c *h3StreamConn) LocalAddr() net.Addr  { return M.Socksaddr{} }
func (c *h3StreamConn) RemoteAddr() net.Addr { return c.remote }

// h3PacketConn owns one request stream; it merges HTTP Datagrams and DATAGRAM
// capsules and exposes complete packets directly to QUIC or the final caller.
type h3PacketConn struct {
	ctx          context.Context
	cancel       context.CancelCauseFunc
	stop         func() bool
	stream       *http3.RequestStream
	capsule      *capsuleConn
	target       M.Socksaddr
	datagrams    bool
	packets      chan []byte
	readDeadline pipe.Deadline
	writeMu      sync.Mutex
	closeOnce    sync.Once
	workers      sync.WaitGroup
	onClose      func()
}

func newH3PacketConn(ctx context.Context, stream *http3.RequestStream, target M.Socksaddr, datagrams bool, onClose func()) *h3PacketConn {
	ctx, cancel := context.WithCancelCause(ctx)
	c := &h3PacketConn{ctx: ctx, cancel: cancel, stream: stream, capsule: newCapsuleConn(stream), target: target, datagrams: datagrams, packets: make(chan []byte, 64), readDeadline: pipe.MakeDeadline(), onClose: onClose}
	c.workers.Add(1)
	if datagrams {
		c.workers.Add(1)
	}
	// AfterFunc can start immediately for an already-canceled parent. Publish
	// stop before its callback or any read worker can enter closeWithError.
	initialized := make(chan struct{})
	c.stop = context.AfterFunc(ctx, func() {
		<-initialized
		c.closeWithError(context.Cause(ctx))
	})
	close(initialized)
	go c.runReader(c.readCapsules)
	if datagrams {
		go c.runReader(c.readDatagrams)
	}
	return c
}

func (c *h3PacketConn) runReader(read func() error) {
	err := read()
	// onClose may call Close synchronously, so release this worker first.
	c.workers.Done()
	c.closeWithError(err)
}

func (c *h3PacketConn) readCapsules() error {
	for {
		packet, err := c.capsule.ReadPacket()
		if err != nil {
			return err
		}
		if !c.deliver(packet) {
			return context.Cause(c.ctx)
		}
	}
}

func (c *h3PacketConn) deliver(packet []byte) bool {
	select {
	case c.packets <- packet:
		return true
	case <-c.ctx.Done():
		return false
	}
}

func (c *h3PacketConn) readDatagrams() error {
	for {
		packet, err := c.stream.ReceiveDatagram(c.ctx)
		if err != nil {
			return err
		}
		reader := bytes.NewReader(packet)
		contextID, err := readCapsuleVarint(reader)
		if err != nil {
			return fmt.Errorf("CONNECT-UDP datagram context: %w", unexpectedEOF(err))
		}
		if contextID != 0 {
			continue
		}
		if reader.Len() > maxUDPPayload {
			return fmt.Errorf("CONNECT-UDP payload exceeds RFC 9298 maximum: %d", reader.Len())
		}
		if !c.deliver(packet[len(packet)-reader.Len():]) {
			return context.Cause(c.ctx)
		}
	}
}

func (c *h3PacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case <-c.ctx.Done():
		return 0, nil, context.Cause(c.ctx)
	default:
	}
	select {
	case packet := <-c.packets:
		// Match a UDP socket: a short caller buffer discards the suffix. QUIC
		// can then drop a truncated packet without losing its packet socket.
		return copy(p, packet), c.target, nil
	case <-c.readDeadline.Wait():
		return 0, nil, os.ErrDeadlineExceeded
	case <-c.ctx.Done():
		return 0, nil, context.Cause(c.ctx)
	}
}

func (c *h3PacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	n, _, err := c.ReadFrom(buffer.FreeBytes())
	buffer.Extend(n)
	return c.target, err
}

func (c *h3PacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if len(p) > maxUDPPayload {
		return 0, fmt.Errorf("CONNECT-UDP payload exceeds RFC 9298 maximum: %d", len(p))
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.ctx.Err() != nil {
		return 0, context.Cause(c.ctx)
	}
	if c.datagrams {
		packet := make([]byte, len(p)+1)
		copy(packet[1:], p)
		err := c.stream.SendDatagram(packet)
		if err == nil {
			return len(p), nil
		}
		var tooLarge *quic.DatagramTooLargeError
		if !errors.As(err, &tooLarge) {
			c.closeWithError(err)
			return 0, err
		}
	}
	n, err := c.capsule.WritePacket(p)
	if err != nil {
		c.closeWithError(err)
	}
	return n, err
}

func (c *h3PacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	_, err := c.WriteTo(buffer.Bytes(), destination)
	return err
}

func (c *h3PacketConn) closeWithError(err error) {
	closed := false
	c.closeOnce.Do(func() {
		if err == nil {
			err = net.ErrClosed
		}
		c.stop()
		c.cancel(err)
		c.stream.CancelRead(0)
		c.stream.CancelWrite(0)
		closed = true
	})
	// Keep callbacks outside Once so reentrant Close does not wait on itself.
	if closed && c.onClose != nil {
		c.onClose()
	}
}

func (c *h3PacketConn) Close() error {
	c.closeWithError(net.ErrClosed)
	c.workers.Wait()
	return nil
}
func (c *h3PacketConn) LocalAddr() net.Addr  { return &net.UDPAddr{IP: net.IPv4zero} }
func (c *h3PacketConn) RemoteAddr() net.Addr { return c.target }
func (c *h3PacketConn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Set(t)
	return nil
}
func (c *h3PacketConn) SetWriteDeadline(t time.Time) error { return c.stream.SetWriteDeadline(t) }
func (c *h3PacketConn) SetDeadline(t time.Time) error {
	return errors.Join(c.SetReadDeadline(t), c.SetWriteDeadline(t))
}
