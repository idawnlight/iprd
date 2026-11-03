package relay

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"iprd/internal/progress"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/pipe"
	"golang.org/x/net/http2"
)

// h2Client binds a fresh credential to each underlying TLS session. Network
// establishment happens outside mu; waiting callers retain their own context.
type h2Client struct {
	ctx       context.Context
	hop       Hop
	tls       *rpkDialer
	source    Source
	geohash   func() string
	onGeohash func(string)
	logf      LogFunc
	observer  progress.Observer
	mu       sync.Mutex
	sessions []*h2Session
	opening  *h2Opening
	retired  bool
	done     chan struct{}
	wg       sync.WaitGroup
}
type h2Session struct {
	cc            *http2.ClientConn
	socket        *sessionSocket
	token         Credential
	draining      bool
	authenticated atomic.Bool
}
type h2Opening struct {
	done   chan struct{}
	cancel context.CancelFunc
	err    error
}

func newH2Client(ctx context.Context, hop Hop, tls *rpkDialer, source Source, logf LogFunc, observer progress.Observer) *h2Client {
	return &h2Client{ctx: ctx, hop: hop, tls: tls, source: source, logf: logf, observer: observer, done: make(chan struct{})}
}

func (c *h2Client) observe(stage string, status progress.Status, detail string, err error) {
	c.observer.Emit(progress.Event{Stage: stage, Hop: c.hop.Name, Network: N.NetworkTCP, Status: status, Detail: detail, Err: err})
}

func (c *h2Client) acquire(ctx context.Context) (*h2Session, error) {
	for {
		c.mu.Lock()
		if c.retired || c.ctx.Err() != nil {
			c.mu.Unlock()
			return nil, ErrConfigurationChanged
		}
		kept := c.sessions[:0]
		var selected *h2Session
		for _, s := range c.sessions {
			if s.socket.closed.Load() {
				continue
			}
			kept = append(kept, s)
			if !s.token.ExpiresAt.IsZero() && !time.Now().Before(s.token.ExpiresAt) {
				c.drainLocked(s)
			}
			if selected == nil && !s.draining && s.cc.ReserveNewRequest() {
				selected = s
			}
		}
		c.sessions = kept
		if selected != nil {
			c.mu.Unlock()
			return selected, nil
		}
		opening := c.opening
		if opening == nil {
			dialCtx, cancel := context.WithTimeout(c.ctx, connectTimeout)
			opening = &h2Opening{done: make(chan struct{}), cancel: cancel}
			c.opening = opening
			c.wg.Add(1)
			go c.open(dialCtx, opening)
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

func (c *h2Client) open(ctx context.Context, opening *h2Opening) {
	defer c.wg.Done()
	defer opening.cancel()
	var session *h2Session
	conn, err := c.tls.DialTLSContext(ctx, M.ParseSocksaddr(c.hop.Server))
	if err == nil {
		stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
		var token Credential
		c.observe("tokens", progress.Running, "acquiring connection token", nil)
		token, err = c.source.TakeToken(ctx, c.hop.ID)
		if err != nil {
			c.observe("tokens", progress.Failed, "", err)
		} else {
			c.observe("tokens", progress.OK, "connection token acquired", nil)
		}
		if err == nil {
			var cc *http2.ClientConn
			transport := &http2.Transport{DisableCompression: true}
			socket := &sessionSocket{Conn: conn}
			cc, err = transport.NewClientConn(socket)
			if err == nil {
				session = &h2Session{cc: cc, socket: socket, token: token}
			}
		}
		if !stop() && err == nil {
			err = ctx.Err()
			if session != nil {
				session.cc.Close()
				session = nil
			}
		}
		if err != nil {
			conn.Close()
		}
	}
	var discard *h2Session
	c.mu.Lock()
	if c.retired || c.ctx.Err() != nil {
		if session != nil {
			discard = session
		}
		err = ErrConfigurationChanged
	} else if session != nil {
		c.sessions = append(c.sessions, session)
		c.logf("%s: new H2 session with a fresh token", c.hop.Name)
	}
	opening.err = err
	c.opening = nil
	close(opening.done)
	c.mu.Unlock()
	if discard != nil {
		discard.cc.Close()
	}
}

func (c *h2Client) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	network = N.NetworkName(network)
	if network != N.NetworkTCP {
		return nil, os.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()
	for attempt := 0; attempt < 2; attempt++ {
		session, err := c.acquire(ctx)
		if err != nil {
			return nil, err
		}
		conn, status, err := c.connect(ctx, session, destination)
		if status == http.StatusUnauthorized || status == http.StatusProxyAuthRequired {
			c.mu.Lock()
			c.drainLocked(session)
			c.mu.Unlock()
			c.source.Rejected(c.hop.ID)
			c.observe("tokens", progress.Retry, "relay rejected session token; replacing session", err)
			c.logf("%s: relay rejected session token (HTTP %d); replacing session", c.hop.Name, status)
			continue
		}
		if err != nil && ctx.Err() == nil && !session.cc.CanTakeNewRequest() && attempt == 0 {
			continue
		}
		return conn, err
	}
	return nil, fmt.Errorf("%s: relay authentication failed after token replacement", c.hop.Name)
}

func (c *h2Client) connect(ctx context.Context, s *h2Session, destination M.Socksaddr) (_ net.Conn, _ int, err error) {
	c.observe("connect", progress.Running, destination.String(), nil)
	defer func() {
		if err != nil {
			c.observe("connect", progress.Failed, destination.String(), err)
		}
	}()
	input, output := pipe.Pipe()
	streamCtx, cancel := context.WithCancel(c.ctx)
	stop := context.AfterFunc(ctx, cancel)
	request := &http.Request{Method: http.MethodConnect, URL: &url.URL{Host: destination.String()}, Host: destination.String(), Header: make(http.Header), Body: input}
	if !s.authenticated.Load() {
		request.Header.Set("Proxy-Authorization", s.token.Authorization)
	}
	if c.geohash != nil {
		if gh := c.geohash(); gh != "" {
			request.Header.Set("Sec-CH-Geohash", gh)
		}
	}
	response, err := s.cc.RoundTrip(request.WithContext(streamCtx))
	stopped := stop()
	if err == nil && !stopped {
		cancel()
		go response.Body.Close()
		err = ctx.Err()
	}
	if err != nil {
		cancel()
		output.Close()
		return nil, 0, fmt.Errorf("%s H2 CONNECT: %w", c.hop.Name, err)
	}
	if response.StatusCode != http.StatusOK {
		cancel()
		go response.Body.Close()
		output.Close()
		return nil, response.StatusCode, fmt.Errorf("%s H2 CONNECT: HTTP %d", c.hop.Name, response.StatusCode)
	}
	if c.onGeohash != nil {
		if gh := response.Header.Get("Client-Geohash"); gh != "" {
			c.onGeohash(gh)
		}
	}
	s.authenticated.Store(true)
	c.observe("connect", progress.OK, destination.String(), nil)
	c.logf("%s: H2 CONNECT established to %s (HTTP %d)", c.hop.Name, destination, response.StatusCode)
	stream := &streamConn{reader: response.Body, writer: output, cancel: cancel, remote: destination}
	return wrapStream(stream), response.StatusCode, nil
}

func (c *h2Client) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

func (c *h2Client) drainLocked(s *h2Session) {
	if s.draining || (c.retired && s.socket.closed.Load()) {
		return
	}
	s.draining = true
	s.cc.SetDoNotReuse()
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		if err := s.cc.Shutdown(c.ctx); err != nil {
			_ = s.cc.Close()
		}
	}()
}

// Retire prevents new streams and lets existing streams finish naturally.
func (c *h2Client) Retire() <-chan struct{} {
	c.mu.Lock()
	if c.retired {
		c.mu.Unlock()
		return c.done
	}
	c.retired = true
	if c.opening != nil {
		c.opening.cancel()
	}
	for _, s := range c.sessions {
		c.drainLocked(s)
	}
	c.mu.Unlock()
	go func() { c.wg.Wait(); close(c.done) }()
	return c.done
}
func (c *h2Client) Close() error {
	done := c.Retire()
	c.mu.Lock()
	sessions := append([]*h2Session(nil), c.sessions...)
	c.mu.Unlock()
	for _, s := range sessions {
		_ = s.cc.Close()
	}
	<-done
	return nil
}

// Observe socket termination without ClientConn.State, which takes the HTTP/2
// frame writer lock and can wait on a blocked network write.
type sessionSocket struct {
	net.Conn
	closed atomic.Bool
}

func (s *sessionSocket) Read(p []byte) (int, error) {
	n, err := s.Conn.Read(p)
	if err != nil {
		s.closed.Store(true)
	}
	return n, err
}
func (s *sessionSocket) Close() error { s.closed.Store(true); return s.Conn.Close() }
