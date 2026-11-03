package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/protocol/socks/socks5"
)

// sing's default packet buffer is 16 KiB; retain an entire UDP datagram.
const (
	udpBufferSize  = 65535
	udpTargetQueue = 64
	udpTargetIdle  = 2 * time.Minute
)

type udpAssociation struct {
	ctx     context.Context
	cancel  context.CancelFunc
	control net.Conn
	socket  *net.UDPConn
	source  M.Socksaddr
	handler *forwarder
	once    sync.Once
	workers sync.WaitGroup

	mu         sync.Mutex
	client     netip.AddrPort
	clientPort uint16
	targets    map[string]*udpTarget
}

type udpTarget struct {
	destination M.Socksaddr
	packets     chan *buf.Buffer
	lastActive  atomic.Int64
}

func (t *udpTarget) touch() { t.lastActive.Store(time.Now().UnixNano()) }

func handleUDPAssociate(ctx context.Context, control net.Conn, reader *bufio.Reader, handler *forwarder, source, requested M.Socksaddr) error {
	local := M.SocksaddrFromNet(control.LocalAddr()).Unwrap()
	socket, err := net.ListenUDP(M.NetworkFromNetAddr("udp", local.Addr), M.SocksaddrFrom(local.Addr, 0).UDPAddr())
	if err != nil {
		_ = socks5.WriteResponse(control, socks5.Response{ReplyCode: socks5.ReplyCodeForError(err)})
		return fmt.Errorf("SOCKS5 UDP association: %w", err)
	}
	ctx, cancel := context.WithCancel(ctx)
	a := &udpAssociation{
		ctx: ctx, cancel: cancel, control: control, socket: socket, source: source,
		handler: handler, clientPort: requested.Port, targets: make(map[string]*udpTarget),
	}
	if requested.Port != 0 {
		a.client = netip.AddrPortFrom(source.Addr.Unmap(), requested.Port)
	}
	stop := context.AfterFunc(ctx, a.close)
	defer stop()
	defer a.close()
	if err := socks5.WriteResponse(control, socks5.Response{
		ReplyCode: socks5.ReplyCodeSuccess,
		Bind:      M.SocksaddrFromNet(socket.LocalAddr()).Unwrap(),
	}); err != nil {
		return err
	}
	_ = control.SetReadDeadline(time.Time{})
	handler.logf("proxy UDP association from %s listening on %s", source, socket.LocalAddr())
	controlDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, reader)
		a.close()
		close(controlDone)
	}()
	err = a.readPackets()
	a.close()
	<-controlDone
	a.workers.Wait()
	return err
}

func (a *udpAssociation) close() {
	a.once.Do(func() {
		a.cancel()
		_ = a.socket.Close()
		_ = a.control.Close()
	})
}

func (a *udpAssociation) readPackets() error {
	for {
		packet := buf.NewSize(udpBufferSize)
		n, source, err := a.socket.ReadFromUDPAddrPort(packet.FreeBytes())
		if err != nil {
			packet.Release()
			if a.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		source = netip.AddrPortFrom(source.Addr().Unmap(), source.Port())
		if source.Addr() != a.source.Addr.Unmap() || n < 4 {
			packet.Release()
			continue
		}
		packet.Truncate(n)
		header := packet.Bytes()
		// RFC 1928: reserved bytes are zero. Fragmentation is unsupported, so
		// discard nonzero FRAG instead of forwarding an incomplete payload.
		if header[0] != 0 || header[1] != 0 || header[2] != 0 {
			packet.Release()
			continue
		}
		packet.Advance(3)
		destination, err := M.SocksaddrSerializer.ReadAddrPort(packet)
		if err != nil || !destination.IsValid() {
			packet.Release()
			continue
		}
		a.mu.Lock()
		if a.ctx.Err() != nil || (a.clientPort != 0 && source.Port() != a.clientPort) {
			a.mu.Unlock()
			packet.Release()
			continue
		}
		if a.clientPort == 0 {
			a.clientPort, a.client = source.Port(), source
		}
		key := destination.String()
		target := a.targets[key]
		if target == nil {
			target = &udpTarget{destination: destination, packets: make(chan *buf.Buffer, udpTargetQueue)}
			target.touch()
			a.targets[key] = target
			a.workers.Add(1)
			go a.runTarget(key, target)
		}
		select {
		case target.packets <- packet:
			target.touch()
		default:
			packet.Release()
		}
		a.mu.Unlock()
	}
}

func (a *udpAssociation) runTarget(key string, target *udpTarget) {
	defer a.workers.Done()
	defer a.removeTarget(key, target)
	ctx, cancel := context.WithCancel(a.ctx)
	defer cancel()
	a.handler.logf("proxy UDP %s -> %s", a.source, target.destination)
	conn, err := a.handler.dial(ctx, "udp", target.destination.String())
	if err != nil {
		a.logTargetError(target, err)
		return
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	idleDone := make(chan struct{})
	go func() {
		defer close(idleDone)
		idle := time.NewTimer(udpTargetIdle)
		defer idle.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-idle.C:
				remaining := udpTargetIdle - time.Since(time.Unix(0, target.lastActive.Load()))
				if remaining <= 0 {
					cancel()
					return
				}
				idle.Reset(remaining)
			}
		}
	}()
	defer func() { cancel(); <-idleDone }()
	readDone := make(chan error, 1)
	go func() {
		readDone <- a.readTarget(conn, target)
		cancel()
	}()
	writeErr := a.writeTarget(ctx, conn, target)
	cancel()
	_ = conn.Close()
	readErr := <-readDone
	if writeErr != nil && !errors.Is(writeErr, context.Canceled) {
		a.logTargetError(target, writeErr)
	} else {
		a.logTargetError(target, readErr)
	}
}

func (a *udpAssociation) writeTarget(ctx context.Context, conn net.Conn, target *udpTarget) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case packet := <-target.packets:
			n, err := conn.Write(packet.Bytes())
			if err == nil && n != packet.Len() {
				err = io.ErrShortWrite
			}
			packet.Release()
			if err != nil {
				return err
			}
			target.touch()
		}
	}
}

func (a *udpAssociation) readTarget(conn net.Conn, target *udpTarget) error {
	destination := target.destination
	payload := make([]byte, udpBufferSize)
	for {
		n, readErr := conn.Read(payload)
		if readErr != nil && n == 0 {
			return readErr
		}
		target.touch()
		packet := buf.NewSize(3 + M.SocksaddrSerializer.AddrPortLen(destination) + n)
		_ = packet.WriteZeroN(3)
		err := M.SocksaddrSerializer.WriteAddrPort(packet, destination)
		if err == nil {
			_, err = packet.Write(payload[:n])
		}
		if err == nil {
			a.mu.Lock()
			client := a.client
			a.mu.Unlock()
			_, err = a.socket.WriteToUDPAddrPort(packet.Bytes(), client)
		}
		packet.Release()
		if err != nil {
			return err
		}
		if readErr != nil {
			return readErr
		}
	}
}

func (a *udpAssociation) removeTarget(key string, target *udpTarget) {
	a.mu.Lock()
	if a.targets[key] == target {
		delete(a.targets, key)
	}
	a.mu.Unlock()
	for {
		select {
		case packet := <-target.packets:
			packet.Release()
		default:
			return
		}
	}
}

func (a *udpAssociation) logTargetError(target *udpTarget, err error) {
	if err != nil && a.ctx.Err() == nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, context.Canceled) {
		a.handler.logf("proxy UDP %s -> %s: %v", a.source, target.destination, err)
	}
}
