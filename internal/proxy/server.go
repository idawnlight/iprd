package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/sagernet/sing/common/buf"
	singbufio "github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	singhttp "github.com/sagernet/sing/protocol/http"
	"github.com/sagernet/sing/protocol/socks"
	"github.com/sagernet/sing/protocol/socks/socks5"
)

const handshakeTimeout = 15 * time.Second

// Serve accepts SOCKS5 CONNECT/UDP ASSOCIATE and HTTP proxy requests on one port.
func Serve(ctx context.Context, address string, dial func(context.Context, string, string) (net.Conn, error), logf func(string, ...any)) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	ctx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	stopListener := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer func() {
		cancel()
		stopListener()
		_ = listener.Close()
		workers.Wait()
	}()
	logf("SOCKS5 / HTTP proxy listening on %s", listener.Addr())
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer conn.Close()
			stopConn := context.AfterFunc(ctx, func() { _ = conn.Close() })
			defer stopConn()
			onClose := N.OnceClose(func(err error) {
				if err != nil && ctx.Err() == nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
					logf("proxy connection from %s: %v", conn.RemoteAddr(), err)
				}
			})
			handler := &forwarder{client: conn, dial: dial, logf: logf}
			_ = conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
			reader := bufio.NewReader(conn)
			first, err := reader.Peek(1)
			if err != nil {
				onClose(err)
				return
			}
			source := M.SocksaddrFromNet(conn.RemoteAddr()).Unwrap()
			if first[0] == socks5.Version {
				err = handleSOCKS5(ctx, conn, reader, handler, source, onClose)
			} else {
				err = singhttp.HandleConnectionEx(ctx, conn, reader, nil, handler, source, onClose)
			}
			onClose(err)
		}()
	}
}

type forwarder struct {
	client net.Conn
	dial   func(context.Context, string, string) (net.Conn, error)
	logf   func(string, ...any)
}

func (h *forwarder) NewConnectionEx(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer conn.Close()
	// Plain HTTP reaches this handler through sing's in-memory pipe. Clear the
	// accepted client's deadline so request bodies and keep-alive remain open.
	_ = h.client.SetReadDeadline(time.Time{})
	h.logf("proxy %s -> %s", source, destination)
	upstream, err := h.dial(ctx, "tcp", destination.String())
	if err != nil {
		_ = N.ReportHandshakeFailure(conn, err)
	} else {
		defer upstream.Close()
		err = N.ReportConnHandshakeSuccess(conn, upstream)
		if err == nil {
			err = singbufio.CopyConn(ctx, conn, upstream)
		}
	}
	if onClose != nil {
		onClose(err)
	}
}

func handleSOCKS5(ctx context.Context, conn net.Conn, reader *bufio.Reader, handler *forwarder, source M.Socksaddr, onClose N.CloseHandlerFunc) error {
	auth, err := socks5.ReadAuthRequest(reader)
	if err != nil {
		return err
	}
	method := socks5.AuthTypeNotRequired
	if !slices.Contains(auth.Methods, method) {
		method = socks5.AuthTypeNoAcceptedMethods
	}
	if err := socks5.WriteAuthResponse(conn, socks5.AuthResponse{Method: method}); err != nil {
		return err
	}
	if method == socks5.AuthTypeNoAcceptedMethods {
		return errors.New("SOCKS5 client does not offer no-authentication mode")
	}
	request, err := socks5.ReadRequest(reader)
	if err != nil {
		return err
	}
	if request.Command == socks5.CommandUDPAssociate {
		return handleUDPAssociate(ctx, conn, reader, handler, source, request.Destination)
	}
	if request.Command != socks5.CommandConnect {
		if err := socks5.WriteResponse(conn, socks5.Response{ReplyCode: socks5.ReplyCodeUnsupported}); err != nil {
			return err
		}
		return fmt.Errorf("unsupported SOCKS5 command %d", request.Command)
	}
	// Retain application bytes sent together with the SOCKS5 request.
	if size := reader.Buffered(); size > 0 {
		buffer := buf.NewSize(size)
		if _, err := buffer.ReadFullFrom(reader, size); err != nil {
			buffer.Release()
			return err
		}
		conn = singbufio.NewCachedConn(conn, buffer)
	}
	handler.NewConnectionEx(ctx, socks.NewLazyConn(conn, socks5.Version), source, request.Destination, onClose)
	return nil
}
