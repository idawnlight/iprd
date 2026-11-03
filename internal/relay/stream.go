package relay

import (
	"context"
	"errors"
	"github.com/sagernet/sing/common/bufio/deadline"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// streamConn exposes one HTTP/2 stream, including an independent write half-close.
// sing's deadline adapter supplies read deadlines without timing out the shared TLS socket.
type streamConn struct {
	reader io.ReadCloser
	writer net.Conn
	cancel context.CancelFunc
	remote net.Addr
	once   sync.Once
}

func (c *streamConn) Read(p []byte) (int, error)  { return c.reader.Read(p) }
func (c *streamConn) Write(p []byte) (int, error) { return c.writer.Write(p) }
func (c *streamConn) CloseWrite() error           { return c.writer.Close() }
func (c *streamConn) Close() error {
	c.once.Do(func() { c.cancel(); c.writer.Close(); go c.reader.Close() })
	return nil
}
func (c *streamConn) LocalAddr() net.Addr                { return M.Socksaddr{} }
func (c *streamConn) RemoteAddr() net.Addr               { return c.remote }
func (c *streamConn) SetDeadline(t time.Time) error      { return os.ErrInvalid }
func (c *streamConn) SetReadDeadline(t time.Time) error  { return os.ErrInvalid }
func (c *streamConn) SetWriteDeadline(t time.Time) error { return c.writer.SetWriteDeadline(t) }
func (c *streamConn) NeedAdditionalReadDeadline() bool   { return true }

type tunnelConn struct {
	N.ExtendedConn
	stream *streamConn
}

func wrapStream(s *streamConn) *tunnelConn { return &tunnelConn{deadline.NewConn(s), s} }
func (c *tunnelConn) CloseWrite() error    { return c.stream.CloseWrite() }
func (c *tunnelConn) SetDeadline(t time.Time) error {
	return errors.Join(c.SetReadDeadline(t), c.SetWriteDeadline(t))
}
