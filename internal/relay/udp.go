package relay

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// RFC 9298 section 5 requires aborting streams with larger UDP payloads.
const maxUDPPayload = 65527

func connectUDPURL(authority string, destination string, port uint16) *url.URL {
	const prefix = "/.well-known/masque/udp/"
	suffix := "/" + strconv.Itoa(int(port)) + "/"
	return &url.URL{
		Scheme: "https", Host: authority,
		Path:    prefix + destination + suffix,
		RawPath: prefix + strings.ReplaceAll(url.PathEscape(destination), ":", "%3A") + suffix,
	}
}

// udpConn is the sole packet-to-stream view, used only at DialContext's boundary.
// Each Read consumes one complete datagram, even when p is too small.
type udpConn struct {
	net.PacketConn
	remote net.Addr
}

func (c *udpConn) Read(p []byte) (int, error) {
	n, _, err := c.ReadFrom(p)
	return n, err
}
func (c *udpConn) Write(p []byte) (int, error) { return c.WriteTo(p, c.remote) }
func (c *udpConn) RemoteAddr() net.Addr        { return c.remote }

var _ net.Conn = (*udpConn)(nil)

// capsuleConn is the RFC 9297 codec on an HTTP/3 request stream. It never wraps
// a stream as net.Conn or imposes a read deadline partway through a capsule.
type capsuleConn struct {
	stream io.ReadWriteCloser
	reader *bufio.Reader
}

func newCapsuleConn(stream io.ReadWriteCloser) *capsuleConn {
	return &capsuleConn{stream: stream, reader: bufio.NewReader(stream)}
}

func (c *capsuleConn) ReadPacket() ([]byte, error) {
	for {
		kind, err := readCapsuleVarint(c.reader)
		if err != nil {
			return nil, err
		}
		length, err := readCapsuleVarint(c.reader)
		if err != nil {
			return nil, fmt.Errorf("CONNECT-UDP capsule length: %w", unexpectedEOF(err))
		}
		value := &io.LimitedReader{R: c.reader, N: int64(length)}
		if kind == 0 {
			contextID, err := readCapsuleVarint(value)
			if err != nil {
				return nil, fmt.Errorf("CONNECT-UDP capsule context: %w", unexpectedEOF(err))
			}
			if contextID == 0 {
				if value.N > maxUDPPayload {
					return nil, fmt.Errorf("CONNECT-UDP payload exceeds RFC 9298 maximum: %d", value.N)
				}
				packet := make([]byte, int(value.N))
				_, err := io.ReadFull(value, packet)
				return packet, unexpectedEOF(err)
			}
		}
		// Unknown capsule types and unregistered contexts are ignored by length.
		if _, err := io.CopyN(io.Discard, value, value.N); err != nil {
			return nil, unexpectedEOF(err)
		}
	}
}

// The caller serializes writes so a partial capsule cannot interleave with
// another packet. A failed write is fatal to the containing request stream.
func (c *capsuleConn) WritePacket(packet []byte) (int, error) {
	capsule := make([]byte, 0, len(packet)+10)
	capsule = append(capsule, 0)
	capsule = appendCapsuleVarint(capsule, uint64(len(packet)+1))
	capsule = append(capsule, 0)
	headerLength := len(capsule)
	capsule = append(capsule, packet...)
	n, err := c.stream.Write(capsule)
	if err == nil && n != len(capsule) {
		err = io.ErrShortWrite
	}
	return max(0, n-headerLength), err
}

func readCapsuleVarint(reader io.Reader) (uint64, error) {
	var encoded [8]byte
	if _, err := io.ReadFull(reader, encoded[:1]); err != nil {
		return 0, err
	}
	length := 1 << (encoded[0] >> 6)
	if _, err := io.ReadFull(reader, encoded[1:length]); err != nil {
		return 0, unexpectedEOF(err)
	}
	value := uint64(encoded[0] & 0x3f)
	for _, next := range encoded[1:length] {
		value = value<<8 | uint64(next)
	}
	return value, nil
}

func appendCapsuleVarint(destination []byte, value uint64) []byte {
	length, prefix := 1, byte(0)
	switch {
	case value >= 1<<30:
		length, prefix = 8, 0xc0
	case value >= 1<<14:
		length, prefix = 4, 0x80
	case value >= 1<<6:
		length, prefix = 2, 0x40
	}
	start := len(destination)
	destination = append(destination, make([]byte, length)...)
	for offset := length - 1; offset >= 0; offset-- {
		destination[start+offset] = byte(value)
		value >>= 8
	}
	destination[start] |= prefix
	return destination
}

func unexpectedEOF(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}
