package diagnostic

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"slices"

	"golang.org/x/net/dns/dnsmessage"

	"iprd/internal/control"
	"iprd/internal/relay"
)

type DNSReport struct {
	Server      string  `json:"server"`
	Name        string  `json:"name"`
	Type        string  `json:"type"`
	QueryID     uint16  `json:"queryId"`
	ResponseID  uint16  `json:"responseId"`
	QR          bool    `json:"qr"`
	RCode       *uint16 `json:"rcode,omitempty"`
	RCodeName   string  `json:"rcodeName,omitempty"`
	AnswerCount int     `json:"answerCount"`
	Truncated   bool    `json:"truncated"`
}

func (r *recorder) probeDNS(ctx context.Context, dialer *relay.Dialer, manager *control.Manager, server string) error {
	const stage = "target:dns"
	r.stage(stage, "running", "establish both relay hops for UDP and query example.com A")
	var idBytes [2]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		r.fail(stage, err)
		return err
	}
	id := binary.BigEndian.Uint16(idBytes[:])
	name, err := dnsmessage.NewName("example.com.")
	if err != nil {
		r.fail(stage, err)
		return err
	}
	query := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}
	packet, err := query.Pack()
	if err != nil {
		r.fail(stage, err)
		return err
	}
	r.mu.Lock()
	r.report.DNS = &DNSReport{Server: server, Name: name.String(), Type: "A", QueryID: id}
	r.mu.Unlock()
	conn, err := dialer.DialContext(ctx, "udp", server)
	if err != nil {
		snapshot := manager.Snapshot()
		if snapshot.LastFailure != nil {
			r.stage(snapshot.LastFailure.Stage, "retry", snapshot.LastFailure.Message)
		}
		r.fail(r.failureStage(snapshot, err), err)
		return err
	}
	defer conn.Close()
	if route, ok := dialer.Route("udp"); ok {
		r.mu.Lock()
		r.actualRoute = &route
		r.setRouteLocked(route)
		r.mu.Unlock()
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			r.fail(stage, err)
			return err
		}
	}
	if count, err := conn.Write(packet); err != nil {
		r.fail(stage, err)
		return err
	} else if count != len(packet) {
		r.fail(stage, io.ErrShortWrite)
		return io.ErrShortWrite
	}
	r.mu.Lock()
	r.targetSent = true
	r.mu.Unlock()
	r.stage(stage, "running", fmt.Sprintf("DNS query sent to %s through both relay hops", server))
	responseBytes := make([]byte, 65535)
	count, err := conn.Read(responseBytes)
	r.mu.Lock()
	r.report.ResponseBytes = int64(count)
	r.mu.Unlock()
	if err != nil {
		r.fail(stage, err)
		return err
	}
	var response dnsmessage.Message
	if err := response.Unpack(responseBytes[:count]); err != nil {
		err = fmt.Errorf("parse DNS response: %w", err)
		r.fail(stage, err)
		return err
	}
	code := uint16(response.RCode)
	r.mu.Lock()
	dns := r.report.DNS
	dns.ResponseID, dns.QR, dns.RCode = response.ID, response.Response, &code
	dns.RCodeName, dns.AnswerCount, dns.Truncated = response.RCode.String(), len(response.Answers), response.Truncated
	r.mu.Unlock()
	if response.ID != id || !response.Response {
		err := fmt.Errorf("invalid DNS response: id=%d (want %d), QR=%t", response.ID, id, response.Response)
		r.fail(stage, err)
		return err
	}
	if response.RCode != dnsmessage.RCodeSuccess {
		err := fmt.Errorf("DNS server returned rcode=%d (%s)", code, response.RCode)
		r.fail(stage, err)
		return err
	}
	r.stage(stage, "ok", fmt.Sprintf("DNS id/QR verified; rcode=%d, answers=%d, %d response bytes", code, len(response.Answers), count))
	return nil
}

func (r *recorder) setRouteLocked(route relay.Config) {
	proxy := func(hop relay.Hop, role string) Proxy {
		if r.report.Configuration != nil {
			for _, candidate := range r.report.Configuration.Proxies {
				if candidate.Vendor == hop.Name && candidate.Server == hop.Server {
					return candidate
				}
			}
		}
		return Proxy{Index: -1, Vendor: hop.Name, Hostname: hop.ServerName, Server: hop.Server, Hop: role}
	}
	r.report.Route = &Route{Ingress: proxy(route.Ingress, "ingress"), Egress: proxy(route.Egress, "egress")}
	if configuration := r.report.Configuration; configuration != nil {
		for i := range configuration.Paths {
			path := &configuration.Paths[i]
			path.Selected = slices.Equal(path.Indexes, []int{r.report.Route.Ingress.Index, r.report.Route.Egress.Index})
		}
	}
}
