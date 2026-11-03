package relay

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	rpktls "github.com/sagernet/quic-go/rpktls"
)

type Transport string

const (
	TransportAuto Transport = "auto"
	TransportH3   Transport = "h3"
	TransportH2   Transport = "h2"
)

func ParseTransport(value string) (Transport, error) {
	switch Transport(strings.ToLower(strings.TrimSpace(value))) {
	case "", TransportAuto:
		return TransportAuto, nil
	case TransportH3:
		return TransportH3, nil
	case TransportH2:
		return TransportH2, nil
	default:
		return "", fmt.Errorf("unsupported transport %q (want auto, h3, or h2)", value)
	}
}

const geohashAlphabet = "0123456789bcdefghjkmnpqrstuvwxyz"

// ParseGeohash normalizes a geohash setting into "", "auto", or a quoted
// 4-character RFC 8941 string ("xxxx").
func ParseGeohash(value string) (string, error) {
	trimmed := strings.ToLower(strings.Trim(strings.TrimSpace(value), `"`))
	switch trimmed {
	case "", "none", "off":
		return "", nil
	case "auto":
		return "auto", nil
	}
	if len(trimmed) != 4 {
		return "", fmt.Errorf("invalid geohash %q (want auto or a 4-character base32 geohash)", value)
	}
	for i := 0; i < len(trimmed); i++ {
		if !strings.ContainsRune(geohashAlphabet, rune(trimmed[i])) {
			return "", fmt.Errorf("invalid geohash %q (characters must be in %s)", value, geohashAlphabet)
		}
	}
	return `"` + trimmed + `"`, nil
}

// Config is the boundary between token issuance and the data plane.
type Config struct {
	Revision string `json:"revision,omitempty"`
	Epoch    uint16 `json:"epoch"`
	Ingress  Hop    `json:"ingress"`
	Egress   Hop    `json:"egress"`
}

type Hop struct {
	ID         string   `json:"id,omitempty"`
	Name       string   `json:"name"`
	Server     string   `json:"server"`
	ServerName string   `json:"server_name"`
	PublicKeys []string `json:"public_keys"`
	Algorithm  int      `json:"algorithm"`
}

func (h Hop) hostname() (string, error) {
	if h.ServerName != "" {
		return h.ServerName, nil
	}
	host, _, err := net.SplitHostPort(h.Server)
	return host, err
}

func (h Hop) publicKeys() ([][]byte, error) {
	keys := make([][]byte, 0, len(h.PublicKeys))
	for _, encoded := range h.PublicKeys {
		key, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("%s public key: %w", h.Name, err)
		}
		keys = append(keys, key)
	}
	return keys, nil
}

const algorithmX25519MLKEM768 = 3

func (h Hop) curvePreferences() []rpktls.CurveID {
	if h.Algorithm == algorithmX25519MLKEM768 {
		return []rpktls.CurveID{rpktls.X25519MLKEM768, rpktls.X25519}
	}
	return []rpktls.CurveID{rpktls.X25519}
}

// Credential is consumed once when a new relay session authenticates.
type Credential struct {
	Authorization string    `json:"authorization"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// Source owns configuration refresh and each hop's unused credential pool.
type Source interface {
	Current(context.Context) (Config, error)
	TakeToken(context.Context, string) (Credential, error)
	Rejected(string)
}

// AlternativeSource activates additional published routes for UDP when the
// preferred egress does not offer CONNECT-UDP. Hops share credential pools.
type AlternativeSource interface {
	Alternatives(context.Context) ([]Config, error)
	ActivateRoute(context.Context, Config) error
}

var ErrConfigurationChanged = errors.New("relay configuration changed")
