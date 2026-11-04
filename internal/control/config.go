package control

import (
	"cmp"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"iprd/internal/apple"
	"iprd/internal/relay"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

// ConfigurationURL is the NSPDefaults.global configuration endpoint shipped
// with NetworkServiceProxy.framework on the reference Mac.
const ConfigurationURL = "https://mask-api.icloud.com/v6_2/fetchConfigFile"

const DefaultClientInfo = "<MacBookPro18,3> <macOS;27.2;26B123>"

// Preferences ranks acceptable ingress and egress vendors or endpoints.
// Entries can contain comma-separated values; both slice and comma order matter.
type Preferences struct {
	Ingress []string
	Egress  []string
}

// Configuration contains the native proxy list, usable fallback paths, the
// selected ingress/egress pair and the token issuer.
// SignatureVerified means the certificate chain, project markers and signature
// over the exact nested protobuf bytes were successfully verified.
type Configuration struct {
	Raw                  []byte
	FetchedAt, RefreshAt time.Time
	Revision             string
	Epoch                uint16
	AuthURL              string
	AuthType             int
	Ingress              Proxy
	Egress               Proxy
	Proxies              []Proxy
	Paths                []Path
	SelectedPath         Path
	PreferenceFallback   bool
	SignatureVerified    bool
}

type Proxy struct {
	ID         string
	Index      int // Native array index; distinct from any proxyIndex field.
	Hop        int // Native enum: 1=ingress, 2=egress, 3=ANY.
	Name       string
	Server     string
	ServerName string
	ProxyURL   string
	PublicKeys [][]byte
	TokenKey   []byte
	Challenge  []byte
	Algorithm  int

	encodedPublicKeys []string
}

// Path is a two-hop combination published in pathWeights or fallbackPathWeights.
// Indexes reference Configuration.Proxies; zero-weight entries remain discoverable.
type Path struct {
	Indexes        []int
	Weight         uint32
	FallbackWeight uint32
	Ingress        Proxy
	Egress         Proxy
}

// FetchConfiguration downloads the signed remote protobuf, verifies it against
// independently bundled Apple roots, then selects a published fallback path.
// Without preferences it selects the highest positive-weight path.
func FetchConfiguration(ctx context.Context, client *http.Client, subscription, clientInfo string, preferences ...Preferences) (Configuration, error) {
	if client == nil {
		client = http.DefaultClient
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, ConfigurationURL, nil)
	if err != nil {
		return Configuration{}, err
	}
	request.Header.Set("X-Mask-Client-Info", clientInfo)
	request.Header.Set("X-Mask-User-Tier", "SUBSCRIBER")
	request.Header.Set("Retry-Attempt", "0")
	if subscription != "" {
		request.Header.Set("X-Mask-Subscription-Token", subscription)
	}
	response, err := client.Do(request)
	if err != nil {
		return Configuration{}, fmt.Errorf("fetch relay configuration: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Configuration{}, fmt.Errorf("fetch relay configuration: HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(response.Body)
	if err != nil {
		return Configuration{}, fmt.Errorf("read relay configuration: %w", err)
	}
	configuration, err := parseSignedConfiguration(data, preferences...)
	if err != nil {
		return Configuration{}, err
	}
	if epoch := response.Header.Get("proxy-config-epoch"); epoch != "" {
		value, err := strconv.ParseUint(epoch, 10, 16)
		if err != nil {
			return Configuration{}, fmt.Errorf("relay configuration epoch %q: %w", epoch, err)
		}
		configuration.Epoch = uint16(value)
	}
	configuration.FetchedAt = time.Now().UTC()
	configuration.RefreshAt = configuration.FetchedAt.Add(configurationCacheTTL(response.Header))
	configuration.Revision = configurationRevision(configuration)
	return configuration, nil
}

func ParseSignedConfiguration(data []byte, preferences ...Preferences) (Configuration, error) {
	return parseSignedConfiguration(data, preferences...)
}

func LoadConfiguration(path string, preferences ...Preferences) (Configuration, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Configuration{}, fmt.Errorf("read relay configuration: %w", err)
	}
	configuration, err := parseSignedConfiguration(data, preferences...)
	if err != nil {
		return Configuration{}, err
	}
	configuration.FetchedAt = time.Now().UTC()
	return configuration, nil
}

func configurationCacheTTL(headers http.Header) time.Duration {
	for _, directive := range strings.Split(headers.Get("Cache-Control"), ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(directive), "=")
		if ok && strings.EqualFold(key, "max-age") {
			if seconds, err := strconv.ParseInt(strings.Trim(value, "\""), 10, 64); err == nil && seconds > 0 {
				return time.Duration(seconds) * time.Second
			}
		}
	}
	if expires, err := http.ParseTime(headers.Get("Expires")); err == nil && time.Until(expires) > 0 {
		return time.Until(expires)
	}
	return time.Hour
}

func parseSignedConfiguration(data []byte, preferences ...Preferences) (Configuration, error) {
	envelope, err := readProto(data)
	if err != nil {
		return Configuration{}, fmt.Errorf("parse signed relay configuration: %w", err)
	}
	// NSPPrivacyProxySignedConfiguration: 1=configuration, 2=signature,
	// 3=repeated certificates, 4=algorithm (default 1, ECDSA SHA-256).
	raw := protoByte(envelope, 1)
	if len(raw) == 0 {
		return Configuration{}, fmt.Errorf("signed relay configuration has no configuration bytes")
	}
	if err := verifyConfigurationSignature(raw, protoByte(envelope, 2), protoBytes(envelope, 3), protoUint(envelope, 4, 1)); err != nil {
		return Configuration{}, fmt.Errorf("verify relay configuration: %w", err)
	}
	configuration, err := parseConfiguration(raw)
	if err != nil {
		return Configuration{}, err
	}
	var combined Preferences
	for _, preference := range preferences {
		combined.Ingress = append(combined.Ingress, preference.Ingress...)
		combined.Egress = append(combined.Egress, preference.Egress...)
	}
	if err := configuration.SelectPath(combined); err != nil {
		return Configuration{}, err
	}
	configuration.SignatureVerified = true
	configuration.Raw = data
	configuration.Revision = configurationRevision(configuration)
	return configuration, nil
}

func verifyConfigurationSignature(raw, signature []byte, certificates [][]byte, algorithm uint64) error {
	if algorithm != 1 {
		return fmt.Errorf("unsupported configuration signature algorithm %d", algorithm)
	}
	if len(certificates) == 0 || len(signature) == 0 {
		return fmt.Errorf("missing configuration signature or certificate chain")
	}
	chain := make([]*x509.Certificate, 0, len(certificates))
	intermediates := x509.NewCertPool()
	for i, der := range certificates {
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("certificate %d: %w", i, err)
		}
		chain = append(chain, certificate)
		if i > 0 {
			intermediates.AddCert(certificate)
		}
	}
	roots, err := apple.Roots()
	if err != nil {
		return err
	}
	chains, err := chain[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return fmt.Errorf("configuration signing certificate chain: %w", err)
	}
	// These are the exact markers supplied to SecPolicyCreateApplePinned by
	// NSPConfiguration's "networkserviceproxy" policy, not TLS DNS markers.
	leafMarker := asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 12, 22}
	intermediateMarker := asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 2, 17}
	validChain := false
	for _, verified := range chains {
		if len(verified) != 3 || !certificateHasMarker(verified[0], leafMarker) || !certificateHasMarker(verified[1], intermediateMarker) {
			continue
		}
		if !strongConfigurationKeys(verified) {
			continue
		}
		validChain = true
		break
	}
	if !validChain {
		return fmt.Errorf("configuration certificate chain does not match the Apple networkserviceproxy policy")
	}
	publicKey, ok := chain[0].PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("configuration signature requires an ECDSA key")
	}
	digest := sha256.Sum256(raw)
	if !ecdsa.VerifyASN1(publicKey, digest[:], signature) {
		return fmt.Errorf("configuration ECDSA SHA-256 signature mismatch")
	}
	return nil
}

func certificateHasMarker(certificate *x509.Certificate, marker asn1.ObjectIdentifier) bool {
	for _, extension := range certificate.Extensions {
		if extension.Id.Equal(marker) {
			return true
		}
	}
	return false
}

func strongConfigurationKeys(chain []*x509.Certificate) bool {
	for _, certificate := range chain {
		switch key := certificate.PublicKey.(type) {
		case *ecdsa.PublicKey:
			if key.Curve.Params().BitSize < 256 {
				return false
			}
		case *rsa.PublicKey:
			if key.N.BitLen() < 2048 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func parseConfiguration(raw []byte) (Configuration, error) {
	fields, err := readProto(raw)
	if err != nil {
		return Configuration{}, fmt.Errorf("parse relay configuration: %w", err)
	}
	if version := protoUint(fields, 1, 0); version != 1 {
		return Configuration{}, fmt.Errorf("unsupported relay configuration version %d", version)
	}
	if protoUint(fields, 2, 0) == 0 {
		return Configuration{}, fmt.Errorf("remote relay configuration is disabled")
	}
	auth, err := readProto(protoByte(fields, 5))
	if err != nil {
		return Configuration{}, fmt.Errorf("parse relay authentication configuration: %w", err)
	}
	configuration := Configuration{AuthURL: string(protoByte(auth, 2)), AuthType: int(protoUint(auth, 1, 0))}
	if configuration.AuthURL == "" {
		return Configuration{}, fmt.Errorf("relay configuration has no token issuer URL")
	}
	for index, rawProxy := range protoBytes(fields, 7) {
		proxy, err := parseConfigurationProxy(rawProxy)
		if err != nil {
			return Configuration{}, fmt.Errorf("parse relay proxy %d: %w", index, err)
		}
		proxy.Index = index
		configuration.Proxies = append(configuration.Proxies, proxy)
	}
	addPaths := func(rawPaths [][]byte, fallback bool) error {
		for _, rawPath := range rawPaths {
			fields, err := readProto(rawPath)
			if err != nil {
				return fmt.Errorf("parse relay path: %w", err)
			}
			indexes, err := protoRepeatedUint(fields, 2)
			if err != nil {
				return fmt.Errorf("parse relay path indexes: %w", err)
			}
			// Only use a complete, published two-hop edge. Never manufacture a
			// combination from independently preferred ingress and egress nodes.
			if len(indexes) != 2 || indexes[0] >= uint64(len(configuration.Proxies)) || indexes[1] >= uint64(len(configuration.Proxies)) {
				continue
			}
			pair := []int{int(indexes[0]), int(indexes[1])}
			weight := uint32(protoUint(fields, 1, 0))
			if i := slices.IndexFunc(configuration.Paths, func(existing Path) bool { return slices.Equal(existing.Indexes, pair) }); i >= 0 {
				if fallback {
					configuration.Paths[i].FallbackWeight = weight
					if configuration.Paths[i].Weight == 0 {
						configuration.Paths[i].Weight = weight
					}
				}
				continue
			}
			ingress, egress := configuration.Proxies[pair[0]], configuration.Proxies[pair[1]]
			if !fallbackProxyUsable(ingress) || !fallbackProxyUsable(egress) {
				continue
			}
			path := Path{Indexes: pair, Weight: weight, Ingress: ingress, Egress: egress}
			if fallback {
				path.FallbackWeight = weight
			}
			configuration.Paths = append(configuration.Paths, path)
		}
		return nil
	}
	if err := addPaths(protoBytes(fields, 8), false); err != nil {
		return Configuration{}, err
	}
	if err := addPaths(protoBytes(fields, 11), true); err != nil {
		return Configuration{}, err
	}
	return configuration, nil
}

func fallbackProxyUsable(proxy Proxy) bool {
	return proxy.Server != "" && len(proxy.PublicKeys) > 0 && len(proxy.TokenKey) > 0
}

// SelectPath applies ordered preferences to two-hop paths in the configuration.
// Positive-weight paths win by default and break ties when a preference matches
// multiple paths; zero-weight paths are selected when explicitly matched and no
// positive-weight path matches at the same preference rank.
func (configuration *Configuration) SelectPath(preferences Preferences) error {
	if len(configuration.Paths) == 0 {
		return fmt.Errorf("relay configuration has no usable two-hop fallback path")
	}
	ingressPreferences := expandPreferences(preferences.Ingress)
	egressPreferences := expandPreferences(preferences.Egress)
	hasPositiveMatch := func(ai, ae int) bool {
		return slices.ContainsFunc(configuration.Paths, func(path Path) bool {
			if path.Weight == 0 {
				return false
			}
			pi, pim := preferenceRank(path.Ingress, ingressPreferences)
			pe, pem := preferenceRank(path.Egress, egressPreferences)
			return pim && pem && pi == ai && pe == ae
		})
	}
	eligible := func(path Path, ai, ae int, aim, aem bool) bool {
		if path.Weight > 0 {
			return true
		}
		return aim && aem && !hasPositiveMatch(ai, ae)
	}
	slices.SortStableFunc(configuration.Paths, func(a, b Path) int {
		ai, aim := preferenceRank(a.Ingress, ingressPreferences)
		ae, aem := preferenceRank(a.Egress, egressPreferences)
		bi, bim := preferenceRank(b.Ingress, ingressPreferences)
		be, bem := preferenceRank(b.Egress, egressPreferences)
		aok := eligible(a, ai, ae, aim, aem)
		bok := eligible(b, bi, be, bim, bem)
		if aok != bok {
			if aok {
				return -1
			}
			return 1
		}
		if (aim && aem) != (bim && bem) {
			if aim && aem {
				return -1
			}
			return 1
		}
		if order := cmp.Compare(ai, bi); order != 0 {
			return order
		}
		if order := cmp.Compare(ae, be); order != 0 {
			return order
		}
		if order := cmp.Compare(b.Weight, a.Weight); order != 0 {
			return order
		}
		return cmp.Compare(b.FallbackWeight, a.FallbackWeight)
	})
	selected := configuration.Paths[0]
	_, ingressMatch := preferenceRank(selected.Ingress, ingressPreferences)
	_, egressMatch := preferenceRank(selected.Egress, egressPreferences)
	if selected.Weight == 0 && (!ingressMatch || !egressMatch || len(ingressPreferences)+len(egressPreferences) == 0) {
		return fmt.Errorf("relay configuration has no positive-weight two-hop fallback path")
	}
	configuration.SelectedPath = selected
	configuration.Ingress, configuration.Egress = selected.Ingress, selected.Egress
	configuration.PreferenceFallback = !ingressMatch || !egressMatch
	configuration.Revision = configurationRevision(*configuration)
	return nil
}

func expandPreferences(values []string) []string {
	var expanded []string
	for _, value := range values {
		for _, entry := range strings.Split(value, ",") {
			if entry = strings.TrimSpace(entry); entry != "" {
				expanded = append(expanded, entry)
			}
		}
	}
	return expanded
}

func preferenceRank(proxy Proxy, preferences []string) (int, bool) {
	if len(preferences) == 0 {
		return 0, true
	}
	vendor := strings.ToLower(proxy.Name)
	for rank, preference := range preferences {
		if strings.EqualFold(preference, proxy.ServerName) || strings.EqualFold(preference, proxy.Server) {
			return rank, true
		}
		name := strings.ToLower(preference)
		if vendor == name || strings.HasPrefix(vendor, name+"_") {
			return rank, true
		}
	}
	return len(preferences), false
}

func parseConfigurationProxy(raw []byte) (Proxy, error) {
	fields, err := readProto(raw)
	if err != nil {
		return Proxy{}, err
	}
	proxy := Proxy{
		Hop:        int(protoUint(fields, 1, 0)),
		Name:       string(protoByte(fields, 6)),
		ProxyURL:   string(protoByte(fields, 2)),
		PublicKeys: protoBytes(fields, 3),
		TokenKey:   protoByte(fields, 4),
		Challenge:  protoByte(fields, 13),
		Algorithm:  int(protoUint(fields, 16, 0)),
	}
	rawEndpoint := string(protoByte(fields, 7))
	if rawEndpoint == "" {
		rawEndpoint = proxy.ProxyURL
	}
	if endpoint, err := url.Parse(rawEndpoint); err == nil && endpoint.Hostname() != "" {
		port := endpoint.Port()
		if port == "" {
			port = "443"
		}
		proxy.ServerName = endpoint.Hostname()
		proxy.Server = net.JoinHostPort(proxy.ServerName, port)
	}
	proxy.ID = proxyIdentity(proxy)
	proxy.encodedPublicKeys = make([]string, len(proxy.PublicKeys))
	for i, key := range proxy.PublicKeys {
		proxy.encodedPublicKeys[i] = base64.StdEncoding.EncodeToString(key)
	}
	return proxy, nil
}

func metadataHop(proxy Proxy) relay.Hop {
	return relay.Hop{ID: proxy.ID, Name: proxy.Name, Server: proxy.Server, ServerName: proxy.ServerName, PublicKeys: proxy.encodedPublicKeys, Algorithm: proxy.Algorithm}
}

// Length-prefixed fields keep identities unambiguous. Discovery Index and Hop
// are excluded so reordering the signed proxy list preserves usable pools.
func proxyIdentity(proxy Proxy) string {
	data := []byte("iprd:proxy:v1")
	for _, value := range []string{proxy.Name, proxy.Server, proxy.ServerName, proxy.ProxyURL} {
		data = appendIdentityField(data, []byte(value))
	}
	data = binary.BigEndian.AppendUint64(data, uint64(len(proxy.PublicKeys)))
	for _, key := range proxy.PublicKeys {
		data = appendIdentityField(data, key)
	}
	data = appendIdentityField(data, proxy.TokenKey)
	data = appendIdentityField(data, proxy.Challenge)
	data = binary.BigEndian.AppendUint64(data, uint64(proxy.Algorithm))
	return identityDigest(data)
}

func configurationRevision(config Configuration) string {
	return routeIdentity(config.Epoch, config.Ingress.ID, config.Egress.ID)
}

func routeIdentity(epoch uint16, ingressID, egressID string) string {
	data := binary.BigEndian.AppendUint16([]byte("iprd:route:v1"), epoch)
	data = appendIdentityField(data, []byte(ingressID))
	data = appendIdentityField(data, []byte(egressID))
	return identityDigest(data)
}

func appendIdentityField(data, field []byte) []byte {
	data = binary.BigEndian.AppendUint64(data, uint64(len(field)))
	return append(data, field...)
}

func identityDigest(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
