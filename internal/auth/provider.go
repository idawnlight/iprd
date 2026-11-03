package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"iprd/internal/apple"
	"iprd/internal/state"

	"github.com/coder/websocket"
	"howett.net/plist"
)

const defaultAnisetteServer = "https://new.ani.sidestore.io"
const grandSlamLookup = "https://gsa.apple.com/grandslam/GsService2/lookup"

type providerIdentity struct {
	Identifier string `json:"identifier"`
	DeviceID   string `json:"device_id"`
	LocalUser  string `json:"local_user"`
}

type providerClientInfo struct {
	ClientInfo string `json:"client_info"`
	UserAgent  string `json:"user_agent"`
}

// Provider keeps a per-client v3 ADI identity. Apple Account credentials are
// never part of the v3 provisioning or get_headers requests.
type Provider struct {
	stateDir string
	server   string
	identity providerIdentity
	info     providerClientInfo
	blob     []byte
	client   *http.Client
}

// NewHTTPClient trusts the system and Apple roots and leaves redirects to callers.
func NewHTTPClient() (*http.Client, error) {
	roots, err := apple.SystemRoots()
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: roots}
	return &http.Client{
		Transport: transport,
		Timeout:   60 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

func OpenProvider(ctx context.Context, stateDir, serverURL string) (*Provider, error) {
	if serverURL == "" {
		serverURL = defaultAnisetteServer
	}
	client, err := NewHTTPClient()
	if err != nil {
		return nil, err
	}
	p := &Provider{
		stateDir: stateDir,
		server:   strings.TrimRight(serverURL, "/"),
		client:   client,
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}
	identityPath := filepath.Join(stateDir, "identity.json")
	if err := readProviderJSON(identityPath, &p.identity); errors.Is(err, os.ErrNotExist) {
		var identifier [16]byte
		if _, err := rand.Read(identifier[:]); err != nil {
			return nil, err
		}
		identifier[6] = identifier[6]&0x0f | 0x40
		identifier[8] = identifier[8]&0x3f | 0x80
		digest := sha256.Sum256(identifier[:])
		uuid := strings.ToUpper(hex.EncodeToString(identifier[:]))
		p.identity = providerIdentity{
			Identifier: base64.StdEncoding.EncodeToString(identifier[:]),
			DeviceID:   uuid[:8] + "-" + uuid[8:12] + "-" + uuid[12:16] + "-" + uuid[16:20] + "-" + uuid[20:],
			LocalUser:  strings.ToUpper(hex.EncodeToString(digest[:])),
		}
		if err := writeProviderJSON(identityPath, p.identity); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, fmt.Errorf("load Anisette identity: %w", err)
	}
	infoPath := filepath.Join(stateDir, "client-info.json")
	if err := readProviderJSON(infoPath, &p.info); errors.Is(err, os.ErrNotExist) {
		raw, err := p.request(ctx, "Anisette client info", http.MethodGet, p.server+"/v3/client_info", nil, nil)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &p.info); err != nil {
			return nil, fmt.Errorf("parse Anisette client info: %w", err)
		}
		if err := writeProviderJSON(infoPath, p.info); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, fmt.Errorf("load Anisette client info: %w", err)
	}
	p.blob, err = os.ReadFile(filepath.Join(stateDir, "adi.pb"))
	if errors.Is(err, os.ErrNotExist) {
		if err := p.provision(ctx); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, fmt.Errorf("load Anisette provisioning: %w", err)
	}
	return p, nil
}

// HTTPClient supplies the same Apple CA trust for GrandSlam and MobileMe.
func (p *Provider) HTTPClient() *http.Client { return p.client }

func (p *Provider) ClientInfo() string { return p.info.ClientInfo }
func (p *Provider) UserAgent() string  { return p.info.UserAgent }

func (p *Provider) identityHeaders() map[string]string {
	return map[string]string{
		"X-MMe-Client-Info":     p.info.ClientInfo,
		"User-Agent":            p.info.UserAgent,
		"X-Mme-Device-Id":       p.identity.DeviceID,
		"X-Apple-I-MD-LU":       p.identity.LocalUser,
		"X-Apple-I-Client-Time": time.Now().UTC().Format(time.RFC3339),
		"X-Apple-I-TimeZone":    "UTC",
		"X-Apple-Locale":        "en_US",
		"X-Apple-I-SRL-NO":      "0",
	}
}

// Headers asks the v3 provider for a fresh MID/OTP pair using this identity's
// adi.pb and combines it with the local device and client-profile fields.
func (p *Provider) Headers(ctx context.Context) (map[string]string, error) {
	body, err := json.Marshal(map[string]string{
		"identifier": p.identity.Identifier,
		"adi_pb":     base64.StdEncoding.EncodeToString(p.blob),
	})
	if err != nil {
		return nil, err
	}
	raw, err := p.request(ctx, "Anisette get_headers", http.MethodPost, p.server+"/v3/get_headers", map[string]string{"Content-Type": "application/json"}, body)
	if err != nil {
		return nil, err
	}
	var response map[string]string
	if err := json.Unmarshal(raw, &response); err != nil {
		return nil, fmt.Errorf("parse Anisette headers: %w", err)
	}
	if result := response["result"]; result != "Headers" {
		return nil, fmt.Errorf("Anisette get_headers returned result %q", result)
	}
	headers := p.identityHeaders()
	delete(response, "result")
	maps.Copy(headers, response)
	return headers, nil
}

func (p *Provider) request(ctx context.Context, stage, method, endpoint string, headers map[string]string, body []byte) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := p.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", stage, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", stage, response.StatusCode)
	}
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("%s response: %w", stage, err)
	}
	return raw, nil
}

func (p *Provider) appleHeaders() map[string]string {
	headers := p.identityHeaders()
	headers["Content-Type"] = "text/x-xml-plist"
	headers["Accept"] = "*/*"
	return headers
}

func (p *Provider) provision(ctx context.Context) error {
	raw, err := p.request(ctx, "Apple provisioning lookup", http.MethodGet, grandSlamLookup, p.appleHeaders(), nil)
	if err != nil {
		return err
	}
	var lookup struct {
		URLs map[string]string `plist:"urls"`
	}
	if _, err := plist.Unmarshal(raw, &lookup); err != nil {
		return fmt.Errorf("parse Apple provisioning lookup: %w", err)
	}
	wsURL, err := url.Parse(p.server + "/v3/provisioning_session")
	if err != nil {
		return err
	}
	if wsURL.Scheme == "https" {
		wsURL.Scheme = "wss"
	} else {
		wsURL.Scheme = "ws"
	}
	ws, _, err := websocket.Dial(ctx, wsURL.String(), &websocket.DialOptions{HTTPClient: p.client})
	if err != nil {
		return fmt.Errorf("Anisette provisioning WebSocket: %w", err)
	}
	defer ws.CloseNow()
	for {
		_, message, err := ws.Read(ctx)
		if err != nil {
			return fmt.Errorf("Anisette provisioning read: %w", err)
		}
		var step struct {
			Result string `json:"result"`
			CPIM   string `json:"cpim"`
			ADIPB  string `json:"adi_pb"`
		}
		if err := json.Unmarshal(message, &step); err != nil {
			return fmt.Errorf("parse Anisette provisioning step: %w", err)
		}
		var reply map[string]any
		switch step.Result {
		case "GiveIdentifier":
			reply = map[string]any{"identifier": p.identity.Identifier}
		case "GiveStartProvisioningData":
			response, err := p.appleProvisioning(ctx, lookup.URLs["midStartProvisioning"], map[string]any{})
			if err != nil {
				return fmt.Errorf("Apple start provisioning: %w", err)
			}
			reply = map[string]any{"spim": response["spim"]}
		case "GiveEndProvisioningData":
			response, err := p.appleProvisioning(ctx, lookup.URLs["midFinishProvisioning"], map[string]any{"cpim": step.CPIM})
			if err != nil {
				return fmt.Errorf("Apple finish provisioning: %w", err)
			}
			reply = map[string]any{"ptm": response["ptm"], "tk": response["tk"]}
		case "ProvisioningSuccess":
			p.blob, err = base64.StdEncoding.DecodeString(step.ADIPB)
			if err != nil {
				return fmt.Errorf("decode Anisette adi.pb: %w", err)
			}
			return state.WritePrivate(filepath.Join(p.stateDir, "adi.pb"), p.blob)
		default:
			return fmt.Errorf("Anisette provisioning returned step %q", step.Result)
		}
		raw, err := json.Marshal(reply)
		if err != nil {
			return err
		}
		if err := ws.Write(ctx, websocket.MessageText, raw); err != nil {
			return fmt.Errorf("Anisette provisioning reply: %w", err)
		}
	}
}

func (p *Provider) appleProvisioning(ctx context.Context, endpoint string, request map[string]any) (map[string]any, error) {
	body, err := plist.Marshal(map[string]any{"Header": map[string]any{}, "Request": request}, plist.XMLFormat)
	if err != nil {
		return nil, err
	}
	raw, err := p.request(ctx, "Apple provisioning", http.MethodPost, endpoint, p.appleHeaders(), body)
	if err != nil {
		return nil, err
	}
	var result struct {
		Response map[string]any `plist:"Response"`
	}
	if _, err := plist.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("parse Apple provisioning response: %w", err)
	}
	return result.Response, nil
}

func readProviderJSON(path string, value any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, value)
}

func writeProviderJSON(path string, value any) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return state.WritePrivate(path, append(raw, '\n'))
}
