package control

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"time"

	"iprd/internal/auth"
	"iprd/internal/progress"
	"iprd/internal/relay"
	"strconv"
	"strings"
)

func issueTokens(ctx context.Context, client *http.Client, provider *auth.Provider, configuration Configuration, proxy Proxy, subscriber, tier, clientInfo string, count int, logf func(string, ...any), observer progress.Observer) ([]relay.Credential, error) {

	if count <= 0 {
		return nil, fmt.Errorf("invalid token batch size %d", count)
	}
	privateToken := len(proxy.Challenge) > 0
	if privateToken && (len(proxy.Challenge) < 2 || binary.BigEndian.Uint16(proxy.Challenge[:2]) != tokenTypeBlindRSA) {
		return nil, fmt.Errorf("%s: unsupported PrivateToken challenge type", proxy.Name)
	}
	info := issueBytes(nil, tokenInfoProxyURL, []byte(proxy.ProxyURL))
	keyHash := sha256.Sum256(proxy.TokenKey)
	info = issueBytes(info, tokenInfoKeyID, keyHash[:])
	states := make([]*BlindState, 0, count)
	for range count {
		var content []byte
		if privateToken {
			nonce := make([]byte, 32)
			if _, err := rand.Read(nonce); err != nil {
				return nil, err
			}
			challengeHash := sha256.Sum256(proxy.Challenge)
			content = binary.BigEndian.AppendUint16(nil, tokenTypeBlindRSA)
			content = append(content, nonce...)
			content = append(content, challengeHash[:]...)
			content = append(content, keyHash[:]...)
		}
		blind, err := NewBlind(proxy.TokenKey, content)
		if err != nil {
			return nil, fmt.Errorf("%s blind token: %w", proxy.Name, err)
		}
		states = append(states, blind)
		if privateToken {
			tokenRequest := binary.BigEndian.AppendUint16(nil, tokenTypeBlindRSA)
			tokenRequest = append(tokenRequest, keyHash[len(keyHash)-1])
			tokenRequest = append(tokenRequest, blind.Blinded...)
			info = issueBytes(info, tokenInfoPrivateRequests, tokenRequest)
		} else {
			info = issueBytes(info, tokenInfoLegacyRequests, blind.Blinded)
		}
	}
	info = issueBytes(info, tokenInfoVendor, []byte(proxy.Name))
	// The dynamic authType=3 policy offers BAA or Anisette. This portable
	// implementation selects the Anisette query type, whose wire value is 2.
	query := issueUint(nil, activationAuthType, authTypeAnisette)
	query = issueBytes(query, activationTokenInfo, info)
	observer.Emit(progress.Event{Stage: "provider", Status: progress.Running, Detail: "request fresh MID/OTP headers"})
	headers, err := provider.Headers(ctx)
	if err != nil {
		if ctx.Err() == nil {
			observer.Emit(progress.Event{Stage: "provider", Status: progress.Retry, Detail: "fresh MID/OTP headers unavailable", Err: err})
		}
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	observer.Emit(progress.Event{Stage: "provider", Status: progress.OK, Detail: "fresh MID/OTP headers available"})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, configuration.AuthURL, bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	request.Header.Set("X-Mask-Client-Info", clientInfo)
	request.Header.Set("X-Mask-User-Tier", tier)
	request.Header.Set("X-Mask-Subscription-Token", subscriber)
	request.Header.Set("Retry-Attempt", "0")
	logf("%s: issuing %d anonymous tokens with Anisette", proxy.Name, count)
	observer.Emit(progress.Event{Stage: "tokens", Hop: proxy.Name, Status: progress.Running, Detail: fmt.Sprintf("request %d anonymous tokens with Anisette", count)})
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%s token issuance: %w", proxy.Name, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	logf("%s: token issuer HTTP %d, %d bytes", proxy.Name, response.StatusCode, len(body))
	observer.Emit(progress.Event{Stage: "tokens", Hop: proxy.Name, Status: progress.Running, Detail: fmt.Sprintf("issuer HTTP %d; %d response bytes", response.StatusCode, len(body))})
	if response.StatusCode != http.StatusOK {
		return nil, &IssuanceError{HopName: proxy.Name, StatusCode: response.StatusCode, RetryAfter: retryAfter(response.Header.Get("Retry-After"))}
	}
	signatures, expiry, err := parseIssuanceResponse(body)
	if err != nil {
		return nil, fmt.Errorf("%s token response: %w", proxy.Name, err)
	}

	if len(signatures) == 0 || len(signatures) > len(states) {
		return nil, fmt.Errorf("%s token response: %d signatures for %d requests", proxy.Name, len(signatures), len(states))
	}
	expiresAt := time.Now().Add(24 * time.Hour).UTC() // Native cache fallback when the issuer omits expiry.
	if expiry != 0 {
		expiresAt = time.UnixMilli(int64(expiry)).UTC()
	}
	credentials := make([]relay.Credential, 0, len(signatures))
	for i, blindSignature := range signatures {
		blind := states[i]
		signature, err := blind.Finalize(blindSignature)
		if err != nil {
			return nil, fmt.Errorf("%s unblind token: %w", proxy.Name, err)
		}
		scheme := "PrivateToken token="
		var token []byte
		if privateToken {
			token = append(token, blind.Content...)
		} else {
			scheme = "PrivacyToken token="
			token = append(token, legacyPrivacyTokenVersion)
			token = append(token, blind.KeyID...)
			token = append(token, blind.Content...)
		}
		token = append(token, signature...)
		credentials = append(credentials, relay.Credential{Authorization: scheme + base64.URLEncoding.EncodeToString(token), ExpiresAt: expiresAt})
	}
	return credentials, nil
}

// Query auth types and token formats are independent wire enums. The legacy
// PrivacyToken byte is a version, not the RFC PrivateToken token_type.
const (
	tokenTypeBlindRSA         uint16 = 0x0002
	legacyPrivacyTokenVersion byte   = 1
	authTypeAnisette          uint64 = 2
	activationAuthType        uint64 = 1
	activationTokenInfo       uint64 = 3
	tokenInfoProxyURL         uint64 = 1
	tokenInfoKeyID            uint64 = 2
	tokenInfoLegacyRequests   uint64 = 3
	tokenInfoVendor           uint64 = 4
	tokenInfoPrivateRequests  uint64 = 5
)

type IssuanceError struct {
	HopName    string
	StatusCode int
	RetryAfter time.Duration
}

func (e *IssuanceError) Error() string {
	return fmt.Sprintf("%s token issuer: HTTP %d", e.HopName, e.StatusCode)
}
func retryAfter(value string) time.Duration {
	if seconds, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	if at, err := http.ParseTime(value); err == nil && time.Until(at) > 0 {
		return time.Until(at)
	}
	return 0
}

func issueBytes(dst []byte, field uint64, data []byte) []byte {
	dst = binary.AppendUvarint(dst, field<<3|2)
	dst = binary.AppendUvarint(dst, uint64(len(data)))
	return append(dst, data...)
}

func issueUint(dst []byte, field, value uint64) []byte {
	dst = binary.AppendUvarint(dst, field<<3)
	return binary.AppendUvarint(dst, value)
}

func parseIssuanceResponse(data []byte) (signatures [][]byte, expiry uint64, err error) {
	fields, err := readProto(data)
	if err != nil {
		return nil, 0, err
	}
	return protoBytes(fields, 2), protoUint(fields, 1, 0), nil
}
