package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"iprd/internal/state"
)

const subscriberFeatureKey = "networking.privacy.subscriber"

// Account is the normalized MobileMe credential used for CSF authentication.
type Account struct {
	DSID              string `json:"dsid"`
	AuthToken         string `json:"authToken"`
	URLTemplate       string `json:"urlTemplate"`
	URLTemplateSource string `json:"urlTemplateSource"`
	DeviceID          string `json:"deviceId"`
	FeatureKey        string `json:"featureKey"`
	CSFClientInfo     string `json:"csfClientInfo"`
}

// LoadAccount reads a normalized account file produced by auth.
func LoadAccount(path string) (Account, error) {
	var account Account
	raw, err := os.ReadFile(path)
	if err != nil {
		return account, fmt.Errorf("read CSF account: %w", err)
	}
	if err := json.Unmarshal(raw, &account); err != nil {
		return account, fmt.Errorf("parse CSF account: %w", err)
	}
	if account.FeatureKey == "" {
		account.FeatureKey = subscriberFeatureKey
	}
	return account, account.validate()
}

func (a Account) validate() error {
	if a.DSID == "" || a.AuthToken == "" {
		return errors.New("CSF account lacks dsid or authToken")
	}
	if a.URLTemplate == "" || a.DeviceID == "" || a.CSFClientInfo == "" {
		return errors.New("CSF account lacks urlTemplate, deviceId or csfClientInfo")
	}
	return nil
}

// Subscription contains the account-linked access token and its refresh times.
type Subscription struct {
	AccessToken string
	Tier        string
	CacheTill   time.Time
	ExpiresAt   time.Time
	Raw         []byte
	CanUse      bool
	statusCode  int
}

// FetchSubscription performs the CSF exchange without writing files or logging.
// On an HTTP or parsing error, Raw retains the response for an explicit caller
// to save. A nil client uses the standard Apple-aware HTTP client.
func FetchSubscription(ctx context.Context, client *http.Client, account Account) (Subscription, error) {
	if err := account.validate(); err != nil {
		return Subscription{}, err
	}
	if account.FeatureKey == "" {
		account.FeatureKey = subscriberFeatureKey
	}
	endpoint := strings.NewReplacer(
		"{udId}", url.PathEscape(account.DeviceID),
		"{featureKey}", url.PathEscape(account.FeatureKey),
	).Replace(account.URLTemplate)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Subscription{}, fmt.Errorf("build CSF request: %w", err)
	}
	request.SetBasicAuth(account.DSID, account.AuthToken)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept-Language", "en-US")
	request.Header.Set("X-MMe-Client-Info", account.CSFClientInfo)
	request.Header.Set("X-MMe-Timezone", "UTC")
	request.Header.Set("X-Mme-Device-Id", account.DeviceID)
	request.Header.Set("X-Apple-DSID", account.DSID)
	if client == nil {
		client, err = NewHTTPClient()
		if err != nil {
			return Subscription{}, err
		}
		defer client.CloseIdleConnections()
	}
	response, err := client.Do(request)
	if err != nil {
		var urlError *url.Error
		if errors.As(err, &urlError) {
			err = urlError.Err
		}
		return Subscription{}, fmt.Errorf("CSF exchange: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return Subscription{}, fmt.Errorf("read CSF response: %w", err)
	}
	if response.StatusCode == http.StatusNoContent {
		return Subscription{Raw: body, statusCode: response.StatusCode}, nil
	}
	subscription, parseErr := parseSubscription(body, account.FeatureKey)
	subscription.statusCode = response.StatusCode
	if response.StatusCode != http.StatusOK {
		return subscription, fmt.Errorf("CSF exchange: HTTP %d", response.StatusCode)
	}
	return subscription, parseErr
}

// ParseSubscription reads a CSF response or a normalized subscriber feature.
func ParseSubscription(raw []byte) (Subscription, error) {
	return parseSubscription(raw, subscriberFeatureKey)
}

func parseSubscription(raw []byte, featureKey string) (Subscription, error) {
	subscription := Subscription{Raw: bytes.Clone(raw)}
	var response any
	if err := json.Unmarshal(raw, &response); err != nil {
		return subscription, fmt.Errorf("parse CSF response: %w", err)
	}
	feature := csfFindFeature(response, featureKey)
	if feature == nil {
		if object, ok := response.(map[string]any); ok && object["featureKey"] == nil {
			feature = object
		}
	}
	if feature == nil {
		return subscription, errors.New("CSF response has no subscriber feature")
	}
	subscription.CanUse, _ = feature["canUse"].(bool)
	subscription.AccessToken, _ = feature["accessToken"].(string)
	subscription.Tier, _ = feature["tier"].(string)
	if subscription.Tier == "" {
		subscription.Tier = "FREE"
		if subscription.CanUse {
			subscription.Tier = "SUBSCRIBER_UNLIMITED"
			if feature["limit"] != nil {
				subscription.Tier = "SUBSCRIBER"
			}
		}
	}
	if cacheTill, _ := feature["cacheTill"].(string); cacheTill != "" {
		var err error
		subscription.CacheTill, err = time.Parse(time.RFC3339Nano, cacheTill)
		if err != nil {
			return subscription, fmt.Errorf("parse CSF cacheTill: %w", err)
		}
	}
	subscription.ExpiresAt = subscriptionTokenExpiry(subscription.AccessToken)
	return subscription, nil
}

// The CSF token is a JWT. Its exp claim supplies scheduling metadata; the token
// remains opaque to the issuer request, which uses the original string.
func subscriptionTokenExpiry(token string) time.Time {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return time.Time{}
	}
	var claims struct {
		ExpiresAt int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.ExpiresAt == 0 {
		return time.Time{}
	}
	return time.Unix(claims.ExpiresAt, 0).UTC()
}

// ExchangeCSF is the CLI wrapper: save the raw response and report metadata.
func ExchangeCSF(ctx context.Context, accountPath, outputPath string) error {
	account, err := LoadAccount(accountPath)
	if err != nil {
		return err
	}
	subscription, fetchErr := FetchSubscription(ctx, nil, account)
	if subscription.Raw == nil {
		return fetchErr
	}
	if err := state.WritePrivate(outputPath, subscription.Raw); err != nil {
		return errors.Join(fetchErr, fmt.Errorf("save CSF response: %w", err))
	}
	metadata := map[string]any{
		"status": subscription.statusCode, "responseBytes": len(subscription.Raw),
		"responseFile": outputPath, "featureKey": account.FeatureKey,
		"canUse": subscription.CanUse, "tokenPresent": subscription.AccessToken != "",
		"cacheTill": nil, "expiresAt": nil,
	}
	if !subscription.CacheTill.IsZero() {
		metadata["cacheTill"] = subscription.CacheTill
	}
	if !subscription.ExpiresAt.IsZero() {
		metadata["expiresAt"] = subscription.ExpiresAt
	}
	return errors.Join(fetchErr, json.NewEncoder(os.Stderr).Encode(metadata))
}

func csfFindFeature(value any, featureKey string) map[string]any {
	switch value := value.(type) {
	case map[string]any:
		if value["featureKey"] == featureKey {
			return value
		}
		for _, child := range value {
			if feature := csfFindFeature(child, featureKey); feature != nil {
				return feature
			}
		}
	case []any:
		for _, child := range value {
			if feature := csfFindFeature(child, featureKey); feature != nil {
				return feature
			}
		}
	}
	return nil
}
