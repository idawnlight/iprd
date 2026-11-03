package auth

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"iprd/internal/state"

	"golang.org/x/term"
	"howett.net/plist"
)

type Options struct {
	StateDir, ServerURL, Output, AccountRequest, DebugDir string
	InitOnly                                              bool
}

type loginSession struct {
	provider *Provider
	client   *http.Client
	bag      loginURLs
	debugDir string
}

type loginOutcome struct {
	status int64
	action string
	data   *loginSPD
}

type loginURLs struct {
	Service      string `plist:"gsService"`
	ValidateCode string `plist:"validateCode"`
}

type loginRequest struct {
	ClientPublic []byte         `plist:"A2k,omitempty"`
	ClientData   map[string]any `plist:"cpd"`
	Operation    string         `plist:"o"`
	Protocols    []string       `plist:"ps,omitempty"`
	Username     string         `plist:"u"`
	ClientProof  []byte         `plist:"M1,omitempty"`
	Cookie       *string        `plist:"c,omitempty"`
}

type loginAppleStatus struct {
	Code    *int64 `plist:"ec"`
	Subcode *int64 `plist:"sec"`
	HSC     *int64 `plist:"hsc"`
	Action  string `plist:"au"`
}

type loginResponse struct {
	Status       *loginAppleStatus `plist:"Status"`
	ServerPublic []byte            `plist:"B"`
	Iterations   int64             `plist:"i"`
	Salt         []byte            `plist:"s"`
	Protocol     string            `plist:"sp"`
	Cookie       *string           `plist:"c"`
	ServerProof  []byte            `plist:"M2"`
	EncryptedSPD []byte            `plist:"spd"`
}

type loginSPD struct {
	ADSID     string `plist:"adsid"`
	IDMSToken string `plist:"GsIdmsToken"`
	Tokens    struct {
		PET struct {
			Token string `plist:"token"`
		} `plist:"com.apple.gs.idms.pet"`
	} `plist:"t"`
}

type loginQuota struct {
	URLTemplate string `plist:"acseGatewayV3DeviceAndAccountFeature"`
}

type loginQuotaBag struct {
	Quota loginQuota `plist:"com.apple.Dataclass.Quota"`
}

type loginMobileMeService struct {
	AppleAccountInfo struct {
		DSID loginDSID `plist:"dsPrsID"`
	} `plist:"appleAccountInfo"`
	DSID   loginDSID `plist:"dsid"`
	Tokens struct {
		AuthToken string `plist:"mmeAuthToken"`
	} `plist:"tokens"`
	AccountInfo loginQuotaBag `plist:"mobilemeAccountInfo"`
	MobileMe    loginQuotaBag `plist:"com.apple.mobileme"`
	Quota       loginQuota    `plist:"com.apple.Dataclass.Quota"`
}

type loginMobileMeResponse struct {
	LocalizedError *string   `plist:"localizedError"`
	Status         *int64    `plist:"status"`
	DSID           loginDSID `plist:"dsid"`
	Delegates      struct {
		MobileMe struct {
			Status  *int64               `plist:"status"`
			Service loginMobileMeService `plist:"service-data"`
		} `plist:"com.apple.mobileme"`
	} `plist:"delegates"`
}

type loginMetadata struct {
	Stage               string `json:"stage"`
	Status              int    `json:"status"`
	ResponseBytes       int    `json:"responseBytes"`
	AppleCode           *int64 `json:"appleCode"`
	HSC                 *int64 `json:"hsc,omitempty"`
	SRPChallengePresent *bool  `json:"srpChallengePresent,omitempty"`
}

const loginBagURL = "https://gsa.apple.com/grandslam/GsService2/lookup"
const loginMobileMeURL = "https://setup.icloud.com/setup/iosbuddy/loginDelegates"
const loginMobileMeUA = "com.apple.iCloudHelper/282 CFNetwork/1408.0.4 Darwin/22.5.0"
const loginCSFURL = "https://acsegateway.icloud.com:443/v3/devices/{udId}/subscriptions/features/{featureKey}"

// Run obtains the MobileMe credential used by the CSF subscriber exchange.
// InitOnly stops after requesting an SRP challenge and does not ask for a password.
func Run(ctx context.Context, options Options) error {
	if options.Output == "" {
		options.Output = "runtime/account.json"
	}
	provider, err := OpenProvider(ctx, options.StateDir, options.ServerURL)
	if err != nil {
		return err
	}
	s := &loginSession{provider: provider, client: provider.HTTPClient(), debugDir: options.DebugDir}
	username, err := loginAccount(options.AccountRequest)
	if err != nil {
		return err
	}
	if err := s.lookup(ctx); err != nil {
		return err
	}
	var password []byte
	if !options.InitOnly {
		password, err = loginReadSecret("Password: ")
		if err != nil {
			return err
		}
	}
	outcome, err := s.exchange(ctx, username, password, options.InitOnly)
	if err != nil || options.InitOnly {
		return err
	}
	if outcome.status == 409 {
		if outcome.action != "trustedDeviceSecondaryAuth" {
			return fmt.Errorf("GrandSlam requires secondary action %q", outcome.action)
		}
		if err := s.verifyTrustedDevice(ctx, outcome.data); err != nil {
			return err
		}
		// A fresh SRP exchange after verification acquires the PET.
		outcome, err = s.exchange(ctx, username, password, false)
		if err != nil {
			return err
		}
		if outcome.status != 200 {
			return fmt.Errorf("GrandSlam did not return success after 2FA: hsc=%d, action=%q", outcome.status, outcome.action)
		}
	}
	pet := outcome.data.Tokens.PET.Token
	if pet == "" {
		return errors.New("GrandSlam succeeded but returned no password-equivalent token")
	}
	fmt.Fprintln(os.Stderr, "GrandSlam: password-equivalent token acquired")
	return s.mobileMe(ctx, username, pet, outcome.data, options.Output)
}

func loginAccount(path string) (string, error) {
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read account request: %w", err)
		}
		var request struct {
			Request struct {
				Username string `plist:"u"`
			} `plist:"Request"`
		}
		if _, err := plist.Unmarshal(data, &request); err != nil {
			return "", errors.New("cannot parse account request plist")
		}
		username := strings.TrimSpace(request.Request.Username)
		if username == "" {
			return "", errors.New("account request plist has no Request.u")
		}
		return username, nil
	}
	fmt.Fprint(os.Stderr, "Apple Account: ")
	username, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return "", errors.New("Apple Account is empty")
	}
	return username, nil
}

func loginReadSecret(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)
	value, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	return value, err
}

func loginHeaderValue(headers map[string]string, name string) string {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return value
		}
	}
	return ""
}

func (s *loginSession) baseHeaders() http.Header {
	header := make(http.Header)
	header.Set("X-MMe-Client-Info", s.provider.ClientInfo())
	header.Set("User-Agent", s.provider.UserAgent())
	header.Set("Accept", "*/*")
	header.Set("X-Apple-I-Client-Time", time.Now().UTC().Format(time.RFC3339))
	return header
}

func (s *loginSession) lookup(ctx context.Context) error {
	_, data, err := s.request(ctx, "urlbag", http.MethodGet, loginBagURL, s.baseHeaders(), nil, nil)
	if err != nil {
		return err
	}
	var response struct {
		URLs loginURLs `plist:"urls"`
	}
	if _, err := plist.Unmarshal(data, &response); err != nil {
		return errors.New("GrandSlam URL bag is not a plist")
	}
	s.bag = response.URLs
	if s.bag.Service == "" {
		return errors.New("GrandSlam URL bag has no gsService")
	}
	fmt.Fprintln(os.Stderr, "GrandSlam: URL bag acquired")
	return nil
}

func (s *loginSession) exchange(ctx context.Context, username string, password []byte, initOnly bool) (loginOutcome, error) {
	var outcome loginOutcome
	headers, err := s.provider.Headers(ctx)
	if err != nil {
		return outcome, err
	}
	cpd := make(map[string]any)
	for key, value := range headers {
		lower := strings.ToLower(key)
		if strings.HasPrefix(lower, "x-apple-") || lower == "x-mme-device-id" {
			cpd[key] = value
		}
	}
	cpd["loc"] = loginHeaderValue(headers, "X-Apple-Locale")
	for _, name := range []string{"bootstrap", "icscrec", "prkgen"} {
		cpd[name] = true
	}
	cpd["pbe"] = false
	cpd["svct"] = "iCloud"
	srp, err := newLoginSRP()
	if err != nil {
		return outcome, err
	}
	request := loginRequest{ClientPublic: srp.public.Bytes(), ClientData: cpd, Operation: "init", Protocols: []string{"s2k", "s2k_fo"}, Username: username}
	response, err := s.grandSlam(ctx, "init", request, false)
	if err != nil {
		return outcome, err
	}
	if initOnly {
		if len(response.ServerPublic) == 0 {
			return outcome, errors.New("GrandSlam init returned no SRP challenge")
		}
		return outcome, nil
	}
	iterations := response.Iterations
	if iterations <= 0 || int64(int(iterations)) != iterations {
		return outcome, errors.New("GrandSlam init has no valid iteration count")
	}
	salt, serverPublic := response.Salt, response.ServerPublic
	if len(salt) == 0 || len(serverPublic) == 0 || response.Cookie == nil {
		return outcome, errors.New("GrandSlam init lacks salt, B, or cookie")
	}
	proof, err := srp.process(username, password, salt, serverPublic, int(iterations), response.Protocol)
	if err != nil {
		return outcome, err
	}
	response, err = s.grandSlam(ctx, "complete", loginRequest{ClientProof: proof.m1, Cookie: response.Cookie, ClientData: cpd, Operation: "complete", Username: username}, true)
	if err != nil {
		return outcome, err
	}
	if response.Status.HSC != nil {
		outcome.status = *response.Status.HSC
	}
	outcome.action = response.Status.Action
	if encrypted := response.EncryptedSPD; len(encrypted) > 0 {
		plain, err := proof.decrypt(response.ServerProof, encrypted)
		if err != nil {
			return outcome, err
		}
		outcome.data = new(loginSPD)
		if _, err := plist.Unmarshal(plain, outcome.data); err != nil {
			return outcome, errors.New("GrandSlam decrypted SPD is not a plist dictionary")
		}
	}
	switch outcome.status {
	case 200:
		if outcome.data == nil {
			return outcome, errors.New("GrandSlam success response has no SPD")
		}
		fmt.Fprintln(os.Stderr, "GrandSlam: SRP succeeded")
	case 409:
		if outcome.data == nil || outcome.action == "" {
			return outcome, errors.New("GrandSlam secondary action has no SPD or action")
		}
	case 433:
		return outcome, errors.New("GrandSlam requested ADI reprovisioning (hsc=433)")
	case 434:
		return outcome, errors.New("GrandSlam requested ADI resync (hsc=434)")
	case 435:
		return outcome, errors.New("GrandSlam requested URL switching (hsc=435)")
	default:
		return outcome, fmt.Errorf("GrandSlam returned unsupported status hsc=%d", outcome.status)
	}
	return outcome, nil
}

func (s *loginSession) grandSlam(ctx context.Context, stage string, request loginRequest, closeConnection bool) (*loginResponse, error) {
	envelope := struct {
		Header struct {
			Version string `plist:"Version"`
		} `plist:"Header"`
		Request loginRequest `plist:"Request"`
	}{Request: request}
	envelope.Header.Version = "1.0.1"
	body, err := plist.Marshal(envelope, plist.XMLFormat)
	if err != nil {
		return nil, err
	}
	if err := s.save(stage+"-request.plist", body); err != nil {
		return nil, err
	}
	headers := s.baseHeaders()
	headers.Set("Content-Type", "text/x-xml-plist")
	if closeConnection {
		headers.Set("Connection", "close")
	}
	status, data, requestErr := s.request(ctx, stage, http.MethodPost, s.bag.Service, headers, body, nil)
	var top struct {
		Response *loginResponse `plist:"Response"`
	}
	_, parseErr := plist.Unmarshal(data, &top)
	response := top.Response
	metadata := loginMetadata{Stage: "GrandSlam " + stage, Status: status, ResponseBytes: len(data)}
	if response != nil && response.Status != nil {
		metadata.AppleCode = response.Status.Code
		metadata.HSC = response.Status.HSC
	}
	if stage == "init" {
		present := response != nil && len(response.ServerPublic) > 0
		metadata.SRPChallengePresent = &present
	}
	encoded, _ := json.Marshal(metadata)
	fmt.Fprintln(os.Stderr, string(encoded))
	if err := s.save(stage+"-metadata.json", append(encoded, '\n')); err != nil {
		return nil, err
	}
	if requestErr != nil {
		return nil, requestErr
	}
	if parseErr != nil || response == nil || response.Status == nil {
		return nil, fmt.Errorf("GrandSlam %s returned an invalid plist response", stage)
	}
	if err := loginAppleError("GrandSlam "+stage, *response.Status); err != nil {
		return nil, err
	}
	return response, nil
}

func (s *loginSession) identityHeaders(ctx context.Context, data *loginSPD) (http.Header, error) {
	adsid, idms := data.ADSID, data.IDMSToken
	if adsid == "" || idms == "" {
		return nil, errors.New("GrandSlam 2FA SPD lacks adsid or GsIdmsToken")
	}
	fresh, err := s.provider.Headers(ctx)
	if err != nil {
		return nil, err
	}
	header := s.baseHeaders()
	for _, name := range []string{"X-Apple-I-MD", "X-Apple-I-MD-M", "X-Apple-I-MD-RINFO"} {
		header.Set(name, loginHeaderValue(fresh, name))
	}
	header.Set("X-Apple-Identity-Token", base64.StdEncoding.EncodeToString([]byte(adsid+":"+idms)))
	return header, nil
}

func (s *loginSession) verifyTrustedDevice(ctx context.Context, data *loginSPD) error {
	headers, err := s.identityHeaders(ctx, data)
	if err != nil {
		return err
	}
	headers.Set("Content-Type", "text/x-xml-plist")
	headers.Set("Accept", "text/x-xml-plist")
	if _, _, err := s.request(ctx, "trusteddevice", http.MethodGet, "https://gsa.apple.com/auth/verify/trusteddevice", headers, nil, nil); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "2FA: trusted-device notification requested")
	code, err := loginReadSecret("Verification code: ")
	if err != nil {
		return err
	}
	headers, err = s.identityHeaders(ctx, data)
	if err != nil {
		return err
	}
	headers.Set("security-code", strings.TrimSpace(string(code)))
	validateURL := s.bag.ValidateCode
	if validateURL == "" {
		return errors.New("GrandSlam URL bag has no validateCode")
	}
	status, body, err := s.request(ctx, "validate", http.MethodGet, validateURL, headers, nil, nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("2FA verification returned HTTP %d", status)
	}
	var response loginAppleStatus
	if _, err := plist.Unmarshal(body, &response); err != nil {
		return errors.New("2FA verification response is not a plist")
	}
	if response.Code == nil {
		return errors.New("2FA verification response has no ec")
	}
	if *response.Code == -21669 {
		return errors.New("2FA verification code is invalid")
	}
	if err := loginAppleError("2FA verification", response); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "2FA: code accepted")
	return nil
}

func (s *loginSession) mobileMe(ctx context.Context, username, pet string, data *loginSPD, output string) error {
	headers, err := s.provider.Headers(ctx)
	if err != nil {
		return err
	}
	clientInfo := loginHeaderValue(headers, "X-MMe-Client-Info")
	parts := strings.Split(strings.TrimSuffix(strings.TrimPrefix(clientInfo, "<"), ">"), "> <")
	if len(parts) != 3 {
		return errors.New("Anisette client info has no model / OS profile")
	}
	clientInfo = fmt.Sprintf("<%s> <%s> <com.apple.AOSKit/282 (com.apple.accountsd/113)>", parts[0], parts[1])
	deviceID := loginHeaderValue(headers, "X-Mme-Device-Id")
	adsid := data.ADSID
	if deviceID == "" || adsid == "" {
		return errors.New("MobileMe login lacks device ID or alternate DSID")
	}
	request := struct {
		AppleID   string `plist:"apple-id"`
		ClientID  string `plist:"client-id"`
		Password  string `plist:"password"`
		Delegates struct {
			MobileMe struct{} `plist:"com.apple.mobileme"`
		} `plist:"delegates"`
	}{AppleID: username, ClientID: deviceID, Password: pet}
	body, err := plist.Marshal(request, plist.XMLFormat)
	if err != nil {
		return err
	}
	header := make(http.Header)
	for name, value := range headers {
		header.Set(name, value)
	}
	header.Set("X-MMe-Client-Info", clientInfo)
	header.Set("User-Agent", loginMobileMeUA)
	header.Set("Content-Type", "text/plist")
	header.Set("Accept", "application/x-plist")
	header.Set("X-Apple-ADSID", adsid)
	_, raw, err := s.request(ctx, "mobileme", http.MethodPost, loginMobileMeURL, header, body, func(r *http.Request) { r.SetBasicAuth(username, pet) })
	if err != nil {
		return err
	}
	var response loginMobileMeResponse
	if _, err := plist.Unmarshal(raw, &response); err != nil {
		return errors.New("MobileMe response is not a plist")
	}
	if response.LocalizedError != nil {
		return errors.New("MobileMe rejected authentication")
	}
	if response.Status == nil {
		return errors.New("MobileMe response has no status")
	}
	if *response.Status != 0 {
		return fmt.Errorf("MobileMe login status=%d", *response.Status)
	}
	delegate := response.Delegates.MobileMe
	if delegate.Status == nil {
		return errors.New("MobileMe delegate has no status")
	}
	if *delegate.Status != 0 {
		return fmt.Errorf("MobileMe delegate status=%d", *delegate.Status)
	}
	service := delegate.Service
	dsid := service.AppleAccountInfo.DSID
	if dsid == "" {
		dsid = service.DSID
	}
	if dsid == "" {
		dsid = response.DSID
	}
	token := service.Tokens.AuthToken
	if dsid == "" || token == "" {
		return errors.New("MobileMe service data lacks DSID or mmeAuthToken")
	}
	template, source := loginCSFURL, "public device endpoint, verified with MobileMe Basic authentication"
	for _, quota := range []loginQuota{service.AccountInfo.Quota, service.MobileMe.Quota, service.Quota} {
		if value := quota.URLTemplate; value != "" {
			template, source = value, "MobileMe Quota dataclass"
			break
		}
	}
	credential := Account{DSID: string(dsid), AuthToken: token, URLTemplate: template, URLTemplateSource: source, CSFClientInfo: clientInfo, DeviceID: deviceID, FeatureKey: subscriberFeatureKey}
	encoded, err := json.MarshalIndent(credential, "", "  ")
	if err != nil {
		return err
	}
	if err := state.WritePrivate(output, append(encoded, '\n')); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "MobileMe: DSID and mmeAuthToken acquired; saved %s\n", output)
	return nil
}

func (s *loginSession) request(ctx context.Context, stage, method, url string, headers http.Header, body []byte, customize func(*http.Request)) (int, []byte, error) {
	request, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return 0, nil, fmt.Errorf("%s: build request: %w", stage, err)
	}
	request.Header = headers
	request.Close = strings.EqualFold(headers.Get("Connection"), "close")
	if customize != nil {
		customize(request)
	}
	response, err := s.client.Do(request)
	if err != nil {
		return 0, nil, fmt.Errorf("%s request: %w", stage, err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		return response.StatusCode, nil, fmt.Errorf("%s response read: %w", stage, err)
	}
	if err := s.save(stage+"-response.plist", data); err != nil {
		return response.StatusCode, data, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return response.StatusCode, data, fmt.Errorf("%s: HTTP %d", stage, response.StatusCode)
	}
	return response.StatusCode, data, nil
}

func (s *loginSession) save(name string, data []byte) error {
	if s.debugDir == "" {
		return nil
	}
	return state.WritePrivate(filepath.Join(s.debugDir, "auth-"+name), data)
}

// MobileMe may encode a DSID as either a plist string or integer.
type loginDSID string

func (d *loginDSID) UnmarshalPlist(unmarshal func(any) error) error {
	var value any
	if err := unmarshal(&value); err != nil {
		return err
	}
	var text string
	switch value := value.(type) {
	case string:
		text = value
	case uint64:
		text = strconv.FormatUint(value, 10)
	case int64:
		if value >= 0 {
			text = strconv.FormatInt(value, 10)
		}
	}
	for _, digit := range text {
		if digit < '0' || digit > '9' {
			return nil
		}
	}
	*d = loginDSID(text)
	return nil
}

func loginAppleError(stage string, status loginAppleStatus) error {
	if status.Code == nil || *status.Code == 0 {
		return nil
	}
	if status.Subcode != nil {
		return fmt.Errorf("%s Apple error: code=%d, subcode=%d", stage, *status.Code, *status.Subcode)
	}
	return fmt.Errorf("%s Apple error: code=%d", stage, *status.Code)
}
