// Package diagnostic runs the account-to-relay workflow and reports public
// configuration and stage results without exposing credentials or response bodies.
package diagnostic

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"iprd/internal/auth"
	"iprd/internal/control"
	"iprd/internal/progress"
	"iprd/internal/relay"
)

type Options struct {
	Control  control.Options
	URL      string
	UDP      string
	Timeout  time.Duration
	ListOnly bool
	JSON     bool
}

type Stage struct {
	Name       string `json:"name"`
	Status     string `json:"status"`
	DurationMS int64  `json:"durationMs"`
	Message    string `json:"message"`
	Retries    int    `json:"retries,omitempty"`
	started    time.Time
	updated    time.Time
}

type Proxy struct {
	Index    int    `json:"index"`
	Vendor   string `json:"vendor"`
	Hostname string `json:"hostname"`
	Server   string `json:"server"`
	Hop      string `json:"hop"`
}

type Path struct {
	Indexes        []int  `json:"indexes"`
	Weight         uint32 `json:"weight"`
	FallbackWeight uint32 `json:"fallbackWeight,omitempty"`
	Active         bool   `json:"active"`
	Selected       bool   `json:"selected"`
}

type Route struct {
	Ingress Proxy `json:"ingress"`
	Egress  Proxy `json:"egress"`
}

type Configuration struct {
	SignatureVerified  bool    `json:"signatureVerified"`
	Epoch              uint16  `json:"epoch"`
	PreferenceFallback bool    `json:"preferenceFallback"`
	Proxies            []Proxy `json:"proxies"`
	Paths              []Path  `json:"paths"`
}

type Report struct {
	Success       bool           `json:"success"`
	Error         string         `json:"error,omitempty"`
	FailedStage   string         `json:"failedStage,omitempty"`
	StartedAt     time.Time      `json:"startedAt"`
	DurationMS    int64          `json:"durationMs"`
	Stages        []Stage        `json:"stages"`
	Network       string         `json:"network,omitempty"`
	Configuration *Configuration `json:"configuration,omitempty"`
	Route         *Route         `json:"route,omitempty"`
	HTTPStatus    int            `json:"httpStatus,omitempty"`
	ResponseBytes int64          `json:"responseBytes"`
	ExitIP        string         `json:"exitIP,omitempty"`
	DNS           *DNSReport     `json:"dns,omitempty"`
}

type recorder struct {
	mu          sync.Mutex
	report      Report
	writer      io.Writer
	targetSent  bool
	actualRoute *relay.Config
	events      map[string]progress.Event
}

var tokenPattern = regexp.MustCompile(`(?i)((?:Private|Privacy)Token\s+token=)[^\s,;]+`)

func redact(message string) string { return tokenPattern.ReplaceAllString(message, "${1}[redacted]") }

func (r *recorder) stage(name, status, message string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stageLocked(name, status, redact(message))
}

func (r *recorder) stageLocked(name, status, message string) {
	now := time.Now()
	index := slices.IndexFunc(r.report.Stages, func(stage Stage) bool { return stage.Name == name })
	if index < 0 {
		r.report.Stages = append(r.report.Stages, Stage{Name: name, started: now})
		index = len(r.report.Stages) - 1
	}
	stage := &r.report.Stages[index]
	if stage.Status == "error" && status != "error" {
		return
	}
	// This report describes the first end-to-end attempt. Refills can begin as
	// soon as a session consumes a token; keep their progress in the log without
	// reopening a prerequisite that already completed for this request.
	if stage.Status == "ok" && status != "error" && (name == "provider" || r.events[name].Stage == "tokens") {
		fmt.Fprintf(r.writer, "[%s] %s: %s: %s\n", time.Since(r.report.StartedAt).Round(time.Millisecond), name, status, message)
		return
	}
	stage.Status, stage.Message, stage.updated = status, message, now
	stage.DurationMS = now.Sub(stage.started).Milliseconds()
	if status == "retry" {
		stage.Retries++
	}
	fmt.Fprintf(r.writer, "[%s] %s: %s: %s\n", time.Since(r.report.StartedAt).Round(time.Millisecond), name, status, message)
}

func (r *recorder) fail(name string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.report.FailedStage == "" {
		r.report.FailedStage = name
		r.stageLocked(name, "error", redact(err.Error()))
	}
}

// logf writes human-readable detail only. Progress and cancellation are driven
// exclusively by structured events.
func (r *recorder) logf(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	fmt.Fprintf(r.writer, "[%s] %s\n", time.Since(r.report.StartedAt).Round(time.Millisecond), redact(fmt.Sprintf(format, args...)))
}

func eventName(event progress.Event) string {
	if event.Stage == "route" {
		return "route:" + event.Network
	}
	if event.Hop != "" {
		return event.Stage + ":" + event.Hop
	}
	return event.Stage
}

func (r *recorder) observe(event progress.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	name := eventName(event)
	r.events[name] = event
	message := event.Detail
	if event.Err != nil {
		if message != "" {
			message += ": "
		}
		message += event.Err.Error()
	}
	status := event.Status
	// A failed session or path may still be replaced. Only the final caller
	// error, or an explicit terminal event, makes the diagnostic fail.
	if status == progress.Failed && !event.Terminal {
		status = progress.Retry
	}
	if event.Stage == "route" && event.Status == progress.Retry {
		for _, stage := range r.report.Stages {
			previous := r.events[stage.Name]
			if (previous.Stage == "quic" || previous.Stage == "connect-udp" || previous.Stage == "connect") && (stage.Status == "running" || stage.Status == "retry") {
				r.stageLocked(stage.Name, "fallback", redact(message))
			}
		}
	}
	r.stageLocked(name, string(status), redact(message))
	if event.Terminal && event.Err != nil && r.report.FailedStage == "" {
		r.report.FailedStage = name
	}
}

func proxySummary(proxy control.Proxy) Proxy {
	hop := map[int]string{1: "ingress", 2: "egress", 3: "any"}[proxy.Hop]
	return Proxy{Index: proxy.Index, Vendor: proxy.Name, Hostname: proxy.ServerName, Server: proxy.Server, Hop: hop}
}

func (r *recorder) configuration(configuration control.Configuration) {
	if !configuration.SignatureVerified {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	result := &Configuration{SignatureVerified: true, Epoch: configuration.Epoch, PreferenceFallback: configuration.PreferenceFallback}
	for _, proxy := range configuration.Proxies {
		result.Proxies = append(result.Proxies, proxySummary(proxy))
	}
	for _, path := range configuration.Paths {
		selected := slices.Equal(path.Indexes, configuration.SelectedPath.Indexes)
		result.Paths = append(result.Paths, Path{Indexes: slices.Clone(path.Indexes), Weight: path.Weight, FallbackWeight: path.FallbackWeight, Active: path.Weight > 0 || selected, Selected: selected})
	}
	r.report.Configuration = result
	if r.actualRoute != nil {
		r.setRouteLocked(*r.actualRoute)
	} else if r.report.Network != "udp" {
		r.report.Route = &Route{Ingress: proxySummary(configuration.Ingress), Egress: proxySummary(configuration.Egress)}
	}
}

func (r *recorder) failureStage(snapshot control.Snapshot, err error) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.report.FailedStage != "" {
		return r.report.FailedStage
	}
	if snapshot.LastFailure != nil && snapshot.LastFailure.Terminal {
		return snapshot.LastFailure.Stage
	}
	if r.targetSent {
		if r.report.Network == "udp" {
			return "target:dns"
		}
		return "target:http"
	}
	// Match the actual error chain to structured event errors. Stage order
	// preserves the originating hop when an outer dial wraps its failure.
	for _, stage := range r.report.Stages {
		event := r.events[stage.Name]
		if stage.Status != "ok" && stage.Status != "fallback" && event.Err != nil && errors.Is(err, event.Err) {
			return stage.Name
		}
	}
	if !snapshot.SubscriptionReady {
		return "subscription"
	}
	if !snapshot.Configuration.SignatureVerified {
		return "configuration"
	}
	if !snapshot.ProviderReady {
		return "provider"
	}
	for _, stage := range r.report.Stages {
		if stage.Name == "provider" && stage.Status != "ok" && r.events[stage.Name].Err != nil {
			return "provider"
		}
	}
	if snapshot.LastFailure != nil {
		for _, stage := range r.report.Stages {
			if stage.Name == snapshot.LastFailure.Stage && stage.Status != "ok" {
				return stage.Name
			}
		}
	}
	var pending string
	var updated time.Time
	for _, stage := range r.report.Stages {
		event := r.events[stage.Name]
		if (stage.Status == "running" || stage.Status == "retry") && event.Stage != "" && stage.updated.After(updated) {
			pending, updated = stage.Name, stage.updated
		}
	}
	if pending != "" {
		return pending
	}
	if r.report.Network == "udp" {
		return "route:udp"
	}
	for _, stage := range r.report.Stages {
		if stage.Name == "target:tls" && stage.Status == "running" {
			return stage.Name
		}
	}
	return "target:http"
}

// Run writes one final text or JSON report, including on failure. ListOnly uses
// only the public signed configuration and never opens account or ADI state.
func Run(ctx context.Context, options Options, output, diagnostics io.Writer) (runErr error) {
	if output == nil {
		output = io.Discard
	}
	if diagnostics == nil {
		diagnostics = io.Discard
	}
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	network := "tcp"
	if options.ListOnly {
		network = ""
	} else if options.UDP != "" {
		network = "udp"
	}
	r := &recorder{writer: diagnostics, events: make(map[string]progress.Event), report: Report{StartedAt: time.Now().UTC(), Network: network}}
	var manager *control.Manager
	defer func() {
		if manager != nil {
			r.configuration(manager.Snapshot().Configuration)
		}
		if runErr != nil {
			if cause := context.Cause(ctx); cause != nil {
				runErr = cause
			}
		}
		r.mu.Lock()
		r.report.Success, r.report.DurationMS = runErr == nil, time.Since(r.report.StartedAt).Milliseconds()
		if runErr != nil {
			r.report.Error = redact(runErr.Error())
		}
		for i := range r.report.Stages {
			stage := &r.report.Stages[i]
			if stage.Status == "running" || stage.Status == "retry" {
				stage.DurationMS = time.Since(stage.started).Milliseconds()
			}
		}
		report := r.report
		r.mu.Unlock()
		runErr = errors.Join(runErr, writeReport(output, report, options.JSON))
	}()

	if options.Control.ClientInfo == "" {
		options.Control.ClientInfo = control.DefaultClientInfo
	}
	if options.ListOnly {
		r.stage("configuration", "running", "download and verify public relay configuration")
		client, err := auth.NewHTTPClient()
		if err != nil {
			r.fail("configuration", err)
			return err
		}
		defer client.CloseIdleConnections()
		configuration, err := control.FetchConfiguration(ctx, client, "", options.Control.ClientInfo, options.Control.Preferences)
		if err != nil {
			r.fail("configuration", err)
			return err
		}
		r.configuration(configuration)
		r.stage("configuration", "ok", "signature verified; public vendors and paths available")
		return nil
	}
	if options.Control.Subscription == "" {
		if options.Control.Account == "" {
			options.Control.Account = "runtime/account.json"
		}
		r.stage("account", "running", "load existing MobileMe credential")
		if _, err := auth.LoadAccount(options.Control.Account); err != nil {
			r.fail("account", err)
			return err
		}
		r.stage("account", "ok", "normalized credential fields present; account authentication is checked by CSF")
	} else {
		r.stage("account", "skipped", "using the supplied subscription response")
	}
	r.stage("subscription", "running", "obtain the Private Relay subscriber feature")
	previousObserver := options.Control.Observer
	observer := progress.Observer(func(event progress.Event) {
		r.observe(event)
		previousObserver.Emit(event)
		if event.Terminal && event.Err != nil {
			cancel(event.Err)
		}
	})
	options.Control.Observer = observer

	var err error
	manager, err = control.NewManager(ctx, options.Control, r.logf)
	if err != nil {
		r.fail("controller", err)
		return err
	}
	defer manager.Close()
	if _, err := manager.Current(ctx); err != nil {
		snapshot := manager.Snapshot()
		if snapshot.LastFailure != nil {
			r.stage(snapshot.LastFailure.Stage, "retry", snapshot.LastFailure.Message)
		}
		r.fail(r.failureStage(snapshot, err), err)
		return err
	}
	r.configuration(manager.Snapshot().Configuration)
	dialer, err := relay.NewManaged(ctx, manager, r.logf, observer)
	if err == nil {
		err = dialer.SetTransport(relay.Transport(options.Control.Transport))
	}
	if err != nil {
		r.fail("relay", err)
		return err
	}
	defer dialer.Close()
	if options.UDP != "" {
		return r.probeDNS(ctx, dialer, manager, options.UDP)
	}
	transport := &http.Transport{DialContext: dialer.DialContext, TLSClientConfig: &tls.Config{NextProtos: []string{"http/1.1"}}}
	defer transport.CloseIdleConnections()
	if options.URL == "" {
		options.URL = "https://api.ipify.org/"
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, options.URL, nil)
	if err != nil {
		r.fail("target:http", err)
		return err
	}
	trace := &httptrace.ClientTrace{
		TLSHandshakeStart: func() { r.stage("target:tls", "running", "TLS handshake with target through both relay hops") },
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			if err != nil {
				r.fail("target:tls", err)
			} else {
				r.stage("target:tls", "ok", "target TLS handshake verified")
			}
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			if info.Err == nil {
				r.mu.Lock()
				r.targetSent = true
				r.mu.Unlock()
				r.stage("target:http", "running", "HTTP request sent through both relay hops")
			}
		},
	}
	request = request.WithContext(httptrace.WithClientTrace(request.Context(), trace))
	r.stage("target:http", "running", "establish both relay hops and request target")
	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		var urlError *url.Error
		if errors.As(err, &urlError) {
			err = urlError.Err
		}
		snapshot := manager.Snapshot()
		if snapshot.LastFailure != nil {
			r.stage(snapshot.LastFailure.Stage, "retry", snapshot.LastFailure.Message)
		}
		r.fail(r.failureStage(snapshot, err), err)
		return err
	}
	defer response.Body.Close()
	r.mu.Lock()
	r.report.HTTPStatus = response.StatusCode
	r.mu.Unlock()
	if route, ok := dialer.Route("tcp"); ok {
		r.mu.Lock()
		r.actualRoute = &route
		r.setRouteLocked(route)
		r.mu.Unlock()
	}
	var prefix strings.Builder
	count, err := io.Copy(&limitedCapture{writer: &prefix, remaining: 128}, response.Body)
	r.mu.Lock()
	r.report.ResponseBytes = count
	if address, parseErr := netip.ParseAddr(strings.TrimSpace(prefix.String())); parseErr == nil && count <= 128 {
		r.report.ExitIP = address.String()
	}
	r.mu.Unlock()
	if err != nil {
		r.fail("target:body", err)
		return err
	}
	if response.StatusCode >= http.StatusBadRequest {
		err := fmt.Errorf("target returned HTTP %d", response.StatusCode)
		r.fail("target:http", err)
		return err
	}
	r.stage("target:http", "ok", fmt.Sprintf("HTTP %d; read %d response bytes", response.StatusCode, count))
	return nil
}

type limitedCapture struct {
	writer    io.Writer
	remaining int
}

func (c *limitedCapture) Write(data []byte) (int, error) {
	n := len(data)
	if c.remaining > 0 {
		part := data[:min(c.remaining, n)]
		if _, err := c.writer.Write(part); err != nil {
			return 0, err
		}
		c.remaining -= len(part)
	}
	return n, nil
}

func writeReport(output io.Writer, report Report, asJSON bool) error {
	if asJSON {
		encoder := json.NewEncoder(output)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	}
	var text strings.Builder
	if report.Success {
		fmt.Fprintf(&text, "iprd debug: success (%d ms)\n", report.DurationMS)
	} else {
		fmt.Fprintf(&text, "iprd debug: failed at %s (%d ms)\nerror: %s\n", report.FailedStage, report.DurationMS, report.Error)
	}
	if report.Route != nil {
		label := "route"
		if report.Network != "" {
			label += " (" + report.Network + ")"
		}
		fmt.Fprintf(&text, "%s: [%d] %s %s -> [%d] %s %s\n", label, report.Route.Ingress.Index, report.Route.Ingress.Vendor, report.Route.Ingress.Server, report.Route.Egress.Index, report.Route.Egress.Vendor, report.Route.Egress.Server)
	}
	if configuration := report.Configuration; configuration != nil {
		fmt.Fprintf(&text, "configuration: signature verified, epoch %d\nproxies:\n", configuration.Epoch)
		for _, proxy := range configuration.Proxies {
			endpoint := proxy.Server
			if endpoint == "" {
				endpoint = proxy.Hostname + " (no TCP fallback endpoint)"
			}
			fmt.Fprintf(&text, "  [%d] %-12s %-7s %s\n", proxy.Index, proxy.Vendor, proxy.Hop, endpoint)
		}
		fmt.Fprintln(&text, "paths:")
		for _, path := range configuration.Paths {
			selected := ""
			if path.Selected {
				selected = " selected"
			} else if !path.Active {
				selected = " inactive"
			}
			if path.FallbackWeight != 0 {
				fmt.Fprintf(&text, "  %v weight=%d fallback=%d%s\n", path.Indexes, path.Weight, path.FallbackWeight, selected)
			} else {
				fmt.Fprintf(&text, "  %v weight=%d%s\n", path.Indexes, path.Weight, selected)
			}
		}
		if configuration.PreferenceFallback {
			fmt.Fprintln(&text, "preferences: some requested preferences could not be satisfied; selected the best matching published path")
		}
	}
	fmt.Fprintln(&text, "stages:")
	for _, stage := range report.Stages {
		fmt.Fprintf(&text, "  %-7s %-24s %6d ms  %s\n", stage.Status, stage.Name, stage.DurationMS, stage.Message)
	}
	if report.HTTPStatus != 0 {
		fmt.Fprintf(&text, "target: HTTP %d, %d bytes", report.HTTPStatus, report.ResponseBytes)
		if report.ExitIP != "" {
			fmt.Fprintf(&text, ", exit IP %s", report.ExitIP)
		}
		fmt.Fprintln(&text)
	}
	if dns := report.DNS; dns != nil {
		fmt.Fprintf(&text, "DNS: %s %s via %s, %d bytes", dns.Name, dns.Type, dns.Server, report.ResponseBytes)
		if dns.RCode != nil {
			fmt.Fprintf(&text, ", rcode=%d (%s), answers=%d, id=%d, QR=%t", *dns.RCode, dns.RCodeName, dns.AnswerCount, dns.ResponseID, dns.QR)
		}
		fmt.Fprintln(&text)
	}
	_, err := io.WriteString(output, text.String())
	return err
}
