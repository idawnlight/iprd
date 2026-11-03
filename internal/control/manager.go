package control

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"slices"
	"sync"
	"time"

	"iprd/internal/auth"
	"iprd/internal/progress"
	"iprd/internal/relay"
)

type Options struct {
	Account, Subscription, StateDir, ServerURL, ClientInfo, Transport string
	TokenTarget                                                       int
	Preferences                                                       Preferences
	Observer                                                          progress.Observer
}

// Snapshot contains public relay metadata and readiness, never credentials.
type Snapshot struct {
	Configuration     Configuration
	SubscriptionReady bool
	ProviderReady     bool
	Pools             []PoolSnapshot
	LastFailure       *Failure
}

type PoolSnapshot struct {
	Name      string
	Unused    int
	ExpiresAt time.Time
}

type Failure struct {
	Stage    string
	Message  string
	Terminal bool
}

// SubscriptionError describes an explicit, unusable CSF subscriber response.
// The controller keeps retrying, while callers can fail without a timeout.
type SubscriptionError struct{ Reason string }

func (e *SubscriptionError) Error() string { return e.Reason }

type managerFailure struct {
	failure Failure
	at      time.Time
}

// Manager maintains the selected route, subscription and unused anonymous tokens.
// All relay state stays in memory. Each hop refills to 60 when 30 or fewer
// tokens remain. TokenTarget allows a different pool size.
type Manager struct {
	ctx      context.Context
	cancel   context.CancelFunc
	done     chan struct{}
	wake     chan struct{}
	options  Options
	logf     func(string, ...any)
	client   *http.Client
	provider *auth.Provider

	mu                 sync.Mutex
	changed            chan struct{}
	configuration      Configuration
	current            relay.Config
	ready              bool
	scope              string
	subscription       auth.Subscription
	pools              map[string]*tokenPool
	subscriptionNext   time.Time
	configurationNext  time.Time
	subscriptionForce  bool
	configurationForce bool
	subscriptionRetry  managerRetry
	configurationRetry managerRetry
	providerRetry      managerRetry
	failures           map[string]managerFailure
	terminal           *SubscriptionError
}

var _ relay.Source = (*Manager)(nil)

func NewManager(ctx context.Context, options Options, logf func(string, ...any)) (*Manager, error) {
	if options.Account == "" {
		options.Account = "runtime/account.json"
	}
	if options.StateDir == "" {
		options.StateDir = "runtime/anisette"
	}
	if options.ClientInfo == "" {
		options.ClientInfo = DefaultClientInfo
	}
	if options.TokenTarget <= 0 {
		options.TokenTarget = 60
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	client, err := auth.NewHTTPClient()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	m := &Manager{
		ctx: ctx, cancel: cancel, done: make(chan struct{}), wake: make(chan struct{}, 1),
		options: options, logf: logf, client: client, changed: make(chan struct{}), pools: make(map[string]*tokenPool),
	}
	go m.run()
	return m, nil
}

func (m *Manager) Close() error {
	m.cancel()
	<-m.done
	m.client.CloseIdleConnections()
	return nil
}

func (m *Manager) Current(ctx context.Context) (relay.Config, error) {
	for {
		if err := ctx.Err(); err != nil {
			return relay.Config{}, err
		}
		if err := m.ctx.Err(); err != nil {
			return relay.Config{}, err
		}
		m.mu.Lock()
		current, ready, changed, terminal := m.current, m.ready, m.changed, m.terminal
		m.mu.Unlock()
		if terminal != nil {
			return relay.Config{}, terminal
		}
		if ready {
			return current, nil
		}
		select {
		case <-ctx.Done():
			return relay.Config{}, ctx.Err()
		case <-m.ctx.Done():
			return relay.Config{}, m.ctx.Err()
		case <-changed:
		}
	}
}

func (m *Manager) TakeToken(ctx context.Context, hopID string) (relay.Credential, error) {
	for {
		if err := ctx.Err(); err != nil {
			return relay.Credential{}, err
		}
		if err := m.ctx.Err(); err != nil {
			return relay.Credential{}, err
		}
		m.mu.Lock()
		if m.terminal != nil {
			err := m.terminal
			m.mu.Unlock()
			return relay.Credential{}, err
		}
		pool := m.pools[hopID]
		if pool == nil {
			m.mu.Unlock()
			return relay.Credential{}, relay.ErrConfigurationChanged
		}
		pool.trim(time.Now())
		if len(pool.tokens) > 0 {
			credential := pool.tokens[0]
			pool.tokens[0] = relay.Credential{}
			pool.tokens = pool.tokens[1:]
			low := len(pool.tokens) <= m.options.TokenTarget/2
			m.mu.Unlock()
			if low {
				m.signal()
			}
			return credential, nil
		}
		changed := m.changed
		m.mu.Unlock()
		m.signal()
		select {
		case <-ctx.Done():
			return relay.Credential{}, ctx.Err()
		case <-m.ctx.Done():
			return relay.Credential{}, m.ctx.Err()
		case <-changed:
		}
	}
}

func (m *Manager) Rejected(hopID string) {
	m.mu.Lock()
	m.subscriptionForce, m.configurationForce = true, true
	m.mu.Unlock()
	m.signal()
}

func (m *Manager) signal() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

func (m *Manager) notifyLocked() {
	close(m.changed)
	m.changed = make(chan struct{})
}

func (m *Manager) run() {
	defer close(m.done)
	defer func() {
		m.mu.Lock()
		provider := m.provider
		m.mu.Unlock()
		if provider != nil {
			provider.HTTPClient().CloseIdleConnections()
		}
	}()
	for m.ctx.Err() == nil {
		m.refreshSubscription()
		m.refreshConfiguration()
		m.refillPools()
		m.mu.Lock()
		delay := m.nextDelayLocked(time.Now())
		m.mu.Unlock()
		timer := time.NewTimer(delay)
		select {
		case <-m.ctx.Done():
			timer.Stop()
			return
		case <-m.wake:
			timer.Stop()
		case <-timer.C:
		}
	}
}

func (m *Manager) refreshSubscription() {
	now := time.Now()
	m.mu.Lock()
	due := !now.Before(m.subscriptionNext) || (m.subscriptionForce && !now.Before(m.subscriptionRetry.next))
	wasTerminal := m.terminal != nil
	if due {
		m.subscriptionForce = false
	}
	m.mu.Unlock()
	if !due || m.ctx.Err() != nil {
		return
	}
	m.options.Observer.Emit(progress.Event{Stage: "subscription", Status: progress.Running, Detail: "refresh the Private Relay subscriber feature"})
	var subscription auth.Subscription
	var err error
	if m.options.Subscription != "" {
		var raw []byte
		raw, err = os.ReadFile(m.options.Subscription)
		if err == nil {
			subscription, err = auth.ParseSubscription(raw)
			if err == nil {
				m.changeScope(managerSubscriptionScope(subscription))
			}
		}
	} else {
		var account auth.Account
		account, err = auth.LoadAccount(m.options.Account)
		if err == nil {
			m.changeScope(managerAccountScope(account))
			subscription, err = auth.FetchSubscription(m.ctx, m.client, account)
		}
	}
	if m.ctx.Err() != nil {
		return
	}
	now = time.Now()
	m.mu.Lock()
	if err == nil {
		// A successful exchange can explicitly withdraw subscriber access.
		// Replace the previous response before reporting that semantic failure.
		m.subscription = subscription
		m.terminal = managerSubscriptionFailure(subscription, now)
		if m.terminal != nil {
			err = m.terminal
		} else if wasTerminal {
			m.configurationNext = time.Time{}
		}
	}
	if err != nil {
		m.subscriptionNext = m.subscriptionRetry.fail(now, 0)
		m.recordFailureLocked("subscription", "subscription", err)
		retryIn := time.Until(m.subscriptionNext).Round(time.Second)
		terminal := m.terminal != nil
		m.notifyLocked()
		m.mu.Unlock()
		m.logf("Subscription refresh failed; retry in %s: %v", retryIn, err)
		status := progress.Retry
		if terminal {
			status = progress.Failed
		}
		m.options.Observer.Emit(progress.Event{Stage: "subscription", Status: status, Detail: fmt.Sprintf("retry in %s", retryIn), Err: err, Terminal: terminal})
		return
	}
	m.subscription, m.subscriptionNext = subscription, managerSubscriptionRefresh(subscription, now)
	m.subscriptionRetry = managerRetry{}
	m.clearFailureLocked("subscription")
	next := m.subscriptionNext.UTC().Format(time.RFC3339)
	m.notifyLocked()
	m.mu.Unlock()
	m.logf("Subscription refreshed: canUse=%t; next refresh %s", subscription.CanUse, next)
	m.options.Observer.Emit(progress.Event{Stage: "subscription", Status: progress.OK, Detail: "subscriber feature is usable; next refresh " + next})
}

func (m *Manager) refreshConfiguration() {
	now := time.Now()
	m.mu.Lock()
	due := m.terminal == nil && (!now.Before(m.configurationNext) || (m.configurationForce && !now.Before(m.configurationRetry.next)))
	if due {
		m.configurationForce = false
	}
	var subscriber string
	if managerSubscriptionUsable(m.subscription, now) {
		subscriber = m.subscription.AccessToken
	}
	m.mu.Unlock()
	if !due || m.ctx.Err() != nil {
		return
	}
	m.options.Observer.Emit(progress.Event{Stage: "configuration", Status: progress.Running, Detail: "download and verify the signed relay configuration"})
	configuration, err := FetchConfiguration(m.ctx, m.client, subscriber, m.options.ClientInfo, m.options.Preferences)
	if err == nil && configuration.AuthType != 2 && configuration.AuthType != 3 {
		err = fmt.Errorf("configuration authentication type %d does not offer Anisette", configuration.AuthType)
	}
	if m.ctx.Err() != nil {
		return
	}
	now = time.Now()
	m.mu.Lock()
	if err != nil {
		m.configurationNext = m.configurationRetry.fail(now, 0)
		m.recordFailureLocked("configuration", "configuration", err)
		retryIn := time.Until(m.configurationNext).Round(time.Second)
		m.mu.Unlock()
		m.logf("Configuration refresh failed; retry in %s: %v", retryIn, err)
		m.options.Observer.Emit(progress.Event{Stage: "configuration", Status: progress.Retry, Detail: fmt.Sprintf("retry in %s", retryIn), Err: err})
		return
	}
	m.configurationRetry = managerRetry{}
	m.clearFailureLocked("configuration")
	m.installConfigurationLocked(configuration)
	m.mu.Unlock()
	if configuration.PreferenceFallback {
		m.logf("Some relay preferences could not be satisfied; selected %s -> %s", configuration.Ingress.Name, configuration.Egress.Name)
	}
	m.logf("Configuration refreshed: %s -> %s", configuration.Ingress.Name, configuration.Egress.Name)
	detail := fmt.Sprintf("signature verified; selected %s -> %s", configuration.Ingress.Name, configuration.Egress.Name)
	if configuration.PreferenceFallback {
		detail += "; some preferences unavailable"
	}
	m.options.Observer.Emit(progress.Event{Stage: "configuration", Status: progress.OK, Detail: detail})
}

func (m *Manager) installConfigurationLocked(configuration Configuration) {
	if configuration.FetchedAt.IsZero() {
		configuration.FetchedAt = time.Now().UTC()
	}
	if configuration.RefreshAt.IsZero() {
		configuration.RefreshAt = configuration.FetchedAt.Add(time.Hour)
	}
	if configuration.Revision == "" {
		configuration.Revision = configurationRevision(configuration)
	}
	current := m.relayConfigLocked(configuration.Epoch, configuration.Ingress, configuration.Egress)
	pools := make(map[string]*tokenPool, len(m.pools)+2)
	// Retain already activated alternative hops while their full token
	// identity remains in the refreshed proxy list.
	for _, proxy := range configuration.Proxies {
		id := proxy.ID
		if pool := m.pools[id]; pool != nil {
			pool.proxy = proxy
			pools[id] = pool
		}
	}
	for _, proxy := range []Proxy{configuration.Ingress, configuration.Egress} {
		id := proxy.ID
		pool := m.pools[id]
		if pool == nil {
			pool = &tokenPool{}
		}
		pool.proxy = proxy
		pools[id] = pool
	}
	for id := range m.pools {
		if pools[id] == nil {
			m.clearFailureLocked("tokens:" + id)
		}
	}
	m.configuration, m.current, m.pools, m.ready = configuration, current, pools, true
	m.configurationNext = configuration.RefreshAt
	m.notifyLocked()
}

func (m *Manager) changeScope(scope string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.scope == scope {
		return
	}
	m.scope, m.subscription = scope, auth.Subscription{}
	m.terminal = nil
	m.subscriptionRetry = managerRetry{}
	clear(m.failures)
	if m.ready {
		m.current.Revision = m.routeRevision(m.configuration.Revision)
	}
	for _, pool := range m.pools {
		pool.tokens, pool.retry = nil, managerRetry{}
	}
	m.notifyLocked()
}

func (m *Manager) routeRevision(configurationRevision string) string {
	return configurationRevision + ":" + m.scope
}

func managerSubscriptionRefresh(subscription auth.Subscription, now time.Time) time.Time {
	refresh := now.Add(time.Hour)
	if !subscription.CacheTill.IsZero() {
		refresh = subscription.CacheTill
	}
	if expiry := subscription.ExpiresAt.Add(-time.Minute); !subscription.ExpiresAt.IsZero() && expiry.Before(refresh) {
		refresh = expiry
	}
	if !refresh.After(now) {
		refresh = now.Add(time.Minute)
	}
	return refresh
}

func managerSubscriptionUsable(subscription auth.Subscription, now time.Time) bool {
	return subscription.CanUse && subscription.AccessToken != "" && (subscription.ExpiresAt.IsZero() || now.Before(subscription.ExpiresAt))
}

func managerSubscriptionFailure(subscription auth.Subscription, now time.Time) *SubscriptionError {
	if !subscription.CanUse {
		return &SubscriptionError{Reason: "CSF subscriber feature is unavailable (canUse=false)"}
	}
	if subscription.AccessToken == "" {
		return &SubscriptionError{Reason: "CSF subscriber feature has no accessToken"}
	}
	if !subscription.ExpiresAt.IsZero() && !now.Before(subscription.ExpiresAt) {
		return &SubscriptionError{Reason: "CSF subscriber accessToken expired at " + subscription.ExpiresAt.UTC().Format(time.RFC3339)}
	}
	return nil
}

func (m *Manager) Snapshot() Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	snapshot := Snapshot{
		Configuration:     m.configuration,
		SubscriptionReady: managerSubscriptionUsable(m.subscription, now),
		ProviderReady:     m.provider != nil,
	}
	for _, id := range m.activePoolIDsLocked() {
		pool := m.pools[id]
		status := PoolSnapshot{Name: pool.proxy.Name}
		for _, token := range pool.tokens {
			if token.Authorization == "" || (!token.ExpiresAt.IsZero() && !now.Before(token.ExpiresAt)) {
				continue
			}
			status.Unused++
			if !token.ExpiresAt.IsZero() && (status.ExpiresAt.IsZero() || token.ExpiresAt.Before(status.ExpiresAt)) {
				status.ExpiresAt = token.ExpiresAt
			}
		}
		snapshot.Pools = append(snapshot.Pools, status)
	}
	var latest time.Time
	for _, failure := range m.failures {
		if failure.at.After(latest) {
			copy := failure.failure
			snapshot.LastFailure, latest = &copy, failure.at
		}
	}
	if m.terminal != nil {
		snapshot.LastFailure = &Failure{Stage: "subscription", Message: m.terminal.Error(), Terminal: true}
	}
	return snapshot
}

func (m *Manager) recordFailureLocked(key, stage string, err error) {
	if m.failures == nil {
		m.failures = make(map[string]managerFailure)
	}
	_, terminal := err.(*SubscriptionError)
	m.failures[key] = managerFailure{failure: Failure{Stage: stage, Message: err.Error(), Terminal: terminal}, at: time.Now()}
}

func (m *Manager) clearFailureLocked(key string) {
	delete(m.failures, key)
}

// Alternatives returns the already ordered, positive-weight published routes.
// It does not activate pools or issue additional tokens.
func (m *Manager) Alternatives(ctx context.Context) ([]relay.Config, error) {
	if _, err := m.Current(ctx); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if m.terminal != nil {
		return nil, m.terminal
	}
	routes := make([]relay.Config, 0, len(m.configuration.Paths))
	for _, path := range m.configuration.Paths {
		if path.Weight > 0 {
			routes = append(routes, m.relayConfigLocked(m.configuration.Epoch, path.Ingress, path.Egress))
		}
	}
	return routes, nil
}

// ActivateRoute enables refill for a still-published route. Shared hops keep one
// pool, and activating an alternative preserves the selected TCP route.
func (m *Manager) ActivateRoute(ctx context.Context, route relay.Config) error {
	if _, err := m.Current(ctx); err != nil {
		return err
	}
	m.mu.Lock()
	if err := ctx.Err(); err != nil {
		m.mu.Unlock()
		return err
	}
	if m.terminal != nil {
		err := m.terminal
		m.mu.Unlock()
		return err
	}
	for _, path := range m.configuration.Paths {
		if path.Weight == 0 {
			continue
		}
		candidate := m.relayConfigLocked(m.configuration.Epoch, path.Ingress, path.Egress)
		if candidate.Revision != route.Revision || candidate.Epoch != route.Epoch ||
			candidate.Ingress.ID != route.Ingress.ID || candidate.Egress.ID != route.Egress.ID {
			continue
		}
		for _, proxy := range []Proxy{path.Ingress, path.Egress} {
			if m.pools[proxy.ID] == nil {
				m.pools[proxy.ID] = &tokenPool{proxy: proxy}
			}
		}
		m.notifyLocked()
		m.mu.Unlock()
		m.signal()
		return nil
	}
	m.mu.Unlock()
	return relay.ErrConfigurationChanged
}

func (m *Manager) relayConfigLocked(epoch uint16, ingress, egress Proxy) relay.Config {
	return relay.Config{
		Revision: m.routeRevision(routeIdentity(epoch, ingress.ID, egress.ID)), Epoch: epoch,
		Ingress: metadataHop(ingress), Egress: metadataHop(egress),
	}
}

// Selected ingress and egress pools precede activated alternatives. Native
// configuration indexes make the remaining refill order deterministic.
func (m *Manager) activePoolIDsLocked() []string {
	ids := make([]string, 0, len(m.pools))
	for id := range m.pools {
		ids = append(ids, id)
	}
	rank := func(id string) int {
		switch id {
		case m.current.Ingress.ID:
			return 0
		case m.current.Egress.ID:
			return 1
		default:
			return 2
		}
	}
	slices.SortFunc(ids, func(a, b string) int {
		if order := rank(a) - rank(b); order != 0 {
			return order
		}
		if order := m.pools[a].proxy.Index - m.pools[b].proxy.Index; order != 0 {
			return order
		}
		if a < b {
			return -1
		}
		if a > b {
			return 1
		}
		return 0
	})
	return ids
}

func managerAccountScope(account auth.Account) string {
	data := appendIdentityField([]byte("iprd:account:v1"), []byte(account.DSID))
	data = appendIdentityField(data, []byte(account.DeviceID))
	return "account:" + identityDigest(data)
}

// A subscription-file override has no independently supplied account identity;
// its opaque credential identifies its in-memory state.
func managerSubscriptionScope(subscription auth.Subscription) string {
	value := []byte(subscription.AccessToken)
	if len(value) == 0 {
		value = subscription.Raw
	}
	return "subscription:" + identityDigest(appendIdentityField([]byte("iprd:subscription:v1"), value))
}
