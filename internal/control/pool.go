package control

import (
	"errors"
	"fmt"
	"time"

	"iprd/internal/auth"
	"iprd/internal/progress"
	"iprd/internal/relay"
)

type tokenPool struct {
	proxy  Proxy
	tokens []relay.Credential
	retry  managerRetry
}

func (p *tokenPool) trim(now time.Time) {
	valid := p.tokens[:0]
	for _, credential := range p.tokens {
		if credential.Authorization != "" && (credential.ExpiresAt.IsZero() || now.Before(credential.ExpiresAt)) {
			valid = append(valid, credential)
		}
	}
	clear(p.tokens[len(valid):])
	p.tokens = valid
}

type managerRetry struct {
	delay time.Duration
	next  time.Time
}

func (r *managerRetry) fail(now time.Time, retryAfter time.Duration) time.Time {
	if r.delay == 0 {
		r.delay = time.Second
	} else {
		r.delay = min(r.delay*2, time.Minute)
	}
	r.next = now.Add(max(r.delay, retryAfter))
	return r.next
}

func (m *Manager) refillPools() {
	m.mu.Lock()
	now := time.Now()
	usable := m.ready && managerSubscriptionUsable(m.subscription, now)
	needed := false
	for _, pool := range m.pools {
		pool.trim(now)
		needed = needed || len(pool.tokens) <= m.options.TokenTarget/2
	}
	m.mu.Unlock()
	if !usable || !needed || m.ctx.Err() != nil {
		return
	}
	m.mu.Lock()
	provider, providerNext := m.provider, m.providerRetry.next
	m.mu.Unlock()
	if provider == nil {
		if now.Before(providerNext) {
			return
		}
		m.options.Observer.Emit(progress.Event{Stage: "provider", Status: progress.Running, Detail: "load or provision the v3 Anisette identity"})
		var err error
		provider, err = auth.OpenProvider(m.ctx, m.options.StateDir, m.options.ServerURL)
		if m.ctx.Err() != nil {
			return
		}
		if err != nil {
			m.mu.Lock()
			next := m.providerRetry.fail(time.Now(), 0)
			m.recordFailureLocked("provider", "provider", err)
			m.mu.Unlock()
			m.logf("Anisette provider unavailable; retry in %s: %v", time.Until(next).Round(time.Second), err)
			m.options.Observer.Emit(progress.Event{Stage: "provider", Status: progress.Retry, Detail: fmt.Sprintf("retry in %s", time.Until(next).Round(time.Second)), Err: err})
			return
		}
		m.mu.Lock()
		m.provider, m.providerRetry = provider, managerRetry{}
		m.clearFailureLocked("provider")
		m.mu.Unlock()
		m.options.Observer.Emit(progress.Event{Stage: "provider", Status: progress.Info, Detail: "v3 identity loaded"})
	}
	m.mu.Lock()
	ids := m.activePoolIDsLocked()
	m.mu.Unlock()
	for _, id := range ids {
		m.mu.Lock()
		pool := m.pools[id]
		now := time.Now()
		if pool == nil || !managerSubscriptionUsable(m.subscription, now) {
			m.mu.Unlock()
			continue
		}
		pool.trim(now)
		if len(pool.tokens) > m.options.TokenTarget/2 || now.Before(pool.retry.next) {
			m.mu.Unlock()
			continue
		}
		count := m.options.TokenTarget - len(pool.tokens)
		configuration, subscription, scope, proxy := m.configuration, m.subscription, m.scope, pool.proxy
		m.mu.Unlock()
		tokens, err := issueTokens(m.ctx, m.client, provider, configuration, proxy, subscription.AccessToken, subscription.Tier, m.options.ClientInfo, count, m.logf, m.options.Observer)
		if m.ctx.Err() != nil {
			return
		}
		if err == nil {
			valid := tokens[:0]
			now := time.Now()
			for _, token := range tokens {
				if token.Authorization != "" && (token.ExpiresAt.IsZero() || now.Before(token.ExpiresAt)) {
					valid = append(valid, token)
				}
			}
			tokens = valid
			if len(tokens) == 0 {
				err = errors.New("issuer returned no usable, unexpired tokens")
			}
		}
		m.mu.Lock()
		if m.pools[id] != pool || m.scope != scope {
			m.mu.Unlock()
			continue
		}
		if err != nil {
			var issueError *IssuanceError
			var retryAfter time.Duration
			authFailure := false
			if errors.As(err, &issueError) {
				retryAfter = issueError.RetryAfter
				authFailure = issueError.StatusCode == 401 || issueError.StatusCode == 403
			}
			next := pool.retry.fail(time.Now(), retryAfter)
			m.recordFailureLocked("tokens:"+id, "tokens:"+proxy.Name, err)
			if authFailure {
				m.subscriptionForce, m.configurationForce = true, true
			}
			remaining := len(pool.tokens)
			m.mu.Unlock()
			m.logf("%s token refill failed; %d tokens remain, retry in %s: %v", proxy.Name, remaining, time.Until(next).Round(time.Second), err)
			m.options.Observer.Emit(progress.Event{Stage: "tokens", Hop: proxy.Name, Status: progress.Retry, Detail: fmt.Sprintf("%d tokens remain; retry in %s", remaining, time.Until(next).Round(time.Second)), Err: err})
			if authFailure {
				return
			}
			continue
		}
		pool.tokens = append(pool.tokens, tokens...)
		pool.trim(time.Now())
		pool.retry = managerRetry{}
		m.clearFailureLocked("tokens:" + id)
		m.notifyLocked()
		remaining := len(pool.tokens)
		m.mu.Unlock()
		m.logf("%s token pool replenished: %d unused", proxy.Name, remaining)
		m.options.Observer.Emit(progress.Event{Stage: "tokens", Hop: proxy.Name, Status: progress.OK, Detail: fmt.Sprintf("%d unused tokens available", remaining)})
	}
}

func (m *Manager) nextDelayLocked(now time.Time) time.Duration {
	subscriptionNext := m.subscriptionNext
	if m.subscriptionForce {
		subscriptionNext = minTime(subscriptionNext, m.subscriptionRetry.next)
	}
	if m.terminal != nil {
		return max(subscriptionNext.Sub(now), 0)
	}
	configurationNext := m.configurationNext
	if m.configurationForce {
		configurationNext = minTime(configurationNext, m.configurationRetry.next)
	}
	next := minTime(subscriptionNext, configurationNext)
	canIssue := m.ready && managerSubscriptionUsable(m.subscription, now)
	for _, pool := range m.pools {
		pool.trim(now)
		for _, token := range pool.tokens {
			if !token.ExpiresAt.IsZero() {
				next = minTime(next, token.ExpiresAt)
			}
		}
		if canIssue && len(pool.tokens) <= m.options.TokenTarget/2 {
			refill := pool.retry.next
			if m.provider == nil && m.providerRetry.next.After(refill) {
				refill = m.providerRetry.next
			}
			next = minTime(next, refill)
		}
	}
	return max(next.Sub(now), 0)
}

// A zero timestamp means the work has not run yet and is due immediately.
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
