// Package policy is the small local gate applied before invoking the
// HumanSurface. It prevents a remote agent from dictating how or when the
// local human is interrupted.
package policy

import (
	"time"

	"github.com/agents-first/clawdchan/core/envelope"
	"github.com/agents-first/clawdchan/core/identity"
	"github.com/agents-first/clawdchan/core/pairing"
)

// Decision is the policy output for an incoming envelope.
type Decision uint8

const (
	// Allow delivers the envelope as intended.
	Allow Decision = 1
	// Downgrade turns an AskHuman into a NotifyHuman (stored, not blocking).
	Downgrade Decision = 2
	// Deny drops the envelope without side effects.
	Deny Decision = 3
)

// Config is the user-editable policy.
type Config struct {
	// AskHumanAllowlist limits which peers can trigger AskHuman; nil allows
	// all paired peers. Revoked peers are always denied regardless.
	AskHumanAllowlist map[identity.NodeID]bool
	// DefaultAskBehavior is applied when a peer is not in AskHumanAllowlist.
	// Zero value defaults to Downgrade.
	DefaultAskBehavior Decision
	// QuietHours, when non-nil, downgrades an otherwise-allowed AskHuman to
	// NotifyHuman during the configured nightly window so a remote peer can't
	// interrupt the human while they're asleep. It only ever softens an
	// Allow — it never loosens a Deny or Downgrade into a wake-up.
	QuietHours *QuietHours
	// Now returns the wall-clock time used to evaluate QuietHours. nil uses
	// time.Now; tests pin it to a fixed instant.
	Now func() time.Time
}

// QuietHours is a daily local-time window during which AskHuman intents are
// downgraded to NotifyHuman. StartHour and EndHour are hours in [0,24) in the
// local timezone and define the half-open window [StartHour, EndHour). When
// StartHour > EndHour the window wraps past midnight (e.g. {22, 7} covers
// 22:00–06:59). StartHour == EndHour is an empty window (quiet hours off).
type QuietHours struct {
	StartHour int
	EndHour   int
}

// Contains reports whether t's hour falls inside the quiet window.
func (q QuietHours) Contains(t time.Time) bool {
	if q.StartHour == q.EndHour {
		return false
	}
	h := t.Hour()
	if q.StartHour < q.EndHour {
		return h >= q.StartHour && h < q.EndHour
	}
	// Wraps past midnight.
	return h >= q.StartHour || h < q.EndHour
}

// Engine evaluates Decisions for incoming envelopes.
type Engine interface {
	Evaluate(env envelope.Envelope, peer pairing.Peer) Decision
}

type engine struct{ cfg Config }

// New returns an Engine that applies cfg.
func New(cfg Config) Engine { return &engine{cfg: cfg} }

// Default is a permissive engine useful for tests and initial deployments.
// It allows all envelopes from non-revoked peers.
func Default() Engine { return &engine{} }

func (e *engine) Evaluate(env envelope.Envelope, peer pairing.Peer) Decision {
	if peer.Trust == pairing.TrustRevoked {
		return Deny
	}
	if env.Intent == envelope.IntentAskHuman {
		base := e.askHumanBase(peer)
		// Quiet hours only soften an otherwise-allowed wake-up; they never
		// upgrade a Deny or Downgrade into one.
		if base == Allow && e.inQuietHours() {
			return Downgrade
		}
		return base
	}
	return Allow
}

// askHumanBase resolves the allowlist decision for an AskHuman, ignoring
// quiet hours.
func (e *engine) askHumanBase(peer pairing.Peer) Decision {
	if e.cfg.AskHumanAllowlist == nil {
		return Allow
	}
	if e.cfg.AskHumanAllowlist[peer.NodeID] {
		return Allow
	}
	if e.cfg.DefaultAskBehavior != 0 {
		return e.cfg.DefaultAskBehavior
	}
	return Downgrade
}

// inQuietHours reports whether the current time falls in the configured
// quiet window.
func (e *engine) inQuietHours() bool {
	if e.cfg.QuietHours == nil {
		return false
	}
	now := time.Now
	if e.cfg.Now != nil {
		now = e.cfg.Now
	}
	return e.cfg.QuietHours.Contains(now())
}
