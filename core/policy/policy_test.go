package policy

import (
	"testing"
	"time"

	"github.com/agents-first/clawdchan/core/envelope"
	"github.com/agents-first/clawdchan/core/identity"
	"github.com/agents-first/clawdchan/core/pairing"
)

func askHuman() envelope.Envelope {
	return envelope.Envelope{Intent: envelope.IntentAskHuman}
}

func peer(trust pairing.Trust) pairing.Peer {
	return pairing.Peer{NodeID: identity.NodeID{1, 2, 3}, Trust: trust}
}

func TestRevokedAlwaysDenied(t *testing.T) {
	e := Default()
	if got := e.Evaluate(askHuman(), peer(pairing.TrustRevoked)); got != Deny {
		t.Fatalf("revoked peer: got %v, want Deny", got)
	}
}

func TestDefaultAllowsAsk(t *testing.T) {
	e := Default()
	if got := e.Evaluate(askHuman(), peer(pairing.TrustPaired)); got != Allow {
		t.Fatalf("default engine: got %v, want Allow", got)
	}
}

func TestAllowlistDowngradesUnlisted(t *testing.T) {
	e := New(Config{AskHumanAllowlist: map[identity.NodeID]bool{}})
	if got := e.Evaluate(askHuman(), peer(pairing.TrustPaired)); got != Downgrade {
		t.Fatalf("unlisted peer: got %v, want Downgrade", got)
	}
}

func TestQuietHoursContains(t *testing.T) {
	at := func(h int) time.Time { return time.Date(2026, 6, 20, h, 30, 0, 0, time.UTC) }
	cases := []struct {
		name string
		q    QuietHours
		hour int
		want bool
	}{
		{"daytime window inside", QuietHours{9, 17}, 12, true},
		{"daytime window before", QuietHours{9, 17}, 8, false},
		{"daytime window at end is excluded", QuietHours{9, 17}, 17, false},
		{"daytime window at start is included", QuietHours{9, 17}, 9, true},
		{"overnight before midnight", QuietHours{22, 7}, 23, true},
		{"overnight after midnight", QuietHours{22, 7}, 3, true},
		{"overnight outside", QuietHours{22, 7}, 12, false},
		{"overnight at end excluded", QuietHours{22, 7}, 7, false},
		{"empty window never matches", QuietHours{0, 0}, 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.q.Contains(at(c.hour)); got != c.want {
				t.Fatalf("Contains(hour=%d) = %v, want %v", c.hour, got, c.want)
			}
		})
	}
}

func TestQuietHoursDowngradesAsk(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 20, 2, 0, 0, 0, time.UTC) }
	e := New(Config{QuietHours: &QuietHours{22, 7}, Now: now})
	if got := e.Evaluate(askHuman(), peer(pairing.TrustPaired)); got != Downgrade {
		t.Fatalf("ask during quiet hours: got %v, want Downgrade", got)
	}
}

func TestQuietHoursAllowsOutsideWindow(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC) }
	e := New(Config{QuietHours: &QuietHours{22, 7}, Now: now})
	if got := e.Evaluate(askHuman(), peer(pairing.TrustPaired)); got != Allow {
		t.Fatalf("ask outside quiet hours: got %v, want Allow", got)
	}
}

// Quiet hours must never loosen an allowlist Deny into a wake-up.
func TestQuietHoursDoesNotLoosenDeny(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 20, 2, 0, 0, 0, time.UTC) }
	e := New(Config{
		AskHumanAllowlist:  map[identity.NodeID]bool{},
		DefaultAskBehavior: Deny,
		QuietHours:         &QuietHours{22, 7},
		Now:                now,
	})
	if got := e.Evaluate(askHuman(), peer(pairing.TrustPaired)); got != Deny {
		t.Fatalf("denied peer during quiet hours: got %v, want Deny", got)
	}
}

// Quiet hours apply only to AskHuman; other intents pass through.
func TestQuietHoursIgnoresNonAsk(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 20, 2, 0, 0, 0, time.UTC) }
	e := New(Config{QuietHours: &QuietHours{22, 7}, Now: now})
	env := envelope.Envelope{Intent: envelope.IntentNotifyHuman}
	if got := e.Evaluate(env, peer(pairing.TrustPaired)); got != Allow {
		t.Fatalf("notify during quiet hours: got %v, want Allow", got)
	}
}
