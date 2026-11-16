package authorization

import (
	"strconv"
	"strings"
	"sync"

	"github.com/plystra/auth/internal/authz/engine"
)

const authorizationCacheCapacity = 4096

type decisionCache struct {
	mu      sync.RWMutex
	entries map[string]cachedDecision
}

type cachedDecision struct {
	decision      engine.Decision
	policyVersion int64
}

func newDecisionCache() *decisionCache {
	return &decisionCache{entries: make(map[string]cachedDecision, authorizationCacheCapacity)}
}

func (c *decisionCache) get(key string) (engine.Decision, int64, bool) {
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok {
		return engine.Decision{}, 0, false
	}
	return cloneDecision(entry.decision), entry.policyVersion, true
}

func (c *decisionCache) put(key string, decision engine.Decision, policyVersion int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= authorizationCacheCapacity {
		for oldest := range c.entries {
			delete(c.entries, oldest)
			break
		}
	}
	c.entries[key] = cachedDecision{decision: cloneDecision(decision), policyVersion: policyVersion}
}

func (c *decisionCache) clear() {
	c.mu.Lock()
	c.entries = make(map[string]cachedDecision, authorizationCacheCapacity)
	c.mu.Unlock()
}

func cloneDecision(in engine.Decision) engine.Decision {
	out := in
	out.Trace = append([]string(nil), in.Trace...)
	return out
}

// authorizationCacheKey contains only non-secret identity and version facts.
// It is never logged or returned to callers. Every version is read from the
// same database snapshot as the authorization facts before a cache lookup.
func authorizationCacheKey(in CheckRequest, catalogVersion int64, spaceVersions []versionFact, memberVersions []versionFact) string {
	var b strings.Builder
	b.WriteString(in.MemberID)
	b.WriteByte(0)
	b.WriteString(in.Permission)
	b.WriteByte(0)
	b.WriteString(in.ResourceSpace)
	b.WriteByte(0)
	b.WriteString(in.ResourceGroup)
	b.WriteByte(0)
	b.WriteString(in.ResourceOwner)
	b.WriteString("\x00token_scopes:")
	if in.TokenScopes == nil {
		b.WriteString("unrestricted")
	} else {
		for _, key := range uniqueSorted(in.TokenScopes) {
			b.WriteString(strconv.Quote(key))
			b.WriteByte(',')
		}
	}
	b.WriteString("\x00catalog:")
	b.WriteString(strconv.FormatInt(catalogVersion, 10))
	b.WriteString("\x00spaces:")
	appendVersionFacts(&b, spaceVersions)
	b.WriteString("\x00members:")
	appendVersionFacts(&b, memberVersions)
	return b.String()
}

type versionFact struct {
	id      string
	version int64
}

func appendVersionFacts(b *strings.Builder, facts []versionFact) {
	for _, fact := range facts {
		b.WriteString(fact.id)
		b.WriteByte('=')
		b.WriteString(strconv.FormatInt(fact.version, 10))
		b.WriteByte(',')
	}
}
