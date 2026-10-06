package engine

import (
	"sort"
)

type Effect string

const (
	Allow Effect = "allow"
	Deny  Effect = "deny"
)

type Assignment struct {
	MemberID              string
	Role                  string
	Permissions           []string
	Scope                 Scope
	Envelope              []string
	EnvelopeEnforced      bool
	PrincipalKinds        []string
	AgentApprovalRequired bool
}
type Scope struct {
	Kind               string
	Anchor             string
	IncludeDescendants bool
}
type Request struct {
	MemberID               string
	PrincipalType          string
	Permission             string
	ResourceSpace          string
	ResourceSpaceAncestors []string
	ResourceGroup          string
	ResourceGroupAncestors []string
	ResourceOwner          string
	Assignments            []Assignment
	Owner                  *Request
	ApprovalValid          bool
	// SkipApproval is used only while evaluating an Agent's owner envelope.
	// Approval belongs to the acting Agent request and must not make an
	// otherwise valid owner permission disappear from the envelope.
	SkipApproval bool
	SelfOwners   []string
}
type Decision struct {
	Effect Effect   `json:"effect"`
	Code   string   `json:"code"`
	Trace  []string `json:"trace"`
}

func Check(in Request) Decision {
	if in.MemberID == "" || in.Permission == "" {
		return Decision{Effect: Deny, Code: "invalid_subject", Trace: []string{"missing subject or permission"}}
	}
	matches := []Assignment{}
	sawPermission := false
	sawPrincipalKind := false
	sawEnvelope := false
	sawScope := false
	for _, a := range in.Assignments {
		if a.MemberID != in.MemberID {
			continue
		}
		if !contains(a.Permissions, in.Permission) {
			continue
		}
		sawPermission = true
		if in.PrincipalType != "" && len(a.PrincipalKinds) > 0 && !contains(a.PrincipalKinds, in.PrincipalType) {
			sawPrincipalKind = true
			continue
		}
		if (a.EnvelopeEnforced || len(a.Envelope) > 0) && !contains(a.Envelope, in.Permission) {
			sawEnvelope = true
			continue
		}
		if !scopeContains(a.Scope, in) {
			sawScope = true
			continue
		}
		matches = append(matches, a)
	}
	if len(matches) == 0 {
		code := "NO_MATCHING_PERMISSION"
		switch {
		case sawPrincipalKind:
			code = "PRINCIPAL_KIND_NOT_ALLOWED"
		case sawEnvelope:
			code = "ENVELOPE_EXCLUDED"
		case sawScope:
			code = "SCOPE_OUT_OF_BOUNDS"
		case !sawPermission:
			code = "NO_MATCHING_PERMISSION"
		}
		return Decision{Effect: Deny, Code: code, Trace: []string{"no matching assignment"}}
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].Role < matches[j].Role })
	trace := []string{"member matched", "permission matched", "scope matched"}
	if in.PrincipalType == "agent" {
		if in.Owner == nil {
			return Decision{Effect: Deny, Code: "OWNER_INACTIVE", Trace: append(trace, "owner chain missing")}
		}
		ownerRequest := *in.Owner
		ownerRequest.SkipApproval = true
		owner := Check(ownerRequest)
		if owner.Effect != Allow {
			if owner.Code == "OWNER_INACTIVE" {
				return Decision{Effect: Deny, Code: "OWNER_INACTIVE", Trace: append(trace, "owner chain inactive")}
			}
			return Decision{Effect: Deny, Code: "OWNER_ENVELOPE_EXCLUDED", Trace: append(trace, "owner envelope denied")}
		}
		for _, a := range matches {
			if a.AgentApprovalRequired && !in.ApprovalValid && !in.SkipApproval {
				return Decision{Effect: Deny, Code: "APPROVAL_REQUIRED", Trace: append(trace, "human approval required")}
			}
		}
	}
	return Decision{Effect: Allow, Code: "allowed", Trace: trace}
}
func scopeContains(s Scope, in Request) bool {
	if s.Kind == "" {
		if s.Anchor == "" {
			return false
		}
		return s.Anchor == in.ResourceSpace || s.IncludeDescendants && contains(in.ResourceSpaceAncestors, s.Anchor)
	}
	switch s.Kind {
	case "global":
		return true
	case "self":
		if in.ResourceOwner == "" {
			return false
		}
		if in.ResourceOwner == in.MemberID {
			return true
		}
		return contains(in.SelfOwners, in.ResourceOwner)
	case "space":
		return s.Anchor != "" && s.Anchor == in.ResourceSpace
	case "space_tree":
		return s.Anchor != "" && (s.Anchor == in.ResourceSpace || contains(in.ResourceSpaceAncestors, s.Anchor))
	case "group":
		return s.Anchor != "" && s.Anchor == in.ResourceGroup
	case "group_tree":
		return s.Anchor != "" && (s.Anchor == in.ResourceGroup || contains(in.ResourceGroupAncestors, s.Anchor))
	default:
		return false
	}
}

func contains(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}
