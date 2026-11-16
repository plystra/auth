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
	// TokenScopes can only constrain persisted authority. Nil is unrestricted;
	// a non-nil empty list represents a credential with no usable permissions.
	TokenScopes []string
	// SkipApproval is used only while evaluating an Agent's owner envelope.
	// Approval belongs to the acting Agent request and must not make an
	// otherwise valid owner permission disappear from the envelope.
	SkipApproval bool
	SelfOwners   []string
}
type Decision struct {
	Effect Effect      `json:"effect"`
	Code   string      `json:"code"`
	Trace  []TraceStep `json:"trace"`
}

func Check(in Request) Decision {
	if in.MemberID == "" || in.Permission == "" {
		return Reject("INVALID_SUBJECT")
	}
	trace := []TraceStep{Passed("subject_input", "subject identity and permission are present")}
	if in.TokenScopes != nil && !contains(in.TokenScopes, in.Permission) {
		return Reject("TOKEN_SCOPE_EXCLUDED", trace...)
	}
	if in.TokenScopes != nil {
		trace = append(trace, Passed("token_scope", "the delegated token scope includes the permission"))
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
		trace = append(trace, assignmentTrace(code)...)
		return Reject(code, trace...)
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].Role < matches[j].Role })
	trace = append(trace, assignmentTrace("")...)
	if in.PrincipalType == "agent" {
		if in.Owner == nil {
			return Reject("OWNER_INACTIVE", trace...)
		}
		ownerRequest := *in.Owner
		ownerRequest.SkipApproval = true
		owner := Check(ownerRequest)
		for _, step := range owner.Trace {
			step.Step = "owner." + step.Step
			trace = append(trace, step)
		}
		if owner.Effect != Allow {
			if owner.Code == "OWNER_INACTIVE" {
				return Reject("OWNER_INACTIVE", trace...)
			}
			return Reject("OWNER_ENVELOPE_EXCLUDED", trace...)
		}
		trace = append(trace, Passed("owner_envelope", "every owner is allowed the same permission on the resource"))
		requiresApproval := false
		for _, a := range matches {
			requiresApproval = requiresApproval || a.AgentApprovalRequired
		}
		if !in.SkipApproval && requiresApproval {
			if !in.ApprovalValid {
				return Reject("APPROVAL_REQUIRED", trace...)
			}
			trace = append(trace, Passed("approval", "a persisted approval authorizes this request"))
		}
	}
	return Decision{Effect: Allow, Code: "allowed", Trace: trace}
}

func assignmentTrace(failure string) []TraceStep {
	var trace []TraceStep
	for _, condition := range []struct{ step, code, detail string }{
		{"permission", "NO_MATCHING_PERMISSION", "a subject assignment includes the permission"},
		{"principal_kind", "PRINCIPAL_KIND_NOT_ALLOWED", "the permission allows this principal type"},
		{"envelope", "ENVELOPE_EXCLUDED", "the permission is included in the assignment's effective envelope"},
		{"scope", "SCOPE_OUT_OF_BOUNDS", "the assignment scope covers the resource"},
	} {
		if failure == condition.code {
			break
		}
		trace = append(trace, Passed(condition.step, condition.detail))
	}
	return trace
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
