package engine

import (
	"sort"
	"strings"
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
	PrincipalKinds        []string
	AgentApprovalRequired bool
}
type Scope struct {
	Kind               string
	Anchor             string
	IncludeDescendants bool
}
type Request struct {
	MemberID      string
	PrincipalType string
	Permission    string
	ResourceSpace string
	ResourceGroup string
	ResourceOwner string
	Assignments   []Assignment
	Owner         *Request
	ApprovalValid bool
	SelfOwners    []string
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
	for _, a := range in.Assignments {
		if a.MemberID != in.MemberID {
			continue
		}
		if !contains(a.Permissions, in.Permission) {
			continue
		}
		if in.PrincipalType != "" && len(a.PrincipalKinds) > 0 && !contains(a.PrincipalKinds, in.PrincipalType) {
			continue
		}
		if len(a.Envelope) > 0 && !contains(a.Envelope, in.Permission) {
			continue
		}
		if !scopeContains(a.Scope, in) {
			continue
		}
		matches = append(matches, a)
	}
	if len(matches) == 0 {
		code := "missing_permission"
		for _, a := range in.Assignments {
			if a.MemberID == in.MemberID && contains(a.Permissions, in.Permission) && len(a.Envelope) > 0 && !contains(a.Envelope, in.Permission) {
				code = "ENVELOPE_EXCLUDED"
				break
			}
		}
		return Decision{Effect: Deny, Code: code, Trace: []string{"no matching assignment"}}
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].Role < matches[j].Role })
	trace := []string{"member matched", "permission matched", "scope matched"}
	if in.PrincipalType == "agent" {
		if in.Owner == nil {
			return Decision{Effect: Deny, Code: "OWNER_INACTIVE", Trace: append(trace, "owner chain missing")}
		}
		owner := Check(*in.Owner)
		if owner.Effect != Allow {
			return Decision{Effect: Deny, Code: "OWNER_ENVELOPE_EXCLUDED", Trace: append(trace, "owner envelope denied")}
		}
		for _, a := range matches {
			if a.AgentApprovalRequired && !in.ApprovalValid {
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
		return s.Anchor == in.ResourceSpace || s.IncludeDescendants && descendant(s.Anchor, in.ResourceSpace)
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
		return s.Anchor != "" && (s.Anchor == in.ResourceSpace || descendant(s.Anchor, in.ResourceSpace))
	case "group", "group_tree":
		return s.Anchor != "" && s.Anchor == in.ResourceGroup
	default:
		return false
	}
}

func descendant(anchor, resource string) bool {
	return len(resource) > len(anchor) && strings.HasPrefix(resource, anchor+"/")
}
func contains(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}
