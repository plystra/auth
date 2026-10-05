package engine

import "sort"

type Effect string

const (
	Allow Effect = "allow"
	Deny  Effect = "deny"
)

type Assignment struct {
	MemberID    string
	Role        string
	Permissions []string
	Scope       Scope
	Envelope    []string
}
type Scope struct {
	Anchor             string
	IncludeDescendants bool
}
type Request struct {
	MemberID      string
	Permission    string
	ResourceSpace string
	ResourceOwner string
	Assignments   []Assignment
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
		if !scopeContains(a.Scope, in.ResourceSpace) {
			continue
		}
		matches = append(matches, a)
	}
	if len(matches) == 0 {
		return Decision{Effect: Deny, Code: "missing_permission", Trace: []string{"no matching assignment"}}
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].Role < matches[j].Role })
	trace := []string{"member matched", "permission matched", "scope matched"}
	return Decision{Effect: Allow, Code: "allowed", Trace: trace}
}
func scopeContains(s Scope, resource string) bool {
	if s.Anchor == "" {
		return false
	}
	return s.Anchor == resource || s.IncludeDescendants && len(resource) > len(s.Anchor) && resource[:len(s.Anchor)] == s.Anchor && resource[len(s.Anchor)] == '/'
}
func contains(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}
