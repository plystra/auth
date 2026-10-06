package delta

import (
	"errors"
	"slices"
	"strings"
)

type NodeKind string

const (
	Space NodeKind = "space"
	Group NodeKind = "group"
)

type Node struct {
	Kind NodeKind
	ID   string
}

type ScopeKind string

const (
	Self      ScopeKind = "self"
	GroupOnly ScopeKind = "group"
	GroupTree ScopeKind = "group_tree"
	SpaceOnly ScopeKind = "space"
	SpaceTree ScopeKind = "space_tree"
	Global    ScopeKind = "global"
)

type Scope struct {
	Kind   ScopeKind
	Anchor string
}

// Snapshots contain effective authority after directory, envelope, owner,
// status, and expiry rules have been applied by the domain layer.
type Permission struct {
	Subject  string
	Position Node
	Key      string
	Scope    Scope
}

type Right struct {
	Holder      string
	Position    Node
	Permissions []string
	Anchor      Node
	Descendants bool
	Delegate    bool
}

type Snapshot struct {
	Permissions []Permission
	Rights      []Right
}

type Result struct {
	Permissions []Permission
	Rights      []Right
}

// Graph is the persisted Space and group ancestry used for coverage checks.
// Missing Space parents denote roots. Referenced groups require GroupSpace.
type Graph struct {
	SpaceParent map[string]string
	GroupParent map[string]string
	GroupSpace  map[string]string
}

// Evaluate returns the positive authority delta. Subjects may represent one
// member or a group cohort, so evaluation does not expand grants to members.
func Evaluate(before, after Snapshot, graph Graph) (Result, error) {
	previousPermissions, err := normalizePermissions(before.Permissions)
	if err != nil {
		return Result{}, err
	}
	nextPermissions, err := normalizePermissions(after.Permissions)
	if err != nil {
		return Result{}, err
	}
	previousRights, err := normalizeRights(before.Rights)
	if err != nil {
		return Result{}, err
	}
	nextRights, err := normalizeRights(after.Rights)
	if err != nil {
		return Result{}, err
	}
	result := Result{Permissions: []Permission{}, Rights: []Right{}}
	for _, candidate := range nextPermissions {
		covered, err := permissionCovered(candidate, previousPermissions, graph)
		if err != nil {
			return Result{}, err
		}
		if !covered {
			result.Permissions = append(result.Permissions, candidate)
		}
	}
	for _, candidate := range nextRights {
		covered, err := rightCovered(candidate, previousRights, graph)
		if err != nil {
			return Result{}, err
		}
		if !covered {
			result.Rights = append(result.Rights, candidate)
		}
	}
	return result, nil
}

func permissionCovered(candidate Permission, previous []Permission, graph Graph) (bool, error) {
	for _, old := range previous {
		covered, err := permissionContains(old, candidate, graph)
		if err != nil || covered {
			return covered, err
		}
	}
	return false, nil
}

func permissionContains(a, b Permission, graph Graph) (bool, error) {
	if a.Subject != b.Subject || a.Position != b.Position || a.Key != b.Key {
		return false, nil
	}
	return scopeContains(a.Scope, b.Scope, graph)
}

func rightCovered(candidate Right, previous []Right, graph Graph) (bool, error) {
	for _, old := range previous {
		covered, err := rightContains(old, candidate, graph)
		if err != nil || covered {
			return covered, err
		}
	}
	return false, nil
}

func rightContains(a, b Right, graph Graph) (bool, error) {
	if a.Holder != b.Holder || a.Position != b.Position || b.Delegate && !a.Delegate || b.Descendants && !a.Descendants {
		return false, nil
	}
	for _, permission := range b.Permissions {
		if !slices.Contains(a.Permissions, permission) {
			return false, nil
		}
	}
	return nodeContains(a.Anchor, a.Descendants, b.Anchor, graph)
}

func scopeContains(a, b Scope, graph Graph) (bool, error) {
	if a.Kind == Global {
		return true, nil
	}
	if b.Kind == Global {
		return false, nil
	}
	if a.Kind == Self || b.Kind == Self {
		return a.Kind == Self && b.Kind == Self, nil
	}
	switch a.Kind {
	case SpaceOnly, SpaceTree:
		var targetSpace string
		switch b.Kind {
		case SpaceOnly, SpaceTree:
			targetSpace = b.Anchor
		case GroupOnly, GroupTree:
			var ok bool
			targetSpace, ok = graph.GroupSpace[b.Anchor]
			if !ok || targetSpace == "" {
				return false, errors.New("group scope is missing its Space")
			}
		default:
			return false, errors.New("invalid permission scope")
		}
		if a.Anchor == targetSpace {
			return a.Kind == SpaceTree || b.Kind != SpaceTree, nil
		}
		if a.Kind == SpaceTree {
			return graph.spaceAncestor(a.Anchor, targetSpace)
		}
		return false, nil
	case GroupOnly, GroupTree:
		if b.Kind != GroupOnly && b.Kind != GroupTree {
			return false, nil
		}
		if a.Anchor == b.Anchor {
			return a.Kind == GroupTree || b.Kind == GroupOnly, nil
		}
		if a.Kind == GroupTree {
			return graph.groupAncestor(a.Anchor, b.Anchor)
		}
		return false, nil
	default:
		return false, errors.New("invalid permission scope")
	}
}

func nodeContains(anchor Node, descendants bool, target Node, graph Graph) (bool, error) {
	if anchor == target {
		return true, nil
	}
	if !descendants {
		return false, nil
	}
	switch anchor.Kind {
	case Space:
		if target.Kind == Space {
			return graph.spaceAncestor(anchor.ID, target.ID)
		}
		if target.Kind == Group {
			spaceID, ok := graph.GroupSpace[target.ID]
			if !ok || spaceID == "" {
				return false, errors.New("group node is missing its Space")
			}
			if anchor.ID == spaceID {
				return true, nil
			}
			return graph.spaceAncestor(anchor.ID, spaceID)
		}
	case Group:
		if target.Kind == Group {
			return graph.groupAncestor(anchor.ID, target.ID)
		}
	}
	return false, nil
}

func (g Graph) spaceAncestor(ancestor, descendant string) (bool, error) {
	seen := map[string]struct{}{}
	for current := descendant; current != ""; current = g.SpaceParent[current] {
		if current == ancestor {
			return true, nil
		}
		if _, ok := seen[current]; ok {
			return false, errors.New("space hierarchy contains a cycle")
		}
		seen[current] = struct{}{}
	}
	return false, nil
}

func (g Graph) groupAncestor(ancestor, descendant string) (bool, error) {
	spaceID, ok := g.GroupSpace[descendant]
	if !ok || spaceID == "" || g.GroupSpace[ancestor] != spaceID {
		return false, errors.New("group hierarchy crosses or lacks a Space")
	}
	seen := map[string]struct{}{}
	for current := descendant; current != ""; current = g.GroupParent[current] {
		if current == ancestor {
			return true, nil
		}
		if _, ok := seen[current]; ok {
			return false, errors.New("group hierarchy contains a cycle")
		}
		if g.GroupSpace[current] != spaceID {
			return false, errors.New("group hierarchy crosses a Space")
		}
		seen[current] = struct{}{}
	}
	return false, nil
}

func normalizePermissions(in []Permission) ([]Permission, error) {
	seen := map[Permission]struct{}{}
	out := make([]Permission, 0, len(in))
	for _, item := range in {
		if item.Subject == "" || item.Key == "" || !validNode(item.Position) || !validScope(item.Scope) {
			return nil, errors.New("invalid effective permission tuple")
		}
		if _, ok := seen[item]; !ok {
			seen[item] = struct{}{}
			out = append(out, item)
		}
	}
	slices.SortFunc(out, func(a, b Permission) int {
		return strings.Compare(permissionKey(a), permissionKey(b))
	})
	return out, nil
}

func normalizeRights(in []Right) ([]Right, error) {
	out := make([]Right, 0, len(in))
	seen := map[string]struct{}{}
	for _, item := range in {
		if item.Holder == "" || !validNode(item.Position) || !validNode(item.Anchor) {
			return nil, errors.New("invalid effective assignment right tuple")
		}
		item.Permissions = slices.Clone(item.Permissions)
		slices.Sort(item.Permissions)
		item.Permissions = slices.Compact(item.Permissions)
		if len(item.Permissions) == 0 || item.Permissions[0] == "" {
			return nil, errors.New("assignment right needs permissions")
		}
		key := rightKey(item)
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			out = append(out, item)
		}
	}
	slices.SortFunc(out, func(a, b Right) int {
		return strings.Compare(rightKey(a), rightKey(b))
	})
	return out, nil
}

func validNode(node Node) bool {
	return node.ID != "" && (node.Kind == Space || node.Kind == Group)
}

func validScope(scope Scope) bool {
	switch scope.Kind {
	case Self, Global:
		return scope.Anchor == ""
	case SpaceOnly, SpaceTree, GroupOnly, GroupTree:
		return scope.Anchor != ""
	default:
		return false
	}
}

func permissionKey(item Permission) string {
	return strings.Join([]string{item.Subject, string(item.Position.Kind), item.Position.ID, item.Key, string(item.Scope.Kind), item.Scope.Anchor}, "\x00")
}

func rightKey(item Right) string {
	flags := "00"
	if item.Descendants {
		flags = "10"
	}
	if item.Delegate {
		flags = flags[:1] + "1"
	}
	return strings.Join([]string{item.Holder, string(item.Position.Kind), item.Position.ID, string(item.Anchor.Kind), item.Anchor.ID, flags, strings.Join(item.Permissions, "\x00")}, "\x00")
}
