package delta

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/plystra/auth/internal/authz/engine"
	"pgregory.net/rapid"
)

func TestEvaluatePermissionCoverageAcrossScopeKinds(t *testing.T) {
	graph := Graph{
		SpaceParent: map[string]string{"spc_child": "spc_root", "spc_other": ""},
		GroupParent: map[string]string{"grp_child": "grp_root"},
		GroupSpace:  map[string]string{"grp_root": "spc_root", "grp_child": "spc_root", "grp_other": "spc_other"},
	}
	position := Node{Kind: Space, ID: "spc_root"}
	permission := func(kind ScopeKind, anchor string) Permission {
		return Permission{Subject: "mem_actor", Position: position, Key: "document:read", Scope: Scope{Kind: kind, Anchor: anchor}}
	}
	tests := []struct {
		name   string
		before Permission
		after  Permission
		new    bool
	}{
		{"same scope", permission(SpaceOnly, "spc_root"), permission(SpaceOnly, "spc_root"), false},
		{"space tree covers descendant Space", permission(SpaceTree, "spc_root"), permission(SpaceOnly, "spc_child"), false},
		{"space does not cover Space tree", permission(SpaceOnly, "spc_root"), permission(SpaceTree, "spc_root"), true},
		{"space covers group subtree inside it", permission(SpaceOnly, "spc_root"), permission(GroupTree, "grp_root"), false},
		{"group tree covers child group", permission(GroupTree, "grp_root"), permission(GroupOnly, "grp_child"), false},
		{"group does not cover child group", permission(GroupOnly, "grp_root"), permission(GroupOnly, "grp_child"), true},
		{"global covers self", permission(Global, ""), permission(Self, ""), false},
		{"self does not cover Space", permission(Self, ""), permission(SpaceOnly, "spc_root"), true},
		{"other Space is outside subtree", permission(SpaceTree, "spc_root"), permission(SpaceOnly, "spc_other"), true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := Evaluate(Snapshot{Permissions: []Permission{test.before}}, Snapshot{Permissions: []Permission{test.after}}, graph)
			if err != nil {
				t.Fatal(err)
			}
			if (len(result.Permissions) == 1) != test.new {
				t.Fatalf("delta = %+v, want new=%v", result, test.new)
			}
		})
	}
	other := permission(SpaceOnly, "spc_root")
	other.Subject = "mem_other"
	result, err := Evaluate(Snapshot{Permissions: []Permission{permission(SpaceOnly, "spc_root")}}, Snapshot{Permissions: []Permission{other}}, graph)
	if err != nil || len(result.Permissions) != 1 {
		t.Fatalf("different subject delta = %+v, %v", result, err)
	}
}

func BenchmarkEvaluateAuthorityDeltaByTupleCount(b *testing.B) {
	for _, count := range []int{8, 64, 512} {
		before := Snapshot{Permissions: make([]Permission, count)}
		after := Snapshot{Permissions: make([]Permission, count*2)}
		for i := 0; i < count; i++ {
			position := Node{Kind: Space, ID: "spc_root"}
			before.Permissions[i] = Permission{Subject: "mem_actor", Position: position, Key: "document:read:" + strconv.Itoa(i), Scope: Scope{Kind: SpaceOnly, Anchor: "spc_root"}}
			after.Permissions[i] = before.Permissions[i]
			after.Permissions[count+i] = Permission{Subject: "mem_actor", Position: position, Key: "document:write:" + strconv.Itoa(i), Scope: Scope{Kind: SpaceOnly, Anchor: "spc_root"}}
		}
		b.Run(strconv.Itoa(count), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				result, err := Evaluate(before, after, Graph{})
				if err != nil || len(result.Permissions) != count {
					b.Fatalf("result = %d, %v; want %d permission tuples", len(result.Permissions), err, count)
				}
			}
		})
	}
}

func TestEvaluateAssignmentRightCoverage(t *testing.T) {
	graph := Graph{SpaceParent: map[string]string{"spc_child": "spc_root"}, GroupSpace: map[string]string{"grp_child": "spc_child"}}
	old := Right{
		Holder: "mem_admin", Position: Node{Kind: Space, ID: "spc_root"},
		Permissions: []string{"document:read", "document:write"}, Anchor: Node{Kind: Space, ID: "spc_root"},
		Descendants: true, Delegate: true,
	}
	covered := old
	covered.Permissions = []string{"document:read"}
	covered.Anchor = Node{Kind: Group, ID: "grp_child"}
	covered.Descendants = false
	covered.Delegate = false
	result, err := Evaluate(Snapshot{Rights: []Right{old}}, Snapshot{Rights: []Right{covered}}, graph)
	if err != nil || len(result.Rights) != 0 {
		t.Fatalf("covered assignment right = %+v, %v", result, err)
	}
	for _, change := range []func(*Right){
		func(right *Right) { right.Permissions = []string{"document:delete"} },
		func(right *Right) { right.Holder = "mem_other" },
		func(right *Right) { right.Position.ID = "spc_child" },
	} {
		candidate := covered
		change(&candidate)
		result, err := Evaluate(Snapshot{Rights: []Right{old}}, Snapshot{Rights: []Right{candidate}}, graph)
		if err != nil || len(result.Rights) != 1 {
			t.Fatalf("uncovered assignment right = %+v, %v", result, err)
		}
	}
	old.Delegate = false
	result, err = Evaluate(Snapshot{Rights: []Right{old}}, Snapshot{Rights: []Right{{
		Holder: old.Holder, Position: old.Position, Permissions: []string{"document:read"},
		Anchor: old.Anchor, Descendants: old.Descendants, Delegate: true,
	}}}, graph)
	if err != nil || len(result.Rights) != 1 {
		t.Fatalf("delegation increase = %+v, %v", result, err)
	}
	groupRight := old
	groupRight.Anchor = Node{Kind: Group, ID: "grp_child"}
	groupRight.Descendants = true
	result, err = Evaluate(Snapshot{Rights: []Right{groupRight}}, Snapshot{Rights: []Right{{
		Holder: old.Holder, Position: old.Position, Permissions: []string{"document:read"},
		Anchor: Node{Kind: Space, ID: "spc_child"},
	}}}, graph)
	if err != nil || len(result.Rights) != 1 {
		t.Fatalf("group right cannot cover a Space right = %+v, %v", result, err)
	}
}

func TestAssignmentRightCoversGrantPositionAndScope(t *testing.T) {
	graph := Graph{
		SpaceParent: map[string]string{"spc_child": "spc_root", "spc_other": ""},
		GroupParent: map[string]string{"grp_child": "grp_root"},
		GroupSpace:  map[string]string{"grp_root": "spc_root", "grp_child": "spc_root"},
	}
	right := Right{Holder: "mem_admin", Position: Node{Kind: Space, ID: "spc_root"}, Permissions: []string{"document:read"}, Anchor: Node{Kind: Space, ID: "spc_root"}, Descendants: true}
	permission := Permission{Subject: "mem_target", Position: Node{Kind: Space, ID: "spc_child"}, Key: "document:read", Scope: Scope{Kind: SpaceTree, Anchor: "spc_child"}}
	tests := []struct {
		name       string
		right      Right
		permission Permission
		want       bool
	}{
		{"ancestor Space covers child subtree", right, permission, true},
		{"right without subtree cannot cover child", func() Right { r := right; r.Descendants = false; return r }(), permission, false},
		{"unrelated Space cannot cover scope", right, func() Permission { p := permission; p.Scope.Anchor = "spc_other"; return p }(), false},
		{"different permission is not covered", right, func() Permission { p := permission; p.Key = "document:write"; return p }(), false},
		{"global cannot be assigned from a node right", right, func() Permission { p := permission; p.Scope = Scope{Kind: Global}; return p }(), false},
		{"group right covers member in group for self", Right{Permissions: right.Permissions, Anchor: Node{Kind: Group, ID: "grp_root"}, Descendants: true}, Permission{Subject: "mem_target", Position: Node{Kind: Group, ID: "grp_child"}, Key: "document:read", Scope: Scope{Kind: Self}}, true},
		{"Space right covers its grouped member without subtree", Right{Permissions: right.Permissions, Anchor: Node{Kind: Space, ID: "spc_root"}}, Permission{Subject: "mem_target", Position: Node{Kind: Group, ID: "grp_root"}, Key: "document:read", Scope: Scope{Kind: SpaceOnly, Anchor: "spc_root"}}, true},
		{"group right cannot cover Space scope", Right{Permissions: right.Permissions, Anchor: Node{Kind: Group, ID: "grp_root"}, Descendants: true}, Permission{Subject: "mem_target", Position: Node{Kind: Group, ID: "grp_child"}, Key: "document:read", Scope: Scope{Kind: SpaceOnly, Anchor: "spc_root"}}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CoversGrant(tc.right, tc.permission, graph)
			if err != nil || got != tc.want {
				t.Fatalf("coverage = %v, %v; want %v", got, err, tc.want)
			}
		})
	}
}

func TestAssignmentRightDownDelegationRequiresSubsetAndCoveredAnchor(t *testing.T) {
	graph := Graph{
		SpaceParent: map[string]string{"spc_child": "spc_root", "spc_other": ""},
		GroupSpace:  map[string]string{"grp_child": "spc_child"},
	}
	parent := Right{Holder: "mem_parent", Position: Node{Kind: Space, ID: "spc_root"}, Permissions: []string{"document:read", "document:write"}, Anchor: Node{Kind: Space, ID: "spc_root"}, Descendants: true, Delegate: true}
	covered := Right{Holder: "mem_child", Position: Node{Kind: Space, ID: "spc_child"}, Permissions: []string{"document:read"}, Anchor: Node{Kind: Space, ID: "spc_child"}, Descendants: false}
	if ok, err := CoversAssignmentRight(parent, covered, graph); err != nil || !ok {
		t.Fatalf("covered delegated right = %v, %v", ok, err)
	}
	for _, mutate := range []func(*Right){
		func(r *Right) { r.Permissions = []string{"document:delete"} },
		func(r *Right) { r.Anchor = Node{Kind: Space, ID: "spc_other"} },
	} {
		candidate := covered
		mutate(&candidate)
		if ok, err := CoversAssignmentRight(parent, candidate, graph); err != nil || ok {
			t.Fatalf("invalid delegated right = %v, %v", ok, err)
		}
	}
	parentWithoutSubtree := parent
	parentWithoutSubtree.Descendants = false
	coveredSubtree := covered
	coveredSubtree.Descendants = true
	if ok, err := CoversAssignmentRight(parentWithoutSubtree, coveredSubtree, graph); err != nil || ok {
		t.Fatalf("parent without subtree coverage = %v, %v", ok, err)
	}
	parent.Delegate = false
	if ok, err := CoversAssignmentRight(parent, covered, graph); err != nil || ok {
		t.Fatalf("non-delegable parent = %v, %v", ok, err)
	}
}

func TestEvaluateRejectsInvalidAncestry(t *testing.T) {
	position := Node{Kind: Space, ID: "spc_root"}
	permission := func(anchor string) Permission {
		return Permission{Subject: "mem_actor", Position: position, Key: "document:read", Scope: Scope{Kind: SpaceTree, Anchor: anchor}}
	}
	_, err := Evaluate(
		Snapshot{Permissions: []Permission{permission("spc_root")}},
		Snapshot{Permissions: []Permission{permission("spc_child")}},
		Graph{SpaceParent: map[string]string{"spc_child": "spc_loop", "spc_loop": "spc_child"}},
	)
	if err == nil {
		t.Fatal("cyclic Space hierarchy was accepted")
	}
}

func TestEvaluateDeduplicatesAndPreservesInputs(t *testing.T) {
	item := Permission{Subject: "mem_actor", Position: Node{Kind: Space, ID: "spc_root"}, Key: "document:read", Scope: Scope{Kind: SpaceOnly, Anchor: "spc_root"}}
	right := Right{Holder: "mem_actor", Position: item.Position, Permissions: []string{"document:write", "document:read", "document:read"}, Anchor: item.Position}
	after := Snapshot{Permissions: []Permission{item, item}, Rights: []Right{right, right}}
	result, err := Evaluate(Snapshot{}, after, Graph{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Permissions) != 1 || len(result.Rights) != 1 || !slices.Equal(result.Rights[0].Permissions, []string{"document:read", "document:write"}) {
		t.Fatalf("canonical delta = %+v", result)
	}
	if !slices.Equal(after.Rights[0].Permissions, []string{"document:write", "document:read", "document:read"}) {
		t.Fatal("Evaluate mutated its input")
	}
}

func TestEvaluateAggregatesAuthorityByTuplesWithoutMemberExpansion(t *testing.T) {
	position := Node{Kind: Group, ID: "grp_ops"}
	permission := Permission{
		Subject: "grp_ops", Position: position, Key: "document:read",
		Scope: Scope{Kind: GroupTree, Anchor: "grp_ops"},
	}
	right := Right{
		Holder: "grp_ops", Position: position, Permissions: []string{"document:read"},
		Anchor: position, Descendants: true, Delegate: true,
	}
	before := Snapshot{Permissions: []Permission{permission}, Rights: []Right{right}}
	after := Snapshot{
		Permissions: []Permission{permission, permission, {
			Subject: "grp_ops", Position: position, Key: "document:write",
			Scope: Scope{Kind: GroupOnly, Anchor: "grp_ops"},
		}},
		Rights: []Right{right, right, {
			Holder: "grp_ops", Position: position, Permissions: []string{"document:read", "document:write"},
			Anchor: position, Descendants: true, Delegate: true,
		}},
	}
	result, err := Evaluate(before, after, Graph{GroupSpace: map[string]string{"grp_ops": "spc_root"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Permissions) != 1 || result.Permissions[0].Key != "document:write" {
		t.Fatalf("permission delta = %+v, want one group tuple", result.Permissions)
	}
	if len(result.Rights) != 1 || !slices.Equal(result.Rights[0].Permissions, []string{"document:read", "document:write"}) || !result.Rights[0].Delegate {
		t.Fatalf("assignment-right delta = %+v, want one delegated tuple", result.Rights)
	}
	if result.Permissions[0].Subject != "grp_ops" || result.Rights[0].Holder != "grp_ops" {
		t.Fatalf("delta expanded a group tuple into members: %+v", result)
	}
}

func TestEvaluateScopeDeltaPreservesEveryNewEngineDecision(t *testing.T) {
	graph := Graph{
		SpaceParent: map[string]string{"spc_child": "spc_root"},
		GroupParent: map[string]string{"grp_child": "grp_root"},
		GroupSpace:  map[string]string{"grp_root": "spc_root", "grp_child": "spc_root"},
	}
	position := Node{Kind: Space, ID: "spc_root"}
	candidates := []Scope{
		{Kind: Self}, {Kind: Global},
		{Kind: SpaceOnly, Anchor: "spc_root"}, {Kind: SpaceTree, Anchor: "spc_root"},
		{Kind: SpaceOnly, Anchor: "spc_child"},
		{Kind: GroupOnly, Anchor: "grp_root"}, {Kind: GroupTree, Anchor: "grp_root"},
		{Kind: GroupOnly, Anchor: "grp_child"},
	}
	resources := []engine.Request{
		{ResourceSpace: "spc_root"},
		{ResourceSpace: "spc_child", ResourceSpaceAncestors: []string{"spc_root"}},
		{ResourceSpace: "spc_root", ResourceGroup: "grp_root"},
		{ResourceSpace: "spc_root", ResourceGroup: "grp_child", ResourceGroupAncestors: []string{"grp_root"}},
		{ResourceSpace: "spc_root", ResourceOwner: "mem_actor"},
	}
	rapid.Check(t, func(t *rapid.T) {
		beforeIndexes := rapid.SliceOfN(rapid.IntRange(0, len(candidates)-1), 0, 12).Draw(t, "before")
		afterIndexes := rapid.SliceOfN(rapid.IntRange(0, len(candidates)-1), 0, 12).Draw(t, "after")
		before := Snapshot{}
		after := Snapshot{}
		for _, index := range beforeIndexes {
			before.Permissions = append(before.Permissions, Permission{Subject: "mem_actor", Position: position, Key: "document:read", Scope: candidates[index]})
		}
		for _, index := range afterIndexes {
			after.Permissions = append(after.Permissions, Permission{Subject: "mem_actor", Position: position, Key: "document:read", Scope: candidates[index]})
		}
		result, err := Evaluate(before, after, graph)
		if err != nil {
			t.Fatal(err)
		}
		for _, resource := range resources {
			if !engineAllows(resource, after.Permissions) {
				continue
			}
			combined := append(slices.Clone(before.Permissions), result.Permissions...)
			if !engineAllows(resource, combined) {
				t.Fatalf("new decision lost: resource=%+v before=%+v after=%+v delta=%+v", resource, before, after, result)
			}
		}
	})
}

func TestEvaluateAuthorityDeltaMatchesRandomTreesRolesGrantsAndRights(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		spaces, groups, graph := drawGovernanceTree(t)
		members := drawMembers(t, spaces, groups)
		keys := []string{"document:read", "document:write", "billing:read"}
		modes := drawEnvelopeModes(t, spaces, groups, keys)

		roles := rapid.SliceOfN(rapid.Custom(func(t *rapid.T) propertyRole {
			position := drawNode(t, spaces, groups)
			permissionKeys := rapid.SliceOfN(rapid.IntRange(0, len(keys)-1), 1, len(keys)).Draw(t, "role_permissions")
			return propertyRole{Position: position, Keys: uniquePropertyKeys(permissionKeys, keys)}
		}), 0, 5).Draw(t, "roles")
		grants := rapid.SliceOfN(rapid.Custom(func(t *rapid.T) propertyGrant {
			member := members[rapid.IntRange(0, len(members)-1).Draw(t, "grant_member")]
			role := roles
			if len(role) == 0 {
				return propertyGrant{Member: member, Keys: []string{keys[0]}, Scope: drawPropertyScope(t, spaces, groups)}
			}
			selectedRole := role[rapid.IntRange(0, len(role)-1).Draw(t, "grant_role")]
			return propertyGrant{Member: member, Keys: selectedRole.Keys, Scope: drawPropertyScope(t, spaces, groups)}
		}), 0, 8).Draw(t, "grants")

		allPermissions := expandPropertyGrants(grants, modes, graph)
		before := choosePropertySubset(t, allPermissions, "before_permissions")
		after := choosePropertySubset(t, allPermissions, "after_permissions")
		before.Rights = drawPropertyRights(t, members, spaces, groups, keys, modes, graph, "before_rights")
		after.Rights = drawPropertyRights(t, members, spaces, groups, keys, modes, graph, "after_rights")

		result, err := Evaluate(before, after, graph)
		if err != nil {
			t.Fatal(err)
		}
		wantPermissions := brutePermissionDelta(before.Permissions, after.Permissions, graph)
		if !slices.Equal(permissionSignatures(result.Permissions), permissionSignatures(wantPermissions)) {
			t.Fatalf("permission delta mismatch: got=%v want=%v before=%+v after=%+v", permissionSignatures(result.Permissions), permissionSignatures(wantPermissions), before, after)
		}
		wantRights := bruteRightDelta(before.Rights, after.Rights, graph)
		if !slices.Equal(rightSignatures(result.Rights), rightSignatures(wantRights)) {
			t.Fatalf("assignment-right delta mismatch: got=%v want=%v before=%+v after=%+v", rightSignatures(result.Rights), rightSignatures(wantRights), before, after)
		}

		requests := propertyRequests(spaces, groups, graph, members, keys)
		for _, request := range requests {
			beforeAllowed := engineAllowsSnapshot(request, before.Permissions)
			afterAllowed := engineAllowsSnapshot(request, after.Permissions)
			withDeltaAllowed := engineAllowsSnapshot(request, append(slices.Clone(before.Permissions), result.Permissions...))
			if afterAllowed && !beforeAllowed && !withDeltaAllowed {
				t.Fatalf("delta lost a newly allowed decision: request=%+v delta=%+v", request, result)
			}
		}
	})
}

type propertyMember struct {
	ID       string
	Position Node
}

type propertyRole struct {
	Position Node
	Keys     []string
}

type propertyGrant struct {
	Member propertyMember
	Keys   []string
	Scope  Scope
}

func drawGovernanceTree(t *rapid.T) ([]Node, []Node, Graph) {
	spaceCount := rapid.IntRange(1, 5).Draw(t, "space_count")
	spaces := make([]Node, spaceCount)
	graph := Graph{SpaceParent: map[string]string{}, GroupParent: map[string]string{}, GroupSpace: map[string]string{}}
	for i := range spaces {
		spaces[i] = Node{Kind: Space, ID: fmt.Sprintf("spc_%d", i)}
		parent := ""
		if i > 0 && rapid.Bool().Draw(t, "space_has_parent") {
			parent = spaces[rapid.IntRange(0, i-1).Draw(t, "space_parent")].ID
		}
		graph.SpaceParent[spaces[i].ID] = parent
	}
	groupCount := rapid.IntRange(0, 6).Draw(t, "group_count")
	groups := make([]Node, groupCount)
	for i := range groups {
		groups[i] = Node{Kind: Group, ID: fmt.Sprintf("grp_%d", i)}
		// Keep the generated group tree in one Space so every cross-node
		// coverage comparison is a valid governance fact rather than a
		// malformed cross-Space reference.
		space := spaces[0]
		graph.GroupSpace[groups[i].ID] = space.ID
		parent := ""
		if i > 0 && rapid.Bool().Draw(t, "group_has_parent") {
			candidates := make([]Node, 0, i)
			for _, candidate := range groups[:i] {
				if graph.GroupSpace[candidate.ID] == space.ID {
					candidates = append(candidates, candidate)
				}
			}
			if len(candidates) > 0 {
				parent = candidates[rapid.IntRange(0, len(candidates)-1).Draw(t, "group_parent")].ID
			}
		}
		graph.GroupParent[groups[i].ID] = parent
	}
	return spaces, groups, graph
}

func drawMembers(t *rapid.T, spaces, groups []Node) []propertyMember {
	n := rapid.IntRange(1, 5).Draw(t, "member_count")
	members := make([]propertyMember, n)
	for i := range members {
		if len(groups) > 0 && rapid.Bool().Draw(t, "member_in_group") {
			members[i] = propertyMember{ID: fmt.Sprintf("mem_%d", i), Position: groups[rapid.IntRange(0, len(groups)-1).Draw(t, "member_group")]}
			continue
		}
		members[i] = propertyMember{ID: fmt.Sprintf("mem_%d", i), Position: spaces[rapid.IntRange(0, len(spaces)-1).Draw(t, "member_space")]}
	}
	return members
}

func drawNode(t *rapid.T, spaces, groups []Node) Node {
	if len(groups) > 0 && rapid.Bool().Draw(t, "node_is_group") {
		return groups[rapid.IntRange(0, len(groups)-1).Draw(t, "node_group")]
	}
	return spaces[rapid.IntRange(0, len(spaces)-1).Draw(t, "node_space")]
}

func drawEnvelopeModes(t *rapid.T, spaces, groups []Node, keys []string) map[string]map[string]int {
	modes := make(map[string]map[string]int, len(spaces)+len(groups))
	for _, node := range append(slices.Clone(spaces), groups...) {
		modes[node.ID] = make(map[string]int, len(keys))
		for _, key := range keys {
			modes[node.ID][key] = rapid.IntRange(0, 2).Draw(t, "envelope_mode")
		}
	}
	return modes
}

func expandPropertyGrants(grants []propertyGrant, modes map[string]map[string]int, graph Graph) []Permission {
	permissions := make([]Permission, 0)
	for _, grant := range grants {
		for _, key := range grant.Keys {
			if effectiveEnvelopeMode(grant.Member.Position, key, modes, graph) == 0 {
				continue
			}
			permissions = append(permissions, Permission{Subject: grant.Member.ID, Position: grant.Member.Position, Key: key, Scope: grant.Scope})
		}
	}
	return permissions
}

func effectiveEnvelopeMode(node Node, key string, modes map[string]map[string]int, graph Graph) int {
	mode := 2
	if value, ok := modes[node.ID][key]; ok && value < mode {
		mode = value
	}
	if node.Kind == Group {
		for current := node.ID; current != ""; current = graph.GroupParent[current] {
			if value := modes[current][key]; value < mode {
				mode = value
			}
		}
		spaceID := graph.GroupSpace[node.ID]
		node = Node{Kind: Space, ID: spaceID}
	}
	for current := node.ID; current != ""; current = graph.SpaceParent[current] {
		if value := modes[current][key]; value < mode {
			mode = value
		}
	}
	return mode
}

func choosePropertySubset(t *rapid.T, input []Permission, label string) Snapshot {
	result := Snapshot{Permissions: make([]Permission, 0, len(input))}
	for _, permission := range input {
		if rapid.Bool().Draw(t, label) {
			result.Permissions = append(result.Permissions, permission)
		}
	}
	return result
}

func drawPropertyScope(t *rapid.T, spaces, groups []Node) Scope {
	switch rapid.IntRange(0, 7).Draw(t, "grant_scope_kind") {
	case 0:
		return Scope{Kind: Self}
	case 1:
		return Scope{Kind: Global}
	case 2:
		return Scope{Kind: SpaceOnly, Anchor: spaces[rapid.IntRange(0, len(spaces)-1).Draw(t, "space_anchor")].ID}
	case 3:
		return Scope{Kind: SpaceTree, Anchor: spaces[rapid.IntRange(0, len(spaces)-1).Draw(t, "space_tree_anchor")].ID}
	case 4:
		if len(groups) == 0 {
			return Scope{Kind: Global}
		}
		return Scope{Kind: GroupOnly, Anchor: groups[rapid.IntRange(0, len(groups)-1).Draw(t, "group_anchor")].ID}
	case 5:
		if len(groups) == 0 {
			return Scope{Kind: Global}
		}
		return Scope{Kind: GroupTree, Anchor: groups[rapid.IntRange(0, len(groups)-1).Draw(t, "group_tree_anchor")].ID}
	default:
		return Scope{Kind: Self}
	}
}

func drawPropertyRights(t *rapid.T, members []propertyMember, spaces, groups []Node, keys []string, modes map[string]map[string]int, graph Graph, label string) []Right {
	count := rapid.IntRange(0, 6).Draw(t, label+"_count")
	rights := make([]Right, 0, count)
	for i := 0; i < count; i++ {
		holder := members[rapid.IntRange(0, len(members)-1).Draw(t, label+"_holder")]
		permissionIndexes := rapid.SliceOfN(rapid.IntRange(0, len(keys)-1), 1, len(keys)).Draw(t, label+"_permissions")
		permissionKeys := uniquePropertyKeys(permissionIndexes, keys)
		for len(permissionKeys) > 0 && effectiveEnvelopeMode(holder.Position, permissionKeys[0], modes, graph) == 0 {
			permissionKeys = permissionKeys[1:]
		}
		if len(permissionKeys) == 0 {
			continue
		}
		anchor := drawNode(t, spaces, groups)
		rights = append(rights, Right{Holder: holder.ID, Position: holder.Position, Permissions: permissionKeys, Anchor: anchor, Descendants: rapid.Bool().Draw(t, label+"_descendants"), Delegate: rapid.Bool().Draw(t, label+"_delegate")})
	}
	return rights
}

func uniquePropertyKeys(indexes []int, keys []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(indexes))
	for _, index := range indexes {
		key := keys[index]
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, key)
	}
	slices.Sort(result)
	return result
}

func brutePermissionDelta(before, after []Permission, graph Graph) []Permission {
	result := make([]Permission, 0)
	for _, candidate := range after {
		covered := false
		for _, previous := range before {
			if previous.Subject == candidate.Subject && previous.Position == candidate.Position && previous.Key == candidate.Key && bruteScopeContains(previous.Scope, candidate.Scope, graph) {
				covered = true
				break
			}
		}
		if !covered {
			result = append(result, candidate)
		}
	}
	return normalizePermissionForTest(result)
}

func bruteScopeContains(a, b Scope, graph Graph) bool {
	if a.Kind == b.Kind && a.Anchor == b.Anchor {
		return true
	}
	if a.Kind == Global {
		return true
	}
	if a.Kind == SpaceOnly && b.Kind == SpaceOnly {
		return a.Anchor == b.Anchor
	}
	if a.Kind == SpaceTree && (b.Kind == SpaceOnly || b.Kind == SpaceTree) {
		return b.Anchor == a.Anchor || isSpaceDescendant(graph, b.Anchor, a.Anchor)
	}
	if a.Kind == GroupTree && (b.Kind == GroupOnly || b.Kind == GroupTree) {
		return b.Anchor == a.Anchor || isGroupDescendant(graph, b.Anchor, a.Anchor)
	}
	if (a.Kind == SpaceOnly || a.Kind == SpaceTree) && (b.Kind == GroupOnly || b.Kind == GroupTree) {
		return groupInSpace(graph, b.Anchor, a.Anchor)
	}
	return false
}

func bruteRightDelta(before, after []Right, graph Graph) []Right {
	result := make([]Right, 0)
	for _, candidate := range after {
		covered := false
		for _, previous := range before {
			if bruteRightContains(previous, candidate, graph) {
				covered = true
				break
			}
		}
		if !covered {
			result = append(result, candidate)
		}
	}
	return normalizeRightForTest(result)
}

func bruteRightContains(a, b Right, graph Graph) bool {
	if a.Holder != b.Holder || a.Position != b.Position || (b.Delegate && !a.Delegate) || (b.Descendants && !a.Descendants) {
		return false
	}
	for _, key := range b.Permissions {
		if !slices.Contains(a.Permissions, key) {
			return false
		}
	}
	if a.Anchor == b.Anchor {
		return true
	}
	if a.Anchor.Kind == Space && b.Anchor.Kind == Space {
		return a.Descendants && isSpaceDescendant(graph, b.Anchor.ID, a.Anchor.ID)
	}
	if a.Anchor.Kind == Group && b.Anchor.Kind == Group {
		return a.Descendants && isGroupDescendant(graph, b.Anchor.ID, a.Anchor.ID)
	}
	if a.Anchor.Kind == Space && b.Anchor.Kind == Group {
		return a.Descendants && groupInSpace(graph, b.Anchor.ID, a.Anchor.ID)
	}
	return false
}

func isSpaceDescendant(graph Graph, child, ancestor string) bool {
	for current := child; current != ""; current = graph.SpaceParent[current] {
		if current == ancestor {
			return true
		}
	}
	return false
}

func isGroupDescendant(graph Graph, child, ancestor string) bool {
	for current := child; current != ""; current = graph.GroupParent[current] {
		if current == ancestor {
			return true
		}
	}
	return false
}

func groupInSpace(graph Graph, group, space string) bool {
	return graph.GroupSpace[group] == space
}

func normalizePermissionForTest(values []Permission) []Permission {
	result := slices.Clone(values)
	slices.SortFunc(result, func(a, b Permission) int {
		return cmpString(permissionSignature(a), permissionSignature(b))
	})
	unique := result[:0]
	for _, value := range result {
		if len(unique) == 0 || permissionSignature(unique[len(unique)-1]) != permissionSignature(value) {
			unique = append(unique, value)
		}
	}
	return unique
}

func normalizeRightForTest(values []Right) []Right {
	result := slices.Clone(values)
	slices.SortFunc(result, func(a, b Right) int { return cmpString(rightSignature(a), rightSignature(b)) })
	unique := result[:0]
	for _, value := range result {
		if len(unique) == 0 || rightSignature(unique[len(unique)-1]) != rightSignature(value) {
			unique = append(unique, value)
		}
	}
	return unique
}

func permissionSignatures(values []Permission) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, permissionSignature(value))
	}
	slices.Sort(result)
	return result
}

func rightSignatures(values []Right) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, rightSignature(value))
	}
	slices.Sort(result)
	return result
}

func permissionSignature(value Permission) string {
	return fmt.Sprintf("%s|%s:%s|%s|%s:%s", value.Subject, value.Position.Kind, value.Position.ID, value.Key, value.Scope.Kind, value.Scope.Anchor)
}

func rightSignature(value Right) string {
	return fmt.Sprintf("%s|%s:%s|%s|%t|%t|%s:%s", value.Holder, value.Position.Kind, value.Position.ID, strings.Join(value.Permissions, ","), value.Descendants, value.Delegate, value.Anchor.Kind, value.Anchor.ID)
}

func cmpString(a, b string) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

func propertyRequests(spaces, groups []Node, graph Graph, members []propertyMember, keys []string) []engine.Request {
	requests := make([]engine.Request, 0, (len(spaces)+len(groups))*len(members)*len(keys))
	for _, member := range members {
		for _, space := range spaces {
			for _, key := range keys {
				requests = append(requests, engine.Request{MemberID: member.ID, Permission: key, ResourceSpace: space.ID, ResourceSpaceAncestors: spaceAncestorsForTest(space.ID, graph), ResourceOwner: member.ID})
			}
		}
		for _, group := range groups {
			for _, key := range keys {
				requests = append(requests, engine.Request{MemberID: member.ID, Permission: key, ResourceSpace: graph.GroupSpace[group.ID], ResourceSpaceAncestors: spaceAncestorsForTest(graph.GroupSpace[group.ID], graph), ResourceGroup: group.ID, ResourceGroupAncestors: groupAncestorsForTest(group.ID, graph), ResourceOwner: member.ID})
			}
		}
	}
	return requests
}

func spaceAncestorsForTest(space string, graph Graph) []string {
	ancestors := make([]string, 0)
	for current := graph.SpaceParent[space]; current != ""; current = graph.SpaceParent[current] {
		ancestors = append(ancestors, current)
	}
	return ancestors
}

func groupAncestorsForTest(group string, graph Graph) []string {
	ancestors := make([]string, 0)
	for current := graph.GroupParent[group]; current != ""; current = graph.GroupParent[current] {
		ancestors = append(ancestors, current)
	}
	return ancestors
}

func engineAllowsSnapshot(request engine.Request, permissions []Permission) bool {
	request.Assignments = nil
	for _, permission := range permissions {
		request.Assignments = append(request.Assignments, engine.Assignment{MemberID: permission.Subject, Permissions: []string{permission.Key}, Scope: engine.Scope{Kind: string(permission.Scope.Kind), Anchor: permission.Scope.Anchor}})
	}
	return engine.Check(request).Effect == engine.Allow
}

func engineAllows(request engine.Request, permissions []Permission) bool {
	request.MemberID = "mem_actor"
	request.Permission = "document:read"
	for _, permission := range permissions {
		request.Assignments = append(request.Assignments, engine.Assignment{
			MemberID: permission.Subject, Permissions: []string{permission.Key},
			Scope: engine.Scope{Kind: string(permission.Scope.Kind), Anchor: permission.Scope.Anchor},
		})
	}
	return engine.Check(request).Effect == engine.Allow
}
