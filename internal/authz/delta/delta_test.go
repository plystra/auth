package delta

import (
	"slices"
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
