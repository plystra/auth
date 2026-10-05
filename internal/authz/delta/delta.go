package delta

import "sort"

type Change struct {
	MemberID   string
	Permission string
	Granted    bool
}
type State struct{ Grants map[string]map[string]bool }

func Apply(before State, changes []Change) State {
	after := State{Grants: map[string]map[string]bool{}}
	for m, ps := range before.Grants {
		after.Grants[m] = map[string]bool{}
		for p, v := range ps {
			after.Grants[m][p] = v
		}
	}
	for _, c := range changes {
		if after.Grants[c.MemberID] == nil {
			after.Grants[c.MemberID] = map[string]bool{}
		}
		after.Grants[c.MemberID][c.Permission] = c.Granted
	}
	return after
}
func Validate(before State, changes []Change) (State, bool) {
	after := Apply(before, changes)
	for _, ps := range after.Grants {
		for _, v := range ps {
			if !v {
				return after, false
			}
		}
	}
	return after, true
}
func Canonical(changes []Change) []Change {
	out := append([]Change(nil), changes...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].MemberID != out[j].MemberID {
			return out[i].MemberID < out[j].MemberID
		}
		return out[i].Permission < out[j].Permission
	})
	return out
}
