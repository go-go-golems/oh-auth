package oauthserver

import (
	"sort"
	"strings"
)

type ScopeSet struct{ values []Scope }

func NewScopeSet(values ...Scope) (ScopeSet, error) {
	seen := make(map[Scope]struct{}, len(values))
	canonical := make([]Scope, 0, len(values))
	for _, value := range values {
		raw := strings.TrimSpace(string(value))
		if raw == "" {
			return ScopeSet{}, invalidValue("scope")
		}
		validated, err := NewScope(raw)
		if err != nil {
			return ScopeSet{}, err
		}
		if _, exists := seen[validated]; exists {
			continue
		}
		seen[validated] = struct{}{}
		canonical = append(canonical, validated)
	}
	sort.Slice(canonical, func(i, j int) bool { return canonical[i] < canonical[j] })
	return ScopeSet{values: canonical}, nil
}

func ParseScopes(raw string) (ScopeSet, error) {
	if strings.TrimSpace(raw) == "" {
		return NewScopeSet()
	}
	parts := strings.Fields(raw)
	values := make([]Scope, 0, len(parts))
	for _, part := range parts {
		values = append(values, Scope(part))
	}
	return NewScopeSet(values...)
}

func (s ScopeSet) Contains(scope Scope) bool {
	_, found := sort.Find(len(s.values), func(i int) int {
		if s.values[i] < scope {
			return -1
		}
		if s.values[i] > scope {
			return 1
		}
		return 0
	})
	return found
}

func (s ScopeSet) Values() []Scope { return append([]Scope(nil), s.values...) }

func (s ScopeSet) Intersect(other ScopeSet) ScopeSet {
	values := make([]Scope, 0, minInt(len(s.values), len(other.values)))
	left, right := 0, 0
	for left < len(s.values) && right < len(other.values) {
		switch {
		case s.values[left] < other.values[right]:
			left++
		case s.values[left] > other.values[right]:
			right++
		default:
			values = append(values, s.values[left])
			left++
			right++
		}
	}
	return ScopeSet{values: values}
}

func (s ScopeSet) IsSubsetOf(other ScopeSet) bool {
	return len(s.Intersect(other).values) == len(s.values)
}

func (s ScopeSet) String() string {
	values := make([]string, len(s.values))
	for i, value := range s.values {
		values[i] = string(value)
	}
	return strings.Join(values, " ")
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
