package oauthserver

import (
	"context"
	"sort"
)

type StaticResourceRegistry struct{ resources map[ResourceID]Resource }

func NewStaticResourceRegistry(configs []ResourceConfig, supported ScopeSet) (*StaticResourceRegistry, error) {
	resources := make(map[ResourceID]Resource, len(configs))
	for _, config := range configs {
		id, err := NewResourceID(config.ID)
		if err != nil {
			return nil, err
		}
		scopes, err := NewScopeSet(stringsToScopes(config.SupportedScopes)...)
		if err != nil || !scopes.IsSubsetOf(supported) {
			return nil, invalidValue("resource scopes")
		}
		if config.DisplayName == "" {
			return nil, invalidValue("resource display name")
		}
		if _, exists := resources[id]; exists {
			return nil, invalidValue("duplicate resource")
		}
		resources[id] = Resource{ID: id, DisplayName: config.DisplayName, SupportedScopes: scopes}
	}
	return &StaticResourceRegistry{resources: resources}, nil
}

func (r *StaticResourceRegistry) LookupResource(_ context.Context, id ResourceID) (Resource, error) {
	resource, ok := r.resources[id]
	if !ok {
		return Resource{}, ErrNotFound
	}
	return resource, nil
}

func (r *StaticResourceRegistry) ListResources(_ context.Context) ([]Resource, error) {
	result := make([]Resource, 0, len(r.resources))
	for _, resource := range r.resources {
		result = append(result, resource)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

var _ ResourceRegistry = (*StaticResourceRegistry)(nil)
