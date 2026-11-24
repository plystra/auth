package protocol

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/enterprise"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/secret"
)

const (
	scimSearchLimit  = 16 << 10
	scimSearchSchema = "urn:ietf:params:scim:api:messages:2.0:SearchRequest"
)

type scimSearchBody struct {
	Schemas            []string `json:"schemas"`
	Filter             string   `json:"filter"`
	Attributes         []string `json:"attributes"`
	ExcludedAttributes []string `json:"excludedAttributes"`
	StartIndex         *int32   `json:"startIndex"`
	Count              *int32   `json:"count"`
}

type scimListQuery struct {
	filter     enterprise.SCIMCollectionFilter
	projection scimProjection
	start      int32
	count      int32
}

func (h HTTP) scimSearch(nameAttribute, schema string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.Enterprise == nil {
			route.WriteSCIMError(w, apierr.New("temporarily_unavailable", "SCIM is unavailable"))
			return
		}
		token, err := scimBearerToken(r)
		if err != nil {
			route.WriteSCIMError(w, err)
			return
		}
		if r.URL.RawQuery != "" || r.URL.ForceQuery {
			route.WriteSCIMError(w, apierr.New("invalid_request", "SCIM search parameters must be in the request body"))
			return
		}
		query, err := decodeSCIMSearch(w, r, nameAttribute, schema)
		if err != nil {
			route.WriteSCIMError(w, err)
			return
		}
		if schema == scimUser {
			h.listSCIMUsers(w, r, token, query)
			return
		}
		h.listSCIMGroups(w, r, token, query, query.projection.includesMembers())
	}
}

func decodeSCIMSearch(w http.ResponseWriter, r *http.Request, nameAttribute, schema string) (scimListQuery, error) {
	var input scimSearchBody
	if err := decodeSCIMJSONWithin(w, r, &input, scimSearchLimit); err != nil {
		return scimListQuery{}, err
	}
	if len(input.Schemas) != 1 || input.Schemas[0] != scimSearchSchema {
		return scimListQuery{}, apierr.New("invalid_request", "SCIM search requires the SearchRequest schema")
	}
	filter, err := parseSCIMCollectionFilter(input.Filter, nameAttribute)
	if err != nil {
		return scimListQuery{}, err
	}
	fields := url.Values{}
	for name, values := range map[string][]string{"attributes": input.Attributes, "excludedAttributes": input.ExcludedAttributes} {
		if values == nil {
			continue
		}
		for _, value := range values {
			if strings.Contains(value, ",") {
				return scimListQuery{}, apierr.New("invalid_request", "SCIM search attributes must be individual paths")
			}
		}
		fields.Set(name, strings.Join(values, ","))
	}
	projection, err := parseSCIMProjection(fields, schema)
	if err != nil {
		return scimListQuery{}, err
	}
	start, count := int32(1), int32(enterprise.MaxSCIMPageSize)
	if input.StartIndex != nil {
		start = *input.StartIndex
	}
	if input.Count != nil {
		count = *input.Count
	}
	start, count = normalizeSCIMPage(start, count)
	return scimListQuery{filter, projection, start, count}, nil
}

func (p scimProjection) includesMembers() bool {
	if p.paths == nil || !p.include {
		return !p.paths["members"]
	}
	for path := range p.paths {
		if path == "members" || strings.HasPrefix(path, "members.") {
			return true
		}
	}
	return false
}

func (h HTTP) listSCIMUsers(w http.ResponseWriter, r *http.Request, token secret.String, query scimListQuery) {
	directoryID := r.PathValue("dir_id")
	users, total, err := h.Enterprise.ListSCIMUsers(r.Context(), directoryID, token, query.filter, query.start, query.count)
	if err != nil {
		route.WriteSCIMError(w, err)
		return
	}
	resources := make([]map[string]any, 0, len(users))
	for _, user := range users {
		resources = append(resources, query.projection.apply(scimUserResource(user, directoryID)))
	}
	writeSCIMList(w, resources, total, query.start)
}

func (h HTTP) listSCIMGroups(w http.ResponseWriter, r *http.Request, token secret.String, query scimListQuery, includeMembers bool) {
	directoryID := r.PathValue("dir_id")
	groups, total, err := h.Enterprise.ListSCIMGroups(r.Context(), directoryID, token, query.filter, includeMembers, query.start, query.count)
	if err != nil {
		route.WriteSCIMError(w, err)
		return
	}
	resources := make([]map[string]any, 0, len(groups))
	for _, group := range groups {
		resources = append(resources, query.projection.apply(scimGroupResource(group, directoryID, includeMembers)))
	}
	writeSCIMList(w, resources, total, query.start)
}

func writeSCIMList(w http.ResponseWriter, resources []map[string]any, total int64, start int32) {
	writeSCIMJSON(w, http.StatusOK, map[string]any{
		"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": total, "startIndex": start, "itemsPerPage": len(resources), "Resources": resources,
	})
}
