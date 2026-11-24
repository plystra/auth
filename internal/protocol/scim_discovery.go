package protocol

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/enterprise"
	"github.com/plystra/auth/internal/route"
)

const (
	scimCore       = "urn:ietf:params:scim:schemas:core:2.0:"
	scimUser       = scimCore + "User"
	scimGroup      = scimCore + "Group"
	scimConfig     = scimCore + "ServiceProviderConfig"
	scimListSchema = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
)

func (h HTTP) registerSCIMDiscovery(mux route.HandlerMux) {
	for _, endpoint := range []struct{ name, path, collection string }{
		{"service_provider_config", "ServiceProviderConfig", "ServiceProviderConfig"},
		{"resource_types", "ResourceTypes", "ResourceTypes"},
		{"resource_type", "ResourceTypes/{id}", "ResourceTypes"},
		{"schemas", "Schemas", "Schemas"},
		{"schema", "Schemas/{id}", "Schemas"},
	} {
		spec := route.NewSpec("scim."+endpoint.name, http.MethodGet, "/scim/v2/{dir_id}/"+endpoint.path,
			route.Principal, "", []route.Subject{route.Public}, route.WithNonJSON())
		route.RegisterNonJSON(mux, spec, h.scimDiscovery(endpoint.collection))
	}
}

func (h HTTP) scimDiscovery(collection string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.Enterprise == nil {
			route.WriteSCIMError(w, apierr.New("unavailable", "SCIM is unavailable"))
			return
		}
		token, err := scimBearerToken(r)
		if err != nil {
			route.WriteSCIMError(w, err)
			return
		}
		directory := r.PathValue("dir_id")
		if err := h.Enterprise.ValidateDirectoryToken(r.Context(), directory, token); err != nil {
			route.WriteSCIMError(w, err)
			return
		}
		if r.URL.Query().Has("filter") {
			route.WriteSCIMError(w, apierr.New("forbidden", "SCIM discovery does not accept filters"))
			return
		}
		base := strings.TrimRight(h.Issuer, "/") + "/scim/v2/" + url.PathEscape(directory)
		if collection == "ServiceProviderConfig" {
			writeSCIMResource(w, http.StatusOK, scimProviderConfig(base))
			return
		}
		entries := scimResourceTypes(base)
		if collection == "Schemas" {
			entries = scimSchemas(base)
		}
		if id := r.PathValue("id"); id != "" {
			for _, entry := range entries {
				if entry["id"] == id {
					writeSCIMResource(w, http.StatusOK, entry)
					return
				}
			}
			route.WriteSCIMError(w, apierr.New("not_found", "SCIM discovery resource was not found"))
			return
		}
		writeSCIMResource(w, http.StatusOK, map[string]any{
			"schemas": []string{scimListSchema}, "totalResults": len(entries),
			"itemsPerPage": len(entries), "startIndex": 1, "Resources": entries,
		})
	}
}

func scimProviderConfig(base string) map[string]any {
	disabled := map[string]any{"supported": false}
	enabled := map[string]any{"supported": true}
	return map[string]any{
		"schemas": []string{scimConfig},
		"patch":   enabled, "bulk": map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":         map[string]any{"supported": true, "maxResults": enterprise.MaxSCIMPageSize},
		"changePassword": disabled, "sort": disabled, "etag": enabled,
		"authenticationSchemes": []map[string]any{{
			"type": "oauthbearertoken", "name": "Directory bearer token",
			"description": "An active bearer token issued for this directory.",
			"specUri":     "https://www.rfc-editor.org/rfc/rfc6750.html", "primary": true,
		}},
		"meta": map[string]any{"resourceType": "ServiceProviderConfig", "location": base + "/ServiceProviderConfig"},
	}
}

func scimResourceTypes(base string) []map[string]any {
	resource := func(name, schema string) map[string]any {
		return map[string]any{
			"schemas": []string{scimCore + "ResourceType"}, "id": name, "name": name,
			"endpoint": "/" + name + "s", "schema": schema,
			"meta": map[string]any{"resourceType": "ResourceType", "location": base + "/ResourceTypes/" + name},
		}
	}
	return []map[string]any{resource("User", scimUser), resource("Group", scimGroup)}
}

func scimSchemas(base string) []map[string]any {
	schema := func(id, name, description string, attributes ...map[string]any) map[string]any {
		return map[string]any{
			"schemas": []string{scimCore + "Schema"}, "id": id, "name": name,
			"description": description, "attributes": attributes,
			"meta": map[string]any{"resourceType": "Schema", "location": base + "/Schemas/" + url.PathEscape(id)},
		}
	}
	attribute := func(name, kind string, required, multi bool) map[string]any {
		return map[string]any{
			"name": name, "type": kind, "required": required, "multiValued": multi,
			"caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none",
		}
	}
	userName := attribute("userName", "string", true, false)
	userName["uniqueness"] = "server"
	userName["description"] = "A normalized email address."
	name := attribute("name", "complex", false, false)
	var nameFields []map[string]any
	for _, field := range enterprise.SCIMNameAttributes() {
		nameFields = append(nameFields, attribute(field, "string", false, false))
	}
	name["subAttributes"] = nameFields
	members := attribute("members", "complex", false, true)
	memberValue := attribute("value", "string", true, false)
	memberValue["caseExact"] = true
	memberValue["mutability"] = "immutable"
	members["subAttributes"] = []map[string]any{memberValue}
	return []map[string]any{
		schema(scimUser, "User", "Directory-provisioned user.", userName, name,
			attribute("displayName", "string", false, false), attribute("active", "boolean", false, false)),
		schema(scimGroup, "Group", "Directory-managed group with User members.",
			attribute("displayName", "string", true, false), members),
	}
}
