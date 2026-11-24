package protocol

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/enterprise"
)

var scimProjectionPath = regexp.MustCompile(`^(?:urn:[a-z0-9:.-]+:)?[a-z][a-z0-9_$-]*(?:\.[a-z][a-z0-9_$-]*)?$`)

type scimProjection struct {
	paths   map[string]bool
	include bool
}

func parseSCIMProjection(query url.Values, schema string) (scimProjection, error) {
	var projection scimProjection
	selected, includes := query["attributes"]
	excluded, excludes := query["excludedAttributes"]
	if !includes && !excludes {
		return projection, nil
	}
	values := excluded
	if includes {
		values = selected
	}
	invalid := apierr.New("invalid_request", "SCIM attributes requires one bounded list, using either attributes or excludedAttributes")
	if includes && excludes || len(values) != 1 || len(values[0]) > 2048 {
		return projection, invalid
	}
	paths := strings.Split(values[0], ",")
	if len(paths) > 64 {
		return projection, invalid
	}
	projection = scimProjection{paths: make(map[string]bool, len(paths)), include: includes}
	for _, item := range paths {
		path := strings.ToLower(strings.TrimSpace(item))
		if !scimProjectionPath.MatchString(path) {
			return scimProjection{}, invalid
		}
		path = strings.TrimPrefix(path, strings.ToLower(schema)+":")
		projection.paths[path] = true
	}
	return projection, nil
}

func (p scimProjection) apply(resource map[string]any) map[string]any {
	if p.paths == nil {
		return resource
	}
	projected := map[string]any{"schemas": resource["schemas"], "id": resource["id"]}
	for name, value := range resource {
		switch name {
		case "id", "schemas":
			continue
		case "name", "emails", "meta", "members":
			if p.paths[name] {
				if p.include {
					projected[name] = value
				}
				continue
			}
			switch typed := value.(type) {
			case enterprise.SCIMName:
				if fields := projectSCIMFields(p, name, typed); len(fields) > 0 {
					projected[name] = fields
				}
			case []enterprise.SCIMEmail:
				if items := p.projectEmails(typed); len(items) > 0 {
					projected[name] = items
				}
			case map[string]any:
				if fields := projectSCIMFields(p, name, typed); len(fields) > 0 {
					projected[name] = fields
				}
			case []map[string]string:
				items := make([]map[string]string, 0, len(typed))
				for _, item := range typed {
					if fields := projectSCIMFields(p, name, item); len(fields) > 0 {
						items = append(items, fields)
					}
				}
				if len(items) > 0 {
					projected[name] = items
				}
			}
		default:
			if p.paths[strings.ToLower(name)] == p.include {
				projected[name] = value
			}
		}
	}
	return projected
}

func projectSCIMFields[V any](p scimProjection, parent string, value map[string]V) map[string]V {
	fields := make(map[string]V)
	for name, detail := range value {
		if p.paths[parent+"."+strings.ToLower(name)] == p.include {
			fields[name] = detail
		}
	}
	return fields
}

func (p scimProjection) projectEmails(emails []enterprise.SCIMEmail) []map[string]any {
	items := make([]map[string]any, 0, len(emails))
	for _, email := range emails {
		item := map[string]any{"value": email.Value}
		if email.Type != "" {
			item["type"] = email.Type
		}
		if email.Display != "" {
			item["display"] = email.Display
		}
		if email.Primary {
			item["primary"] = true
		}
		if fields := projectSCIMFields(p, "emails", item); len(fields) > 0 {
			items = append(items, fields)
		}
	}
	return items
}

func (p scimProjection) write(w http.ResponseWriter, status int, user enterprise.SCIMUser, directoryID string) {
	resource := scimUserResource(user, directoryID)
	writeSCIMResourceHeaders(w, resource)
	writeSCIMJSON(w, status, p.apply(resource))
}
