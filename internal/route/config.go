package route

import "github.com/danielgtaylor/huma/v2"

// HumaConfig keeps the runtime API surface JSON-only and prevents Huma's
// documentation and schema-link helpers from changing response bodies.
func HumaConfig(title, version string) huma.Config {
	config := huma.DefaultConfig(title, version)
	config.OpenAPIPath = ""
	config.DocsPath = ""
	config.SchemasPath = ""
	config.CreateHooks = nil
	config.Transformers = nil
	return config
}
