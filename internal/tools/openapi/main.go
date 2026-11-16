package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/plystra/auth/examples/invoice-saas"
	"github.com/plystra/auth/internal/plane/ops"
	"github.com/plystra/auth/internal/plane/principal"
	"github.com/plystra/auth/internal/plane/server"
	"github.com/plystra/auth/internal/protocol"
	"github.com/plystra/auth/internal/route"
)

func main() {
	_ = os.MkdirAll("openapi", 0755)
	write("principal", build(func(api huma.API) { (&principal.API{}).Register(api) }))
	write("server", build(func(api huma.API) { (&server.API{}).Register(api) }))
	write("ops", build(func(api huma.API) { (&ops.API{}).Register(api) }))
	mux := http.NewServeMux()
	api := humago.New(mux, route.HumaConfig("Invoice SaaS", "1.0.0"))
	(&invoicesaas.API{}).Register(api)
	b, err := json.MarshalIndent(api.OpenAPI(), "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile("examples/invoice-saas/openapi.json", append(b, '\n'), 0644); err != nil {
		panic(err)
	}
}
func build(register func(huma.API)) *huma.OpenAPI {
	mux := http.NewServeMux()
	api := humago.New(mux, route.HumaConfig("Plystra Auth", "1.0.0"))
	register(api)
	protocol.HTTP{Issuer: "https://auth.plystra.com"}.Register(mux)
	return api.OpenAPI()
}
func write(name string, v any) {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		panic(e)
	}
	if e = os.WriteFile(filepath.Join("openapi", name+".json"), append(b, '\n'), 0644); e != nil {
		panic(e)
	}
}
