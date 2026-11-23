package protocol

import (
	"errors"
	"mime"
	"net/http"
	"net/url"

	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/secret"
)

const samlBrowserFormLimit = 64 << 10

func (h HTTP) samlBrowserCallback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	if h.Enterprise == nil || h.HostedOrigin == "" {
		writeErr(w, apierr.New("temporarily_unavailable", "hosted SAML sign-in is unavailable"))
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" || r.URL.RawQuery != "" || r.URL.ForceQuery {
		writeErr(w, apierr.New("invalid_request", "a SAML form body is required"))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, samlBrowserFormLimit)
	if err := r.ParseForm(); err != nil {
		var limit *http.MaxBytesError
		if errors.As(err, &limit) {
			writeErr(w, apierr.New("REQUEST_BODY_TOO_LARGE", "the SAML form exceeds 64 KiB"))
			return
		}
		writeErr(w, apierr.New("invalid_request", "the SAML form body is invalid"))
		return
	}
	relay, payload := r.PostForm["RelayState"], r.PostForm["SAMLResponse"]
	if len(relay) != 1 || len(payload) != 1 || len(relay[0]) == 0 || len(relay[0]) > 80 || payload[0] == "" {
		writeErr(w, apierr.New("invalid_request", "one RelayState and one SAMLResponse are required"))
		return
	}
	connection := r.PathValue("connection_id")
	interaction, err := h.Enterprise.StageSAMLBrowserResponse(r.Context(), connection,
		h.HostedOrigin+route.SAMLBrowserCallbackPrefix+connection, secret.New(relay[0]), secret.New(payload[0]))
	if err != nil {
		writeProtocolErr(w, err)
		return
	}
	location := url.URL{Path: "/oidc/upstream", Fragment: url.Values{"interaction": {interaction}}.Encode()}
	w.Header().Set("Location", location.String())
	w.WriteHeader(http.StatusSeeOther)
}
