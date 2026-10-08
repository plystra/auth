package apierr

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type Error struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Details   any    `json:"details,omitempty"`
	RequestID string `json:"request_id,omitempty"`
	status    int
}

// MarshalJSON keeps errors returned by Huma handlers and errors written by
// protocol handlers on the same wire contract.
func (e *Error) MarshalJSON() ([]byte, error) {
	type payload Error
	return json.Marshal(struct {
		Error *payload `json:"error"`
	}{Error: (*payload)(e)})
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }
func (e *Error) GetStatus() int {
	if e.status != 0 {
		return e.status
	}
	return Status(e.Code)
}
func New(code, message string) *Error                 { return &Error{Code: code, Message: message} }
func WithRequestID(e *Error, requestID string) *Error { c := *e; c.RequestID = requestID; return &c }
func WithStatus(e *Error, status int) *Error          { c := *e; c.status = status; return &c }
func Status(code string) int {
	switch strings.ToLower(strings.TrimSpace(code)) {
	case "invalid_request", "invalid_grant", "invalid_scope", "invalid_target", "validation_failed", "inline_grants_not_allowed":
		return http.StatusBadRequest
	case "invalid_credentials", "invalid_token", "unauthorized", "unauthenticated", "credential_plane_mismatch":
		return http.StatusUnauthorized
	case "forbidden", "permission_denied", "browser_origin_rejected", "cors_origin_rejected", "step_up_required", "human_principal_required":
		return http.StatusForbidden
	case "email_verification_required":
		return http.StatusForbidden
	case "not_found":
		return http.StatusNotFound
	case "conflict":
		return http.StatusConflict
	case "rate_limited":
		return http.StatusTooManyRequests
	case "unavailable", "temporarily_unavailable":
		return http.StatusServiceUnavailable
	case "not_implemented":
		return http.StatusNotImplemented
	default:
		return http.StatusInternalServerError
	}
}
func Write(w http.ResponseWriter, e *Error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.GetStatus())
	_ = json.NewEncoder(w).Encode(e)
}
func Wrap(code string, err error) *Error { return &Error{Code: code, Message: fmt.Sprintf("%s", err)} }
