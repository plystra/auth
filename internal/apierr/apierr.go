package apierr

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type Error struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Details   any    `json:"details,omitempty"`
	RequestID string `json:"request_id,omitempty"`
}

func (e *Error) Error() string                        { return e.Code + ": " + e.Message }
func New(code, message string) *Error                 { return &Error{Code: code, Message: message} }
func WithRequestID(e *Error, requestID string) *Error { c := *e; c.RequestID = requestID; return &c }
func Status(code string) int {
	switch code {
	case "invalid_request", "invalid_credentials", "invalid_grant":
		return http.StatusBadRequest
	case "unauthorized":
		return http.StatusUnauthorized
	case "forbidden":
		return http.StatusForbidden
	case "not_found":
		return http.StatusNotFound
	case "conflict":
		return http.StatusConflict
	case "rate_limited":
		return http.StatusTooManyRequests
	default:
		return http.StatusInternalServerError
	}
}
func Write(w http.ResponseWriter, e *Error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(Status(e.Code))
	_ = json.NewEncoder(w).Encode(struct {
		Error *Error `json:"error"`
	}{e})
}
func Wrap(code string, err error) *Error { return &Error{Code: code, Message: fmt.Sprintf("%s", err)} }
