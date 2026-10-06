package route

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/idempotency"
	"github.com/plystra/auth/internal/requestinfo"
)

const maxIdempotencyBody = 1 << 20

type IdempotencyStore interface {
	Reserve(context.Context, string, string, string, string, []byte) (idempotency.Reservation, error)
	Complete(context.Context, string, int, map[string][]string, []byte) error
}

type idempotencyResponseWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func newIdempotencyResponseWriter(headers http.Header) *idempotencyResponseWriter {
	return &idempotencyResponseWriter{header: cloneHeader(headers)}
}

func (w *idempotencyResponseWriter) Header() http.Header { return w.header }

func (w *idempotencyResponseWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
}

func (w *idempotencyResponseWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.body.Write(body)
}

func serveIdempotent(w http.ResponseWriter, r *http.Request, next http.Handler, plane Plane, service IdempotencyStore) {
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if key == "" {
		next.ServeHTTP(w, r)
		return
	}
	if !validIdempotencyKey(key) {
		writeIdempotencyError(w, r.Context(), "IDEMPOTENCY_KEY_INVALID", "Idempotency-Key must be between 1 and 255 characters and contain no control characters.", http.StatusBadRequest)
		return
	}
	originalBody := r.Body
	body, err := readRequestBody(r)
	if originalBody != nil {
		_ = originalBody.Close()
	}
	if err != nil {
		writeIdempotencyError(w, r.Context(), "REQUEST_BODY_TOO_LARGE", "request body exceeds the idempotency limit.", http.StatusRequestEntityTooLarge)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	requestHash := sha256.Sum256([]byte(r.Method + "\x00" + r.URL.RequestURI() + "\x00" + string(body)))
	scopeHash := sha256.Sum256([]byte(string(plane) + "\x00" + r.Header.Get("Authorization")))
	reservation, err := service.Reserve(r.Context(), hex.EncodeToString(scopeHash[:]), r.Method, r.URL.RequestURI(), key, requestHash[:])
	if err != nil {
		writeIdempotencyError(w, r.Context(), "UNAVAILABLE", "idempotency storage is temporarily unavailable.", http.StatusServiceUnavailable)
		return
	}
	if reservation.Conflict {
		writeIdempotencyError(w, r.Context(), "IDEMPOTENCY_KEY_REUSED", "Idempotency-Key was already used with a different request.", http.StatusConflict)
		return
	}
	if reservation.InProgress {
		w.Header().Set("Retry-After", "1")
		writeIdempotencyError(w, r.Context(), "IDEMPOTENCY_IN_PROGRESS", "the first request using this Idempotency-Key is still in progress.", http.StatusConflict)
		return
	}
	if reservation.Replay {
		requestID := w.Header().Get("X-Request-Id")
		copyHeader(w.Header(), reservation.Headers)
		w.Header().Set("X-Request-Id", requestID)
		w.Header().Set("Idempotency-Replayed", "true")
		w.WriteHeader(reservation.StatusCode)
		_, _ = w.Write(reservation.Body)
		return
	}
	captured := newIdempotencyResponseWriter(w.Header())
	next.ServeHTTP(captured, r)
	status := captured.status
	if status == 0 {
		status = http.StatusOK
	}
	completeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	err = service.Complete(completeCtx, reservation.ID, status, captured.header, captured.body.Bytes())
	cancel()
	if err != nil {
		writeIdempotencyError(w, r.Context(), "UNAVAILABLE", "idempotency result could not be stored.", http.StatusServiceUnavailable)
		return
	}
	copyHeader(w.Header(), captured.header)
	w.WriteHeader(status)
	_, _ = w.Write(captured.body.Bytes())
}

func readRequestBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxIdempotencyBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxIdempotencyBody {
		return nil, io.ErrShortBuffer
	}
	return body, nil
}

func validIdempotencyKey(key string) bool {
	if len(key) == 0 || len(key) > 255 {
		return false
	}
	for _, r := range key {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func isWriteMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func cloneHeader(source http.Header) http.Header {
	clone := make(http.Header, len(source))
	for key, values := range source {
		clone[key] = append([]string(nil), values...)
	}
	return clone
}

func copyHeader(destination, source http.Header) {
	for key := range destination {
		delete(destination, key)
	}
	for key, values := range source {
		destination[key] = append([]string(nil), values...)
	}
}

func writeIdempotencyError(w http.ResponseWriter, ctx context.Context, code, message string, status int) {
	err := apierr.WithStatus(apierr.New(code, message), status)
	err = apierr.WithRequestID(err, requestinfo.Get(ctx).ID)
	apierr.Write(w, err)
}
