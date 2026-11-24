package route

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/idempotency"
	"github.com/plystra/auth/internal/requestinfo"
)

const (
	maxIdempotencyBody        = 1 << 20
	OIDCInteractionsPath      = "/v1/auth/oidc-interactions"
	SAMLBrowserCallbackPrefix = "/oidc/upstream/saml/"
)

// One-time publisher credentials must never enter the replay store, including
// when a caller reuses a key previously reserved by a different operation.
func checkOAuthSecretIdempotency(r *http.Request, plane Plane) error {
	if plane != Principal || r.Method != http.MethodPost || len(r.Header.Values("Idempotency-Key")) == 0 {
		return nil
	}
	path := r.URL.Path
	if isSAMLBrowserPost(r) {
		return apierr.New("VALIDATION_FAILED", "Idempotency-Key is not supported for SAML browser callbacks")
	}
	if path == OIDCInteractionsPath || strings.HasPrefix(path, OIDCInteractionsPath+"/") {
		return apierr.New("VALIDATION_FAILED", "Idempotency-Key is not supported for hosted sign-in interactions")
	}
	denied := apierr.New("VALIDATION_FAILED", "Idempotency-Key is not supported for one-time OAuth client secrets")
	if strings.HasPrefix(path, "/v1/applications/") && strings.HasSuffix(path, "/oauth-client-secret/rotate") {
		return denied
	}
	if !strings.HasPrefix(path, "/v1/spaces/") || !strings.HasSuffix(path, "/applications") {
		return nil
	}
	body, err := readRequestBody(r)
	if err != nil {
		return apierr.New("REQUEST_BODY_TOO_LARGE", "request body exceeds the idempotency limit")
	}
	if r.Body != nil {
		_ = r.Body.Close()
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	var registration struct {
		Method string `json:"token_endpoint_auth_method"`
	}
	if json.Unmarshal(body, &registration) != nil {
		return apierr.New("VALIDATION_FAILED", "invalid application registration")
	}
	if registration.Method == "client_secret_basic" {
		return denied
	}
	return nil
}

func isSAMLBrowserPost(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	connection, ok := strings.CutPrefix(r.URL.Path, SAMLBrowserCallbackPrefix)
	if ok {
		return connection != "" && !strings.Contains(connection, "/")
	}
	path, ok := strings.CutPrefix(r.URL.Path, "/v1/sso/")
	if !ok {
		return false
	}
	connection, operation, ok := strings.Cut(path, "/")
	if !ok || connection == "" || operation != "callback" {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && (mediaType == "application/x-www-form-urlencoded" || mediaType == "multipart/form-data")
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
	if w.status == 0 {
		w.status = status
	}
}

func (w *idempotencyResponseWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.body.Write(body)
}

func (w *idempotencyResponseWriter) Flush() {
	if w.status == 0 {
		w.status = http.StatusOK
	}
}

func serveIdempotent(w http.ResponseWriter, r *http.Request, next http.Handler, plane Plane, manager idempotency.TransactionManager, validate idempotency.CredentialValidator) {
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if key == "" {
		next.ServeHTTP(w, r)
		return
	}
	if !validIdempotencyKey(key) {
		writeIdempotencyError(w, r.Context(), "IDEMPOTENCY_KEY_INVALID", "Idempotency-Key must be between 1 and 255 characters and contain no control characters.", http.StatusBadRequest)
		return
	}
	if validate != nil {
		if err := validate(r.Context(), string(plane), r.Header.Get("Authorization")); err != nil {
			writeRouteError(w, r.Context(), err)
			return
		}
	}
	body, err := readRequestBody(r)
	if err != nil {
		writeIdempotencyError(w, r.Context(), "REQUEST_BODY_TOO_LARGE", "request body exceeds the idempotency limit.", http.StatusRequestEntityTooLarge)
		return
	}
	if r.Body != nil {
		_ = r.Body.Close()
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	requestPrefix := r.Method + "\x00" + r.URL.RequestURI() + "\x00"
	if SCIMDirectoryID(r.Context()) != "" {
		requestPrefix += r.Header.Get("If-Match") + "\x00"
	}
	requestHash := sha256.Sum256([]byte(requestPrefix + string(body)))
	scopeHash := sha256.Sum256([]byte(string(plane) + "\x00" + requestScope(r)))
	tx, err := manager.BeginIdempotency(r.Context())
	if err != nil {
		writeIdempotencyError(w, r.Context(), "UNAVAILABLE", "idempotency storage is temporarily unavailable.", http.StatusServiceUnavailable)
		return
	}
	rollback := true
	defer func() {
		if rollback {
			_ = tx.Rollback(context.Background())
		}
	}()
	reservation, err := tx.Reserve(r.Context(), idempotency.Request{
		ScopeHash: hex.EncodeToString(scopeHash[:]), Method: r.Method,
		Path: r.URL.RequestURI(), Key: key, RequestHash: requestHash[:],
	})
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
		_ = tx.Rollback(context.Background())
		rollback = false
		requestID := w.Header().Get("X-Request-Id")
		copyHeader(w.Header(), reservation.Headers)
		w.Header().Set("X-Request-Id", requestID)
		w.Header().Set("Idempotency-Replayed", "true")
		w.WriteHeader(reservation.StatusCode)
		_, _ = w.Write(reservation.Body)
		return
	}
	request := r.WithContext(tx.Context(r.Context()))
	captured := newIdempotencyResponseWriter(w.Header())
	next.ServeHTTP(captured, request)
	status := captured.status
	if status == 0 {
		status = http.StatusOK
	}
	if err := tx.Complete(r.Context(), reservation.ID, idempotency.Response{
		StatusCode: status, Headers: captured.header, Body: captured.body.Bytes(),
	}); err != nil {
		writeIdempotencyError(w, r.Context(), "UNAVAILABLE", "idempotency result could not be stored.", http.StatusServiceUnavailable)
		return
	}
	commitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	err = tx.Commit(commitCtx)
	cancel()
	if err != nil {
		writeIdempotencyError(w, r.Context(), "UNAVAILABLE", "idempotency result could not be committed.", http.StatusServiceUnavailable)
		return
	}
	rollback = false
	copyHeader(w.Header(), captured.header)
	w.WriteHeader(status)
	_, _ = w.Write(captured.body.Bytes())
}

func requestScope(r *http.Request) string {
	if authorization := strings.TrimSpace(r.Header.Get("Authorization")); authorization != "" {
		return authorization
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return "anonymous\x00" + host
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
	if SCIMDirectoryID(ctx) != "" {
		WriteSCIMError(w, err)
		return
	}
	err = apierr.WithRequestID(err, requestinfo.Get(ctx).ID)
	apierr.Write(w, err)
}

func writeRouteError(w http.ResponseWriter, ctx context.Context, err error) {
	var public *apierr.Error
	if !errors.As(err, &public) {
		writeIdempotencyError(w, ctx, "UNAVAILABLE", "the service is temporarily unavailable.", http.StatusServiceUnavailable)
		return
	}
	public = apierr.WithRequestID(public, requestinfo.Get(ctx).ID)
	apierr.Write(w, public)
}
