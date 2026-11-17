package protocol

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/session"
	"github.com/plystra/auth/internal/store"
)

type tokenTransportFixture struct {
	store    *store.Store
	sessions *session.Service
	handler  http.Handler
	form     url.Values
	memberID string
	audience string
}

func newTokenTransportFixture(t *testing.T, grant string) tokenTransportFixture {
	t.Helper()
	if grant == "authorization_code" || grant == "refresh_token" {
		f := newRedemptionFixture(t)
		return tokenTransportFixture{f.store, f.sessions, f.handler, f.form(grant), f.agent.ID, "app_redemption"}
	}
	f := newDelegationAuditFixture(t)
	form := url.Values{"grant_type": {"agent_key"}, "agent_key": {f.parentKey}, "resource": {security.DefaultApplicationAudience}}
	memberID := f.parent.ID
	if grant == "token_exchange" {
		form = url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"},
			"subject_token": {f.parentToken}, "actor_token": {f.childKey}, "scope": {"auth.members:read"},
			"resource": {security.DefaultApplicationAudience}}
		memberID = f.child.ID
	}
	return tokenTransportFixture{f.store, f.sessions, f.handler, form, memberID, security.DefaultApplicationAudience}
}

type tokenTransportState struct {
	ConsumedCodes, Credentials, UsedCredentials, RevokedCredentials int
	Issued, RefreshCreated, RefreshRotated, Replays                 int
	LastUsed                                                        *time.Time
}

func (f tokenTransportFixture) state(t *testing.T, ctx context.Context) tokenTransportState {
	t.Helper()
	var state tokenTransportState
	err := f.store.Pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM authorization_codes WHERE consumed_at IS NOT NULL),
		(SELECT count(*) FROM agent_credentials),
		(SELECT count(*) FROM agent_credentials WHERE last_used_at IS NOT NULL),
		(SELECT count(*) FROM agent_credentials WHERE revoked_at IS NOT NULL),
		(SELECT count(*) FROM audit_logs WHERE action IN ('agent.access.issue', 'agent.token.exchange')),
		(SELECT count(*) FROM audit_logs WHERE action = 'agent.oauth_refresh.create'),
		(SELECT count(*) FROM audit_logs WHERE action = 'agent.oauth_refresh'),
		(SELECT count(*) FROM audit_logs WHERE action = 'agent.oauth_refresh.replay'),
		(SELECT max(last_used_at) FROM agent_credentials WHERE member_id = $1)`, f.memberID).
		Scan(&state.ConsumedCodes, &state.Credentials, &state.UsedCredentials, &state.RevokedCredentials,
			&state.Issued, &state.RefreshCreated, &state.RefreshRotated, &state.Replays, &state.LastUsed)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

// commitDisconnectConn cuts an actual PostgreSQL connection at the COMMIT
// boundary. The after case consumes the server's COMMIT and ReadyForQuery
// messages without exposing them to pgx, so the transaction really committed
// while the application receives a connection error.
type commitDisconnectConn struct {
	net.Conn
	fault  *commitDisconnect
	drop   atomic.Bool
	readMu sync.Mutex
	buffer []byte
}

type commitDisconnect struct {
	afterCommit bool
	armed       atomic.Bool
	fired       atomic.Bool
	committed   atomic.Bool
}

func (c *commitDisconnectConn) Write(p []byte) (int, error) {
	commit := len(p) >= 6 && p[0] == 'Q' && int(binary.BigEndian.Uint32(p[1:5])) == len(p)-1 &&
		strings.EqualFold(string(p[5:len(p)-1]), "commit")
	if !commit || !c.fault.armed.CompareAndSwap(true, false) {
		return c.Conn.Write(p)
	}
	c.fault.fired.Store(true)
	if !c.fault.afterCommit {
		_ = c.Close()
		return 0, io.ErrClosedPipe
	}
	c.drop.Store(true)
	return c.Conn.Write(p)
}

func (c *commitDisconnectConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	if len(c.buffer) == 0 {
		frame, err := c.readFrame()
		if err != nil {
			return 0, err
		}
		if c.drop.Load() && frame[0] == 'C' && string(frame[5:]) == "COMMIT\x00" {
			defer func() { _ = c.Close() }()
			for {
				frame, err = c.readFrame()
				if err != nil {
					return 0, err
				}
				if frame[0] == 'Z' {
					if len(frame) != 6 || frame[5] != 'I' {
						return 0, errors.New("injected COMMIT did not finish successfully")
					}
					c.fault.committed.Store(true)
					return 0, io.EOF
				}
			}
		}
		c.buffer = frame
	}
	n := copy(p, c.buffer)
	c.buffer = c.buffer[n:]
	return n, nil
}

func (c *commitDisconnectConn) readFrame() ([]byte, error) {
	var header [5]byte
	if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint32(header[1:]))
	if length < 4 || length > 16<<20 {
		return nil, errors.New("invalid PostgreSQL frame in transport fault test")
	}
	frame := make([]byte, length+1)
	copy(frame, header[:])
	_, err := io.ReadFull(c.Conn, frame[5:])
	return frame, err
}

func disconnectTokenCommit(t *testing.T, ctx context.Context, st *store.Store, afterCommit bool) *commitDisconnect {
	t.Helper()
	original := st.Pool
	config := original.Config()
	if config.ConnConfig.TLSConfig != nil {
		t.Fatal("PostgreSQL transport fault test requires the isolated plaintext test connection")
	}
	fault := &commitDisconnect{afterCommit: afterCommit}
	dial := config.ConnConfig.DialFunc
	config.ConnConfig.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return &commitDisconnectConn{Conn: conn, fault: fault}, nil
	}
	config.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	st.Pool = pool
	t.Cleanup(func() {
		pool.Close()
		st.Pool = original
	})
	fault.armed.Store(true)
	return fault
}

func TestTokenRedemptionTransportFailureRetryBoundaries(t *testing.T) {
	for _, grant := range []string{"authorization_code", "refresh_token", "agent_key", "token_exchange"} {
		for _, failure := range []string{"BeforeCommit", "CommitAcknowledgementLost", "HTTPResponseLost"} {
			t.Run(grant+"/"+failure, func(t *testing.T) {
				f := newTokenTransportFixture(t, grant)
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				before := f.state(t, ctx)
				var fault *commitDisconnect
				if failure != "HTTPResponseLost" {
					fault = disconnectTokenCommit(t, ctx, f.store, failure == "CommitAcknowledgementLost")
				}
				var dropResponse atomic.Bool
				dropResponse.Store(failure == "HTTPResponseLost")
				dropped := make(chan []byte, 1)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					response := httptest.NewRecorder()
					f.handler.ServeHTTP(response, r)
					if dropResponse.CompareAndSwap(true, false) {
						if response.Code != http.StatusOK {
							t.Errorf("response-loss injection did not reach successful issuance: status=%d", response.Code)
						}
						dropped <- append([]byte(nil), response.Body.Bytes()...)
						conn, _, err := w.(http.Hijacker).Hijack()
						if err != nil {
							t.Error(err)
							return
						}
						_ = conn.Close()
						return
					}
					for name, values := range response.Header() {
						w.Header()[name] = values
					}
					w.WriteHeader(response.Code)
					_, _ = w.Write(response.Body.Bytes())
				}))
				t.Cleanup(server.Close)
				request := func(form url.Values) (int, []byte, error) {
					r, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/oauth/token", strings.NewReader(form.Encode()))
					if err != nil {
						t.Fatal(err)
					}
					r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					response, err := server.Client().Do(r)
					if err != nil {
						return 0, nil, err
					}
					defer func() { _ = response.Body.Close() }()
					body, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
					return response.StatusCode, body, err
				}
				status, body, err := request(f.form)
				if failure == "HTTPResponseLost" {
					if err == nil || len(body) != 0 {
						t.Fatal("client received credentials despite the dropped HTTP response")
					}
				} else {
					if err != nil || status != http.StatusServiceUnavailable || !strings.Contains(string(body), "temporarily_unavailable") || strings.Contains(string(body), "access_token") || strings.Contains(string(body), "refresh_token") {
						t.Fatalf("database disconnection returned credentials or the wrong error: status=%d error=%v", status, err)
					}
					if !fault.fired.Load() || fault.committed.Load() != fault.afterCommit {
						t.Fatal("database disconnection did not exercise the intended COMMIT boundary")
					}
				}
				after := f.state(t, ctx)
				if failure == "BeforeCommit" {
					if diff := cmp.Diff(before, after); diff != "" {
						t.Fatalf("uncommitted exchange changed persistent state (-before +after):\n%s", diff)
					}
				} else {
					want := before
					want.Issued++
					switch grant {
					case "authorization_code":
						want.ConsumedCodes++
						want.Credentials++
						want.RefreshCreated++
					case "refresh_token":
						want.Credentials++
						want.UsedCredentials++
						want.RefreshRotated++
						want.LastUsed = after.LastUsed
					case "token_exchange":
						want.UsedCredentials++
						want.LastUsed = after.LastUsed
					default:
						want.LastUsed = after.LastUsed
					}
					if grant != "authorization_code" && (after.LastUsed == nil || before.LastUsed != nil && !after.LastUsed.After(*before.LastUsed)) {
						t.Fatal("committed issuance omitted credential usage")
					}
					if diff := cmp.Diff(want, after); diff != "" {
						t.Fatalf("lost response did not preserve an atomic committed exchange (-want +got):\n%s", diff)
					}
				}
				status, body, err = request(f.form)
				if err != nil {
					t.Fatal(err)
				}
				oauth := grant == "authorization_code" || grant == "refresh_token"
				if failure != "BeforeCommit" && oauth {
					if status != http.StatusBadRequest || !strings.Contains(string(body), "invalid_grant") || strings.Contains(string(body), "access_token") {
						t.Fatalf("consumed OAuth credential was reused after response loss: status=%d", status)
					}
					retried := f.state(t, ctx)
					if grant == "refresh_token" {
						after.Replays++
						after.RevokedCredentials = after.Credentials
					}
					if diff := cmp.Diff(after, retried); diff != "" {
						t.Fatalf("OAuth retry changed more than replay protection (-want +got):\n%s", diff)
					}
					if grant == "refresh_token" && failure == "HTTPResponseLost" {
						var hidden struct {
							Refresh string `json:"refresh_token"`
						}
						if err := json.Unmarshal(<-dropped, &hidden); err != nil || hidden.Refresh == "" {
							t.Fatal("dropped response did not include a refresh successor")
						}
						form := maps.Clone(f.form)
						form.Set("refresh_token", hidden.Refresh)
						status, body, err := request(form)
						if err != nil || status != http.StatusBadRequest || !strings.Contains(string(body), "invalid_grant") {
							t.Fatal("lost refresh successor survived replay revocation")
						}
					}
					return
				}
				var returned struct {
					Access string `json:"access_token"`
				}
				if status != http.StatusOK || json.Unmarshal(body, &returned) != nil || returned.Access == "" {
					t.Fatalf("retry with a reusable credential failed: status=%d", status)
				}
				claims, err := f.sessions.Signer.Verify(returned.Access, time.Now(), f.audience)
				if err != nil || claims.Subject != f.memberID {
					t.Fatal("retry returned an invalid token or identity")
				}
				if retried := f.state(t, ctx); retried.Issued != after.Issued+1 {
					t.Fatal("retry did not commit exactly one additional issuance")
				}
			})
		}
	}
}
