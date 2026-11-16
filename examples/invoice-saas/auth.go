package invoicesaas

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/secret"
)

type AuthConfig struct {
	Issuer, ServerURL, ClientID, JWKSURL string
	APIKey                               secret.String
	HTTPClient                           *http.Client
}

type AuthClient struct {
	config AuthConfig
	http   *http.Client
	keys   keyCache
}

func NewAuthClient(config AuthConfig) (*AuthClient, error) {
	if config.ClientID == "" || config.APIKey.Value() == "" {
		return nil, errors.New("auth client ID and API key are required")
	}
	if config.JWKSURL == "" {
		config.JWKSURL = strings.TrimRight(config.Issuer, "/") + "/.well-known/jwks.json"
	}
	for _, endpoint := range []string{config.Issuer, config.ServerURL, config.JWKSURL} {
		if !safeEndpoint(endpoint) {
			return nil, errors.New("auth endpoints require HTTPS, or HTTP on an explicit loopback address")
		}
	}
	client := http.Client{Timeout: 5 * time.Second}
	if config.HTTPClient != nil {
		client = *config.HTTPClient
		if client.Timeout <= 0 {
			client.Timeout = 5 * time.Second
		}
	}
	// Never forward a credential to a redirect target, including the same host.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &AuthClient{config: config, http: &client}, nil
}

func safeEndpoint(raw string) bool {
	endpoint, err := url.Parse(raw)
	if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return false
	}
	if endpoint.Scheme == "https" {
		return true
	}
	ip := net.ParseIP(endpoint.Hostname())
	return endpoint.Scheme == "http" && ip != nil && ip.IsLoopback()
}

type resource struct {
	Type    string `json:"type"`
	ID      string `json:"id"`
	SpaceID string `json:"space_id"`
	GroupID string `json:"group_id"`
}

type checkRequest struct {
	Subject struct {
		Token string `json:"token"`
	} `json:"subject"`
	Action        string   `json:"action"`
	Resource      resource `json:"resource"`
	RequestDigest string   `json:"request_digest,omitempty"`
	Reason        string   `json:"reason,omitempty"`
}

type decision struct {
	Decision   string `json:"decision"`
	DenyCode   string `json:"deny_code"`
	DecisionID string `json:"decision_id"`
}

func (c *AuthClient) check(ctx context.Context, token secret.String, action string, target resource, requestID string) (decision, error) {
	input := checkRequest{Action: action, Resource: target}
	input.Subject.Token = token.Value()
	var response struct {
		Data decision `json:"data"`
	}
	if err := c.post(ctx, "/server/v1/authz/check", input, &response, requestID); err != nil {
		return decision{}, err
	}
	if response.Data.DecisionID == "" || (response.Data.Decision != "allow" && response.Data.Decision != "deny") ||
		(response.Data.Decision == "deny" && response.Data.DenyCode == "") ||
		(response.Data.Decision == "allow" && response.Data.DenyCode != "") {
		return decision{}, unavailable()
	}
	return response.Data, nil
}

func (c *AuthClient) requestApproval(ctx context.Context, token secret.String, target resource, digest, reason, requestID string) (string, error) {
	input := checkRequest{Action: "invoice:approve", Resource: target, RequestDigest: digest, Reason: reason}
	input.Subject.Token = token.Value()
	var response struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := c.post(ctx, "/server/v1/approvals", input, &response, requestID); err != nil {
		return "", err
	}
	if response.Data.ID == "" {
		return "", unavailable()
	}
	return response.Data.ID, nil
}

func (c *AuthClient) post(ctx context.Context, path string, input, output any, requestID string) error {
	body, err := json.Marshal(input)
	if err != nil {
		return unavailable()
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.config.ServerURL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return unavailable()
	}
	request.Header.Set("Authorization", "Bearer "+c.config.APIKey.Value())
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Request-Id", requestID)
	response, err := c.http.Do(request)
	if err != nil {
		return unavailable()
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return unavailable()
	}
	body, err = readBounded(response.Body)
	if err != nil || json.Unmarshal(body, output) != nil {
		return unavailable()
	}
	return nil
}

func readBounded(reader io.Reader) ([]byte, error) {
	const limit = 1 << 20
	body, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil || len(body) > limit {
		return nil, errors.New("invalid Auth response")
	}
	return body, nil
}

func unavailable() *apierr.Error {
	return apierr.New("UNAVAILABLE", "Authorization or storage is unavailable.")
}
