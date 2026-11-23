package principal

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/jackc/pgx/v5"
	"github.com/plystra/auth/internal/account"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/requestinfo"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/secret"
)

const oidcInteractionCookie = "__Host-plystra-oidc"

type oidcBrowserStartInput struct {
	Origin string `header:"Origin"`
	Body   struct {
		ResponseType        string `json:"response_type" enum:"code"`
		ClientID            string `json:"client_id" minLength:"1" maxLength:"512"`
		RedirectURI         string `json:"redirect_uri" minLength:"1" maxLength:"4096"`
		Scope               string `json:"scope" minLength:"1" maxLength:"128"`
		State               string `json:"state" minLength:"1" maxLength:"1024"`
		Nonce               string `json:"nonce" minLength:"1" maxLength:"1024"`
		CodeChallenge       string `json:"code_challenge" minLength:"43" maxLength:"43"`
		CodeChallengeMethod string `json:"code_challenge_method" enum:"S256"`
	}
}

type OIDCBrowserInput struct {
	ID     string `path:"id"`
	Origin string `header:"Origin"`
	Cookie string `cookie:"__Host-plystra-oidc"`
}

type oidcBrowserIdentifyInput struct {
	OIDCBrowserInput
	Body struct {
		Email  string `json:"email" minLength:"1" maxLength:"320"`
		Method string `json:"method" enum:"password,passkey"`
	}
}

type oidcBrowserAuthenticateInput struct {
	OIDCBrowserInput
	UserAgent string `header:"User-Agent"`
	Body      struct {
		Password   secret.String   `json:"password,omitempty"`
		MFACode    secret.String   `json:"mfa_code,omitempty" minLength:"6" maxLength:"6"`
		Credential json.RawMessage `json:"credential,omitempty"`
	}
}

type oidcBrowserDecisionInput struct {
	OIDCBrowserInput
	Body struct {
		Decision string `json:"decision" enum:"approve,deny"`
	}
}

type oidcBrowserState struct {
	ID              string                        `json:"id"`
	ClientName      string                        `json:"client_name"`
	Scopes          []string                      `json:"scopes"`
	ExpiresAt       time.Time                     `json:"expires_at"`
	NextStep        string                        `json:"next_step"`
	SignedInEmail   string                        `json:"signed_in_email,omitempty"`
	SSOConnectionID string                        `json:"sso_connection_id,omitempty"`
	PasskeyOptions  *protocol.CredentialAssertion `json:"passkey_options,omitempty"`
}

type oidcBrowserCookieOutput[T any] struct {
	Cookie string `header:"Set-Cookie"`
	Body   struct {
		Data T `json:"data"`
	}
}

type oidcBrowserRedirect struct {
	RedirectTo string `json:"redirect_to"`
}

func (a *API) registerOIDCBrowserRoutes(api huma.API) {
	const path = route.OIDCInteractionsPath
	subjects := []route.Subject{route.Public}
	route.Register(api, route.NewSpec("oidc.interactions.start", http.MethodPost, path, route.Principal, "", subjects, route.WithStatus(http.StatusCreated)), a.startOIDCBrowserInteraction)
	route.Register(api, route.NewSpec("oidc.interactions.read", http.MethodGet, path+"/{id}", route.Principal, "", subjects), a.readOIDCBrowserInteraction)
	route.Register(api, route.NewSpec("oidc.interactions.identify", http.MethodPost, path+"/{id}/identify", route.Principal, "", subjects), a.identifyOIDCBrowserUser)
	route.Register(api, route.NewSpec("oidc.interactions.authenticate", http.MethodPost, path+"/{id}/authenticate", route.Principal, "", subjects), a.authenticateOIDCBrowserUser)
	route.Register(api, route.NewSpec("oidc.interactions.decision", http.MethodPost, path+"/{id}/decision", route.Principal, "", subjects), a.decideOIDCBrowserInteraction)
}

func (a *API) checkOIDCBrowserOrigin(origin string, write bool) error {
	if a.HostedOrigin == "" || a.Applications == nil || a.Accounts == nil || a.Sessions == nil {
		return apierr.New("UNAVAILABLE", "hosted sign-in is unavailable")
	}
	if (write || origin != "") && origin != a.HostedOrigin {
		return apierr.New("BROWSER_ORIGIN_REJECTED", "hosted sign-in requires the issuer origin")
	}
	return nil
}

func (a *API) startOIDCBrowserInteraction(ctx context.Context, in *oidcBrowserStartInput) (*oidcBrowserCookieOutput[oidcBrowserState], error) {
	if err := a.checkOIDCBrowserOrigin(in.Origin, true); err != nil {
		return nil, err
	}
	client, err := a.Applications.OAuthClient(ctx, in.Body.ClientID)
	if err != nil {
		return nil, err
	}
	interaction, err := a.Applications.StartOIDCBrowserLogin(ctx, application.OIDCLoginRequestInput{
		ApplicationID: client.ID, ClientID: in.Body.ClientID, RedirectURI: in.Body.RedirectURI,
		Scope: strings.Split(in.Body.Scope, " "), State: in.Body.State, Nonce: in.Body.Nonce,
		CodeChallenge: in.Body.CodeChallenge,
	})
	if err != nil {
		return nil, err
	}
	out := &oidcBrowserCookieOutput[oidcBrowserState]{
		Cookie: oidcCookie(interaction.RequestID.Value(), interaction.ExpiresAt, 0),
	}
	out.Body.Data = oidcBrowserState{
		ID: interaction.ID, ClientName: interaction.ClientName, Scopes: interaction.Scopes,
		ExpiresAt: interaction.ExpiresAt, NextStep: "identify",
	}
	return out, nil
}

func (a *API) readOIDCBrowserInteraction(ctx context.Context, in *OIDCBrowserInput) (*authorizationDataOutput[oidcBrowserState], error) {
	interaction, err := a.oidcBrowserInteraction(ctx, *in, false)
	if err != nil {
		return nil, err
	}
	state := oidcInteractionState(interaction)
	if interaction.BrowserSessionID.Valid {
		claims, active, err := a.Sessions.CheckOIDCBrowserSessionTx(ctx, a.Applications.Store.Queries(), interaction.BrowserSessionID.String)
		if err != nil {
			return nil, err
		}
		if !active {
			return nil, apierr.New("invalid_token", "the hosted sign-in session is no longer active")
		}
		user, err := a.Accounts.Me(ctx, claims)
		if err != nil {
			return nil, err
		}
		state.SignedInEmail = user.Email
	}
	return oidcStateOutput(state), nil
}

func (a *API) identifyOIDCBrowserUser(ctx context.Context, in *oidcBrowserIdentifyInput) (*authorizationDataOutput[oidcBrowserState], error) {
	interaction, err := a.oidcBrowserInteraction(ctx, in.OIDCBrowserInput, true)
	if err != nil {
		return nil, err
	}
	if interaction.BrowserAttemptID.Valid || interaction.BrowserSessionID.Valid {
		return nil, apierr.New("CONFLICT", "the interaction already has an authentication attempt")
	}
	state := oidcInteractionState(interaction)
	if a.Enterprise != nil {
		connection, err := a.Enterprise.ForcedConnectionForEmail(ctx, in.Body.Email)
		if err != nil {
			return nil, err
		}
		if connection != "" {
			state.NextStep, state.SSOConnectionID = "sso", connection
			return oidcStateOutput(state), nil
		}
	}
	login := account.LoginInput{Email: in.Body.Email, IP: requestinfo.Get(ctx).IP}
	var challenge account.SignInChallenge
	if in.Body.Method == "passkey" {
		challenge, err = a.Accounts.BeginPasskeySignIn(ctx, login)
	} else {
		challenge, err = a.Accounts.BeginSignIn(ctx, login)
	}
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(in.Cookie))
	changed, err := a.Applications.Store.Queries().SetOIDCBrowserAttempt(ctx, db.SetOIDCBrowserAttemptParams{
		ID: in.ID, RequestHash: digest[:], AttemptID: challenge.AttemptID,
	})
	if err != nil {
		return nil, err
	}
	if changed != 1 {
		return nil, apierr.New("CONFLICT", "the authentication interaction changed")
	}
	state.NextStep, state.PasskeyOptions = challenge.NextStep, challenge.PasskeyOptions
	return oidcStateOutput(state), nil
}

func (a *API) authenticateOIDCBrowserUser(ctx context.Context, in *oidcBrowserAuthenticateInput) (*authorizationDataOutput[oidcBrowserState], error) {
	interaction, err := a.oidcBrowserInteraction(ctx, in.OIDCBrowserInput, true)
	if err != nil {
		return nil, err
	}
	state := oidcInteractionState(interaction)
	password, code, hasCredential := in.Body.Password.Value(), in.Body.MFACode.Value(), len(in.Body.Credential) != 0
	count := 0
	for _, present := range []bool{password != "", code != "", hasCredential} {
		if present {
			count++
		}
	}
	if count != 1 || (password != "" && state.NextStep != "password") ||
		(code != "" && state.NextStep != "totp") || (hasCredential && state.NextStep != "passkey") {
		return nil, apierr.New("invalid_request", "submit only the credential for the current authentication step")
	}
	digest := sha256.Sum256([]byte(in.Cookie))
	ctx = account.WithSignInSessionBinding(ctx, func(ctx context.Context, q *db.Queries, attempt, sessionID string) error {
		changed, err := q.BindOIDCBrowserSession(ctx, db.BindOIDCBrowserSessionParams{
			ID: in.ID, RequestHash: digest[:], AttemptID: attempt, SessionID: sessionID,
		})
		if err != nil {
			return err
		}
		if changed != 1 {
			return apierr.New("invalid_request", "the authentication interaction expired or changed")
		}
		return nil
	})
	attempt, ip := interaction.BrowserAttemptID.String, requestinfo.Get(ctx).IP
	var result account.AuthResult
	switch state.NextStep {
	case "password":
		result, err = a.Accounts.CompleteSignIn(ctx, attempt, password, ip, in.UserAgent)
	case "totp":
		result, err = a.Accounts.CompleteSignInTOTP(ctx, attempt, code, ip, in.UserAgent)
	case "passkey":
		result, err = a.Accounts.CompletePasskeySignIn(ctx, attempt, in.Body.Credential, ip, in.UserAgent)
	}
	if err != nil {
		return nil, err
	}
	switch {
	case result.Tokens != nil:
		state.NextStep = "consent"
		state.SignedInEmail = result.User.Email
	case result.NextStep == "totp":
		state.NextStep = "totp"
	default:
		return nil, apierr.New("invalid_grant", "the authentication attempt did not issue a session")
	}
	return oidcStateOutput(state), nil
}

func (a *API) decideOIDCBrowserInteraction(ctx context.Context, in *oidcBrowserDecisionInput) (*oidcBrowserCookieOutput[oidcBrowserRedirect], error) {
	if err := a.checkOIDCBrowserOrigin(in.Origin, true); err != nil {
		return nil, err
	}
	redirect, err := a.Applications.DecideOIDCBrowserLogin(ctx, a.Sessions, in.ID, secret.New(in.Cookie), in.Body.Decision)
	if err != nil {
		return nil, err
	}
	out := &oidcBrowserCookieOutput[oidcBrowserRedirect]{Cookie: oidcCookie("", time.Unix(0, 0).UTC(), -1)}
	out.Body.Data.RedirectTo = redirect
	return out, nil
}

func (a *API) oidcBrowserInteraction(ctx context.Context, in OIDCBrowserInput, write bool) (db.GetPendingOIDCBrowserInteractionRow, error) {
	if err := a.checkOIDCBrowserOrigin(in.Origin, write); err != nil {
		return db.GetPendingOIDCBrowserInteractionRow{}, err
	}
	digest := sha256.Sum256([]byte(in.Cookie))
	interaction, err := a.Applications.Store.Queries().GetPendingOIDCBrowserInteraction(ctx, db.GetPendingOIDCBrowserInteractionParams{
		ID: in.ID, RequestHash: digest[:],
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return db.GetPendingOIDCBrowserInteractionRow{}, apierr.New("invalid_request", "the authentication interaction is invalid or expired")
	}
	return interaction, err
}

func oidcInteractionState(interaction db.GetPendingOIDCBrowserInteractionRow) oidcBrowserState {
	step := "identify"
	switch {
	case interaction.BrowserSessionID.Valid:
		step = "consent"
	case interaction.NeedsTotp:
		step = "totp"
	case interaction.BrowserAttemptID.Valid:
		step = interaction.SignInMethod
	}
	return oidcBrowserState{
		ID: interaction.ID, ClientName: interaction.ClientName, Scopes: strings.Split(interaction.Scope, " "),
		ExpiresAt: interaction.ExpiresAt.Time, NextStep: step,
	}
}

func oidcStateOutput(state oidcBrowserState) *authorizationDataOutput[oidcBrowserState] {
	out := &authorizationDataOutput[oidcBrowserState]{}
	out.Body.Data = state
	return out
}

func oidcCookie(value string, expires time.Time, maxAge int) string {
	return (&http.Cookie{
		Name: oidcInteractionCookie, Value: value, Path: "/", Expires: expires,
		MaxAge: maxAge, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	}).String()
}
