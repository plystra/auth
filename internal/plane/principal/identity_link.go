package principal

import (
	"context"

	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/enterprise"
	"github.com/plystra/auth/internal/secret"
)

type ssoIdentityLinkInput struct {
	Authorization string `header:"Authorization"`
	ConnectionID  string `path:"connection_id"`
}

type ssoIdentityLinkStartOutput struct {
	CacheControl string `header:"Cache-Control"`
	Body         struct {
		Data enterprise.StartResult `json:"data"`
	}
}

type ssoIdentityLinkCompleteInput struct {
	Authorization string `header:"Authorization"`
	ConnectionID  string `path:"connection_id"`
	Body          struct {
		State        string        `json:"state"`
		Code         string        `json:"code,omitempty"`
		SAMLResponse secret.String `json:"saml_response,omitempty"`
	}
}

type ssoIdentityLinkCompleteOutput struct {
	Body struct {
		Data struct {
			Linked bool `json:"linked"`
		} `json:"data"`
	}
}

func (a *API) startSSOIdentityLink(ctx context.Context, in *ssoIdentityLinkInput) (*ssoIdentityLinkStartOutput, error) {
	claims, err := a.userClaims(ctx, in.Authorization)
	if err != nil {
		return nil, err
	}
	if a.Enterprise == nil {
		return nil, apierr.New("unavailable", "enterprise SSO is unavailable")
	}
	result, err := a.Enterprise.StartIdentityLink(ctx, in.ConnectionID, claims.Subject, claims.SessionID)
	if err != nil {
		return nil, err
	}
	out := &ssoIdentityLinkStartOutput{CacheControl: "no-store"}
	out.Body.Data = result
	return out, nil
}

func (a *API) completeSSOIdentityLink(ctx context.Context, in *ssoIdentityLinkCompleteInput) (*ssoIdentityLinkCompleteOutput, error) {
	claims, err := a.userClaims(ctx, in.Authorization)
	if err != nil {
		return nil, err
	}
	if a.Enterprise == nil {
		return nil, apierr.New("unavailable", "enterprise SSO is unavailable")
	}
	if err := a.Enterprise.CompleteIdentityLink(ctx, in.ConnectionID, claims.Subject, claims.SessionID, in.Body.State, in.Body.Code, in.Body.SAMLResponse.Value()); err != nil {
		return nil, err
	}
	out := &ssoIdentityLinkCompleteOutput{}
	out.Body.Data.Linked = true
	return out, nil
}
