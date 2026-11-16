package server

import (
	"context"
	"errors"
	"strings"

	"github.com/plystra/auth/internal/apierr"
)

func (a *API) introspectIdentity(ctx context.Context, token, audience string) (IntrospectIdentity, bool, error) {
	if strings.HasPrefix(strings.TrimSpace(token), "ply_ag_") {
		if a.Agents == nil {
			return IntrospectIdentity{}, false, apierr.New("UNAVAILABLE", "Agent introspection is unavailable")
		}
		credential, err := a.Agents.AuthenticateKey(ctx, token)
		if err != nil {
			var public *apierr.Error
			if errors.As(err, &public) && public.Code == "UNAUTHENTICATED" {
				return IntrospectIdentity{}, false, nil
			}
			return IntrospectIdentity{}, false, err
		}
		return a.introspectAgentIdentity(ctx, IntrospectIdentity{Subject: credential.MemberID, ExpiresAt: credential.ExpiresAt.Unix()})
	}
	if a.Sessions == nil {
		return IntrospectIdentity{}, false, apierr.New("UNAVAILABLE", "token introspection is unavailable")
	}
	claims, active, err := a.Sessions.Introspect(ctx, token, audience)
	if err != nil || !active {
		return IntrospectIdentity{}, false, err
	}
	identity := IntrospectIdentity{Subject: claims.Subject, SessionID: claims.SessionID, ExpiresAt: claims.ExpiresAt}
	if claims.Type == "agent" {
		return a.introspectAgentIdentity(ctx, identity)
	}
	identity.UserID = claims.Subject
	if claims.MemberID != "" {
		identity.MemberID, identity.MemberType, identity.SpaceID = claims.MemberID, "human", claims.SpaceID
	}
	return identity, true, nil
}

func (a *API) introspectAgentIdentity(ctx context.Context, identity IntrospectIdentity) (IntrospectIdentity, bool, error) {
	if a.Agents == nil {
		return IntrospectIdentity{}, false, apierr.New("UNAVAILABLE", "Agent introspection is unavailable")
	}
	current, active, err := a.Agents.IntrospectionIdentity(ctx, identity.Subject)
	if err != nil || !active {
		return IntrospectIdentity{}, false, err
	}
	identity.MemberID, identity.MemberType, identity.SpaceID = current.MemberID, "agent", current.SpaceID
	identity.OwnerChain = current.OwnerChain
	identity.ExpiresAt = min(identity.ExpiresAt, current.ExpiresAt.Unix())
	return identity, true, nil
}
