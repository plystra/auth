package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/member"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/session"
)

type API struct {
	Applications  *application.Service
	Members       *member.Service
	Authorization *authorization.Service
	Sessions      *session.Service
	Agents        *agent.Service
}

type CheckSubject struct {
	Token    string   `json:"token,omitempty"`
	MemberID string   `json:"member_id,omitempty"`
	UserID   string   `json:"user_id,omitempty"`
	_        struct{} `json:"-" additionalProperties:"true"`
	unknown  []string
}

func (s *CheckSubject) UnmarshalJSON(data []byte) error {
	var fields struct {
		Token    string `json:"token,omitempty"`
		MemberID string `json:"member_id,omitempty"`
		UserID   string `json:"user_id,omitempty"`
	}
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	var values map[string]json.RawMessage
	if err := json.Unmarshal(data, &values); err != nil {
		return err
	}
	known := map[string]struct{}{"token": {}, "member_id": {}, "user_id": {}}
	unknown := make([]string, 0)
	for key := range values {
		if _, ok := known[key]; !ok {
			unknown = append(unknown, key)
		}
	}
	s.Token = fields.Token
	s.MemberID = fields.MemberID
	s.UserID = fields.UserID
	s.unknown = unknown
	return nil
}

type CheckResource struct {
	Type          string `json:"type"`
	ID            string `json:"id"`
	SpaceID       string `json:"space_id,omitempty"`
	GroupID       string `json:"group_id,omitempty"`
	OwnerMemberID string `json:"owner_member_id,omitempty"`
}

type CheckBody struct {
	Subject  CheckSubject    `json:"subject"`
	Action   string          `json:"action"`
	Resource CheckResource   `json:"resource"`
	Grants   json.RawMessage `json:"grants,omitempty"`
	Roles    json.RawMessage `json:"roles,omitempty"`
}

type CheckInput struct {
	Authorization string `header:"Authorization"`
	Body          CheckBody
}

type CheckDecision struct {
	Decision      string `json:"decision"`
	DenyCode      string `json:"deny_code,omitempty"`
	DecisionID    string `json:"decision_id"`
	PolicyVersion string `json:"policy_version"`
}

type CheckOutput struct {
	Body struct {
		Data CheckDecision `json:"data"`
	}
}

type ExplainStep struct {
	Step   string `json:"step"`
	Result string `json:"result"`
	Detail string `json:"detail"`
}

type ExplainDecision struct {
	Decision      string        `json:"decision"`
	DenyCode      string        `json:"deny_code,omitempty"`
	DecisionID    string        `json:"decision_id"`
	PolicyVersion string        `json:"policy_version"`
	Summary       string        `json:"summary"`
	Trace         []ExplainStep `json:"trace"`
}

type ExplainOutput struct {
	Body struct {
		Data ExplainDecision `json:"data"`
	}
}

type BatchCheckBody struct {
	Requests []CheckBody `json:"requests"`
}

type BatchCheckInput struct {
	Authorization string `header:"Authorization"`
	Body          BatchCheckBody
}

type BatchCheckOutput struct {
	Body struct {
		Data []CheckDecision `json:"data"`
	}
}

type IntrospectInput struct {
	Authorization string `header:"Authorization"`
	Body          struct {
		Token string `json:"token"`
	}
}

type IntrospectOutput struct {
	Body struct {
		Data struct {
			Active    bool   `json:"active"`
			Subject   string `json:"sub,omitempty"`
			SessionID string `json:"sid,omitempty"`
			ExpiresAt int64  `json:"exp,omitempty"`
		} `json:"data"`
	}
}

type resolvedSubject struct {
	ID     string
	Type   string
	Scopes []string
}

func (a *API) Register(api huma.API) {
	route.Register(api, route.NewSpec("authz.check", "POST", "/server/v1/authz/check", route.Server, "auth.authz:check", []route.Subject{route.HumanAgent}, route.WithAuthoritativeCheck()), a.check)
	route.Register(api, route.NewSpec("authz.batch_check", "POST", "/server/v1/authz/batch-check", route.Server, "auth.authz:check", []route.Subject{route.HumanAgent}, route.WithAuthoritativeCheck(), route.WithMaxBodyBytes(256*1024)), a.batchCheck)
	route.Register(api, route.NewSpec("authz.explain", "POST", "/server/v1/authz/explain", route.Server, "auth.authz:explain", []route.Subject{route.HumanAgent}, route.WithAuthoritativeCheck()), a.explain)
	route.Register(api, route.NewSpec("tokens.introspect", "POST", "/server/v1/tokens/introspect", route.Server, "auth.tokens:introspect", []route.Subject{route.HumanAgent}), a.introspect)
}

func (a *API) check(ctx context.Context, in *CheckInput) (*CheckOutput, error) {
	if len(in.Body.Grants) > 0 || len(in.Body.Roles) > 0 || len(in.Body.Subject.unknown) > 0 {
		return nil, apierr.New("INLINE_GRANTS_NOT_ALLOWED", "authorization facts must come from Auth state, not the request")
	}
	key, err := a.key(ctx, in.Authorization)
	if err != nil {
		return nil, err
	}
	return a.checkWithKey(ctx, key, in.Body)
}

func (a *API) batchCheck(ctx context.Context, in *BatchCheckInput) (*BatchCheckOutput, error) {
	if len(in.Body.Requests) == 0 || len(in.Body.Requests) > 100 {
		return nil, apierr.New("VALIDATION_FAILED", "requests must contain between 1 and 100 items")
	}
	key, err := a.key(ctx, in.Authorization)
	if err != nil {
		return nil, err
	}
	if !contains(key.Scopes, "auth.authz:check") {
		return nil, apierr.New("PERMISSION_DENIED", "API key is not scoped for authorization checks.")
	}
	out := &BatchCheckOutput{}
	out.Body.Data = make([]CheckDecision, 0, len(in.Body.Requests))
	for _, body := range in.Body.Requests {
		decision, checkErr := a.checkWithKey(ctx, key, body)
		if checkErr != nil {
			return nil, checkErr
		}
		out.Body.Data = append(out.Body.Data, decision.Body.Data)
	}
	return out, nil
}

func (a *API) explain(ctx context.Context, in *CheckInput) (*ExplainOutput, error) {
	if len(in.Body.Grants) > 0 || len(in.Body.Roles) > 0 || len(in.Body.Subject.unknown) > 0 {
		return nil, apierr.New("INLINE_GRANTS_NOT_ALLOWED", "authorization facts must come from Auth state, not the request")
	}
	key, err := a.key(ctx, in.Authorization)
	if err != nil {
		return nil, err
	}
	evaluation, err := a.evaluateWithKey(ctx, key, in.Body, "auth.authz:explain")
	if err != nil {
		return nil, err
	}
	if err := a.writeDenyAudit(ctx, key, in.Body, evaluation.decision, "authz.explain"); err != nil {
		return nil, err
	}
	out := &ExplainOutput{}
	out.Body.Data = ExplainDecision{
		Decision:      string(evaluation.decision.Effect),
		DecisionID:    string(ids.New[ids.ID]("dec")),
		PolicyVersion: strconv.FormatInt(evaluation.policyVersion, 10),
		Summary:       explainSummary(in.Body.Action, evaluation.decision),
		Trace:         explainTrace(evaluation.decision),
	}
	if evaluation.decision.Effect == engine.Deny {
		out.Body.Data.DenyCode = evaluation.decision.Code
	}
	return out, nil
}

func (a *API) checkWithKey(ctx context.Context, key application.Key, body CheckBody) (*CheckOutput, error) {
	evaluation, err := a.evaluateWithKey(ctx, key, body, "auth.authz:check")
	if err != nil {
		return nil, err
	}
	return a.writeDecisionWithVersion(ctx, key, body, evaluation.memberID, evaluation.spaceID, evaluation.decision, evaluation.policyVersion)
}

type authorizationEvaluation struct {
	decision      engine.Decision
	policyVersion int64
	memberID      string
	spaceID       string
}

func (a *API) evaluateWithKey(ctx context.Context, key application.Key, body CheckBody, requiredScope string) (authorizationEvaluation, error) {
	if len(body.Grants) > 0 || len(body.Roles) > 0 || len(body.Subject.unknown) > 0 {
		return authorizationEvaluation{}, apierr.New("INLINE_GRANTS_NOT_ALLOWED", "authorization facts must come from Auth state, not the request")
	}
	if !contains(key.Scopes, requiredScope) {
		return authorizationEvaluation{}, apierr.New("PERMISSION_DENIED", "API key is not scoped for this authorization operation.")
	}
	if a.Authorization == nil {
		return authorizationEvaluation{}, apierr.New("UNAVAILABLE", "authorization is unavailable")
	}
	spaceID := strings.TrimSpace(body.Resource.SpaceID)
	if spaceID == "" {
		spaceID = key.SpaceID
	}
	if spaceID != key.SpaceID {
		version, err := a.Authorization.PolicyVersion(ctx, spaceID)
		if err != nil {
			return authorizationEvaluation{}, err
		}
		return authorizationEvaluation{decision: engine.Decision{Effect: engine.Deny, Code: "KEY_SCOPE_EXCLUDED"}, policyVersion: version, spaceID: spaceID}, nil
	}
	resolved, err := a.resolveSubject(ctx, key, body.Subject, spaceID)
	if err != nil {
		return authorizationEvaluation{}, err
	}
	memberID := resolved.ID
	permission := strings.TrimSpace(body.Action)
	if len(resolved.Scopes) > 0 && !contains(resolved.Scopes, permission) {
		policyVersion, versionErr := a.Authorization.PolicyVersion(ctx, spaceID)
		if versionErr != nil {
			return authorizationEvaluation{}, versionErr
		}
		return authorizationEvaluation{decision: engine.Decision{Effect: engine.Deny, Code: "TOKEN_SCOPE_EXCLUDED", Trace: []string{"delegated token scope excludes permission"}}, policyVersion: policyVersion, memberID: memberID, spaceID: spaceID}, nil
	}
	decision, policyVersion, err := a.Authorization.Check(ctx, authorization.CheckRequest{
		MemberID: memberID, Permission: permission, ResourceSpace: spaceID,
		ResourceGroup: body.Resource.GroupID, ResourceOwner: body.Resource.OwnerMemberID,
	})
	if err != nil {
		return authorizationEvaluation{}, err
	}
	return authorizationEvaluation{decision: decision, policyVersion: policyVersion, memberID: memberID, spaceID: spaceID}, nil
}

func (a *API) resolveSubject(ctx context.Context, key application.Key, subject CheckSubject, spaceID string) (resolvedSubject, error) {
	if subject.Token != "" {
		if strings.HasPrefix(subject.Token, "ply_ag_") && a.Agents != nil {
			credential, err := a.Agents.AuthenticateKey(ctx, subject.Token)
			if err != nil {
				return resolvedSubject{}, err
			}
			return resolvedSubject{ID: credential.MemberID, Type: "agent"}, nil
		}
		if a.Sessions == nil {
			return resolvedSubject{}, apierr.New("UNAVAILABLE", "authentication is unavailable")
		}
		claims, active, err := a.Sessions.Introspect(ctx, subject.Token, key.ClientID)
		if err != nil {
			return resolvedSubject{}, err
		}
		if !active {
			return resolvedSubject{}, apierr.New("UNAUTHENTICATED", "the subject token is invalid")
		}
		if claims.Type == "agent" {
			return resolvedSubject{ID: claims.Subject, Type: "agent", Scopes: claims.Scopes}, nil
		}
		if a.Authorization == nil {
			return resolvedSubject{}, apierr.New("UNAVAILABLE", "authorization is unavailable")
		}
		if claims.MemberID != "" && subject.MemberID != "" && subject.MemberID != claims.MemberID {
			return resolvedSubject{}, apierr.New("SUBJECT_NOT_FOUND", "the subject token and member do not match")
		}
		var member authorization.Member
		if claims.MemberID != "" {
			member, err = a.Authorization.GetMember(ctx, claims.MemberID, spaceID)
		} else {
			member, err = a.Authorization.GetMemberForUser(ctx, claims.Subject, spaceID)
		}
		if err != nil {
			return resolvedSubject{}, err
		}
		if subject.MemberID != "" && subject.MemberID != member.ID {
			return resolvedSubject{}, apierr.New("SUBJECT_NOT_FOUND", "the subject token and member do not match")
		}
		return resolvedSubject{ID: member.ID, Type: member.Kind}, nil
	}
	if subject.MemberID == "" {
		return resolvedSubject{}, apierr.New("VALIDATION_FAILED", "subject.token is required")
	}
	if !key.AllowSubjectAssertion {
		return resolvedSubject{}, apierr.New("VALIDATION_FAILED", "member_id subject assertions are not enabled for this API key")
	}
	if a.Authorization == nil {
		return resolvedSubject{ID: subject.MemberID, Type: "human"}, nil
	}
	member, err := a.Authorization.GetMember(ctx, subject.MemberID, spaceID)
	if err != nil {
		return resolvedSubject{}, err
	}
	if subject.UserID != "" {
		bound, err := a.Authorization.GetMemberForUser(ctx, subject.UserID, spaceID)
		if err != nil || bound.ID != member.ID {
			return resolvedSubject{}, apierr.New("SUBJECT_NOT_FOUND", "the asserted user is not bound to this member")
		}
	}
	return resolvedSubject{ID: member.ID, Type: member.Kind}, nil
}

func (a *API) writeDecisionWithVersion(ctx context.Context, key application.Key, body CheckBody, memberID, spaceID string, decision engine.Decision, policyVersion int64) (*CheckOutput, error) {
	out := &CheckOutput{}
	out.Body.Data.Decision = string(decision.Effect)
	out.Body.Data.DecisionID = string(ids.New[ids.ID]("dec"))
	out.Body.Data.PolicyVersion = strconv.FormatInt(policyVersion, 10)
	if decision.Effect == engine.Deny {
		out.Body.Data.DenyCode = decision.Code
	}
	if err := a.writeDenyAudit(ctx, key, body, decision, "authz.check"); err != nil {
		return nil, err
	}
	return out, nil
}

func (a *API) writeDenyAudit(ctx context.Context, key application.Key, body CheckBody, decision engine.Decision, action string) error {
	if decision.Effect == engine.Deny && a.Applications != nil && a.Applications.Store != nil {
		extra := map[string]string{}
		if body.Subject.Token == "" {
			extra["subject_source"] = "application_assertion"
		}
		return a.Applications.Store.InTx(ctx, func(q *db.Queries) error {
			return audit.WriteWithMetadata(ctx, q, "application", key.ID, action, body.Resource.ID, "deny", extra)
		})
	}
	return nil
}

func explainSummary(action string, decision engine.Decision) string {
	if decision.Effect == engine.Allow {
		return fmt.Sprintf("%s is allowed", action)
	}
	return fmt.Sprintf("%s is denied: %s", action, decision.Code)
}

func explainTrace(decision engine.Decision) []ExplainStep {
	if len(decision.Trace) == 0 {
		return []ExplainStep{{Step: "authorization", Result: "fail", Detail: explainDenyDetail(decision.Code)}}
	}
	trace := make([]ExplainStep, 0, len(decision.Trace))
	for i, detail := range decision.Trace {
		result := "pass"
		if decision.Effect == engine.Deny && i == len(decision.Trace)-1 {
			result = "fail"
		}
		trace = append(trace, ExplainStep{Step: "authorization", Result: result, Detail: detail})
	}
	return trace
}

func explainDenyDetail(code string) string {
	switch code {
	case "INVALID_SUBJECT":
		return "subject or permission is missing"
	case "UNKNOWN_PERMISSION":
		return "permission is not registered"
	case "PERMISSION_DISABLED":
		return "permission is disabled"
	case "ACTOR_MEMBER_INACTIVE":
		return "subject member is inactive"
	case "PRINCIPAL_KIND_NOT_ALLOWED":
		return "the permission does not allow this principal type"
	case "ENVELOPE_EXCLUDED":
		return "the permission is excluded by the effective envelope"
	case "SCOPE_OUT_OF_BOUNDS":
		return "the assignment scope does not cover the resource"
	case "OWNER_INACTIVE":
		return "owner chain contains an inactive member"
	case "OWNER_ENVELOPE_EXCLUDED":
		return "the owner effective envelope excludes the permission"
	case "APPROVAL_REQUIRED":
		return "human approval is required"
	case "RESOURCE_GROUP_NOT_FOUND":
		return "resource group was not found in the Space"
	case "RESOURCE_GROUP_INACTIVE":
		return "resource group is inactive"
	case "SPACE_INACTIVE":
		return "resource Space is inactive"
	case "KEY_SCOPE_EXCLUDED":
		return "the API key is outside the resource Space scope"
	case "TOKEN_SCOPE_EXCLUDED":
		return "the delegated token scope excludes the permission"
	case "NO_MATCHING_PERMISSION":
		return "no matching permission assignment was found"
	default:
		return "authorization denied"
	}
}

func (a *API) introspect(ctx context.Context, in *IntrospectInput) (*IntrospectOutput, error) {
	key, err := a.key(ctx, in.Authorization)
	if err != nil {
		return nil, err
	}
	if !contains(key.Scopes, "auth.tokens:introspect") {
		return nil, apierr.New("PERMISSION_DENIED", "API key is not scoped for token introspection.")
	}
	if strings.TrimSpace(in.Body.Token) == "" {
		return nil, apierr.New("VALIDATION_FAILED", "token is required")
	}
	if a.Sessions == nil {
		return nil, apierr.New("UNAVAILABLE", "token introspection is unavailable")
	}
	claims, active, err := a.Sessions.Introspect(ctx, in.Body.Token, key.ClientID)
	if err != nil {
		return nil, err
	}
	out := &IntrospectOutput{}
	out.Body.Data.Active = active
	if active {
		out.Body.Data.Subject = claims.Subject
		out.Body.Data.SessionID = claims.SessionID
		out.Body.Data.ExpiresAt = claims.ExpiresAt
	}
	return out, nil
}

func (a *API) key(ctx context.Context, value string) (application.Key, error) {
	parts := strings.Fields(value)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return application.Key{}, apierr.New("CREDENTIAL_PLANE_MISMATCH", "an application API key is required")
	}
	if a.Applications == nil {
		return application.Key{}, apierr.New("UNAVAILABLE", "application credentials are unavailable")
	}
	return a.Applications.AuthenticateKey(ctx, parts[1])
}

func contains(ss []string, w string) bool {
	for _, s := range ss {
		if s == w {
			return true
		}
	}
	return false
}
