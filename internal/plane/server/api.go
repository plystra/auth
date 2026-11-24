package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/approval"
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
	Approvals     *approval.Service
}

type CheckSubject struct {
	Token    string   `json:"token,omitempty"`
	MemberID string   `json:"member_id,omitempty"`
	UserID   string   `json:"user_id,omitempty"`
	_        struct{} `json:"-" additionalProperties:"true"`
	unknown  []string
}

func (s CheckSubject) accountOnly() bool {
	return s.Token == "" && s.MemberID == "" && s.UserID != ""
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

type ApprovalCreateInput struct {
	Authorization string `header:"Authorization"`
	Body          struct {
		Subject       CheckSubject    `json:"subject"`
		Action        string          `json:"action"`
		Resource      CheckResource   `json:"resource"`
		RequestDigest string          `json:"request_digest" minLength:"64" maxLength:"64"`
		Reason        string          `json:"reason,omitempty" maxLength:"2000"`
		Grants        json.RawMessage `json:"grants,omitempty"`
		Roles         json.RawMessage `json:"roles,omitempty"`
	}
}

type ApprovalCreateOutput struct {
	Body struct {
		Data approval.Request `json:"data"`
	}
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
		Data IntrospectIdentity `json:"data"`
	}
}

type IntrospectIdentity struct {
	Active     bool                  `json:"active"`
	Subject    string                `json:"sub,omitempty"`
	SessionID  string                `json:"sid,omitempty"`
	ExpiresAt  int64                 `json:"exp,omitempty"`
	MemberID   string                `json:"member_id,omitempty"`
	MemberType string                `json:"member_type,omitempty"`
	SpaceID    string                `json:"space_id,omitempty"`
	UserID     string                `json:"user_id,omitempty"`
	OwnerChain []agent.OwnerIdentity `json:"owner_chain,omitempty"`
}

type resolvedSubject struct {
	ID      string
	Type    string
	SpaceID string
	UserID  string
	Scopes  []string
}

func (a *API) Register(api huma.API) {
	// Discovery requires key authentication in the handlers, but no member permission.
	route.Register(api, route.NewSpec("key.whoami", "GET", "/server/v1/key", route.Server, "", []route.Subject{route.Public}), a.whoami)
	route.Register(api, route.NewSpec("installations.list", "GET", "/server/v1/installations", route.Server, "", []route.Subject{route.Public}), a.listKeyInstallations)
	route.Register(api, route.NewSpec("authz.check", "POST", "/server/v1/authz/check", route.Server, "auth.authz:check", []route.Subject{route.HumanAgent}, route.WithAuthoritativeCheck()), a.check)
	route.Register(api, route.NewSpec("authz.batch_check", "POST", "/server/v1/authz/batch-check", route.Server, "auth.authz:check", []route.Subject{route.HumanAgent}, route.WithAuthoritativeCheck(), route.WithMaxBodyBytes(256*1024)), a.batchCheck)
	route.Register(api, route.NewSpec("authz.explain", "POST", "/server/v1/authz/explain", route.Server, "auth.authz:explain", []route.Subject{route.HumanAgent}, route.WithAuthoritativeCheck()), a.explain)
	route.Register(api, route.NewSpec("tokens.introspect", "POST", "/server/v1/tokens/introspect", route.Server, "auth.tokens:introspect", []route.Subject{route.HumanAgent}), a.introspect)
	route.Register(api, route.NewSpec("approvals.create", "POST", "/server/v1/approvals", route.Server, "auth.authz:check", []route.Subject{route.HumanAgent}, route.WithAuthoritativeCheck()), a.createApproval)
	route.Register(api, route.NewSpec("audit.write", "POST", "/server/v1/audit/events", route.Server, "auth.audit:write", []route.Subject{route.HumanAgent}, route.WithAuthoritativeCheck()), a.writeBusinessAudit)
}

func (a *API) createApproval(ctx context.Context, in *ApprovalCreateInput) (*ApprovalCreateOutput, error) {
	if a.Approvals == nil {
		return nil, apierr.New("UNAVAILABLE", "approvals are unavailable")
	}
	body := CheckBody{Subject: in.Body.Subject, Action: in.Body.Action, Resource: in.Body.Resource, Grants: in.Body.Grants, Roles: in.Body.Roles}
	key, err := a.key(ctx, in.Authorization)
	if err != nil {
		return nil, err
	}
	if body.Subject.accountOnly() {
		return nil, apierr.New("VALIDATION_FAILED", "business approvals require an Agent subject")
	}
	evaluation, err := a.evaluateWithKey(ctx, key, body, "auth.authz:check", false)
	if err != nil {
		return nil, err
	}
	if evaluation.decision.Code != "APPROVAL_REQUIRED" {
		return nil, apierr.New("VALIDATION_FAILED", "the Agent action is not awaiting human approval")
	}
	digest, err := hex.DecodeString(in.Body.RequestDigest)
	if err != nil || len(digest) != 32 {
		return nil, apierr.New("VALIDATION_FAILED", "request_digest must be a SHA-256 hex digest")
	}
	ctx = audit.WithCaller(ctx, audit.Caller{ApplicationID: key.ApplicationID, KeyID: key.ID, CredentialType: "application_api_key"})
	created, err := a.Approvals.CreateBusiness(ctx, key.ID, evaluation.memberID, in.Body.Action, approval.Resource{
		Type: in.Body.Resource.Type, ID: in.Body.Resource.ID, SpaceID: evaluation.spaceID,
		GroupID: in.Body.Resource.GroupID, OwnerMemberID: in.Body.Resource.OwnerMemberID,
	}, digest, in.Body.Reason)
	if err != nil {
		return nil, err
	}
	out := &ApprovalCreateOutput{}
	out.Body.Data = created
	return out, nil
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
	evaluation, err := a.evaluateWithKey(ctx, key, in.Body, "auth.authz:explain", false)
	if err != nil {
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
	if err := a.writeDenyAudit(ctx, key, in.Body, evaluation, out.Body.Data.DecisionID, "authz.explain"); err != nil {
		return nil, err
	}
	return out, nil
}

func (a *API) checkWithKey(ctx context.Context, key application.Key, body CheckBody) (*CheckOutput, error) {
	evaluation, err := a.evaluateWithKey(ctx, key, body, "auth.authz:check", true)
	if err != nil {
		return nil, err
	}
	return a.writeDecisionWithVersion(ctx, key, body, evaluation)
}

type authorizationEvaluation struct {
	decision      engine.Decision
	policyVersion int64
	memberID      string
	spaceID       string
	userID        string
}

func (a *API) evaluateWithKey(ctx context.Context, key application.Key, body CheckBody, requiredScope string, consumeApproval bool) (authorizationEvaluation, error) {
	if len(body.Grants) > 0 || len(body.Roles) > 0 || len(body.Subject.unknown) > 0 {
		return authorizationEvaluation{}, apierr.New("INLINE_GRANTS_NOT_ALLOWED", "authorization facts must come from Auth state, not the request")
	}
	if a.Authorization == nil {
		return authorizationEvaluation{}, apierr.New("UNAVAILABLE", "authorization is unavailable")
	}
	spaceID := strings.TrimSpace(body.Resource.SpaceID)
	accountAssertion := body.Subject.accountOnly()
	if accountAssertion {
		if spaceID == "" {
			return authorizationEvaluation{}, apierr.New("VALIDATION_FAILED", "resource.space_id is required for an account assertion")
		}
		if !key.AllowSubjectAssertion {
			return authorizationEvaluation{}, apierr.New("VALIDATION_FAILED", "subject assertions are not enabled for this API key")
		}
	}
	var resolved resolvedSubject
	if spaceID == "" {
		if !contains(key.Scopes, requiredScope) {
			return authorizationEvaluation{}, apierr.New("PERMISSION_DENIED", "API key is not scoped for this operation.")
		}
		var err error
		resolved, err = a.resolveSubject(ctx, key, body.Subject, "")
		if err != nil {
			return authorizationEvaluation{}, err
		}
		spaceID = resolved.SpaceID
	}
	keyDecision, keyVersion, err := a.keyOperationDecision(ctx, key, requiredScope, spaceID, body.Resource.GroupID, body.Resource.OwnerMemberID)
	if err != nil {
		return authorizationEvaluation{}, err
	}
	if keyDecision.Effect != engine.Allow {
		for i := range keyDecision.Trace {
			if keyDecision.Trace[i].Step != "application" {
				keyDecision.Trace[i].Step = "application." + keyDecision.Trace[i].Step
			}
		}
		return authorizationEvaluation{decision: keyDecision, policyVersion: keyVersion, spaceID: spaceID}, nil
	}
	if accountAssertion {
		resolved.UserID = body.Subject.UserID
	} else if resolved.ID == "" {
		resolved, err = a.resolveSubject(ctx, key, body.Subject, spaceID)
		if err != nil {
			return authorizationEvaluation{}, err
		}
	}
	if resolved.SpaceID != "" && resolved.SpaceID != spaceID {
		subjectDecision, _, err := a.keyOperationDecision(ctx, key, requiredScope, resolved.SpaceID, "", "")
		if err != nil {
			return authorizationEvaluation{}, err
		}
		if subjectDecision.Effect != engine.Allow {
			for i := range subjectDecision.Trace {
				if subjectDecision.Trace[i].Step != "application" {
					subjectDecision.Trace[i].Step = "application." + subjectDecision.Trace[i].Step
				}
			}
			return authorizationEvaluation{decision: subjectDecision, policyVersion: keyVersion, spaceID: spaceID}, nil
		}
	}
	memberID := resolved.ID
	permission := strings.TrimSpace(body.Action)
	check := authorization.CheckRequest{
		MemberID: memberID, Permission: permission, ResourceSpace: spaceID,
		ResourceGroup: body.Resource.GroupID, ResourceOwner: body.Resource.OwnerMemberID,
		TokenScopes: resolved.Scopes,
	}
	var decision engine.Decision
	var policyVersion int64
	if body.Subject.Token == "" && resolved.UserID != "" {
		var checked authorization.AssertedHumanDecision
		checked, err = a.Authorization.CheckAssertedHuman(ctx, check, resolved.UserID)
		memberID, decision, policyVersion = checked.MemberID, checked.Decision, checked.PolicyVersion
	} else if consumeApproval {
		ctx = audit.WithCaller(ctx, audit.Caller{ApplicationID: key.ApplicationID, KeyID: key.ID, UserID: resolved.UserID, CredentialType: "application_api_key"})
		decision, policyVersion, err = a.Authorization.CheckBusiness(ctx, check, body.Resource.Type, body.Resource.ID)
	} else if requiredScope == "auth.authz:explain" {
		decision, policyVersion, err = a.Authorization.ExplainBusiness(ctx, check, body.Resource.Type, body.Resource.ID)
	} else {
		decision, policyVersion, err = a.Authorization.Check(ctx, check)
	}
	if err != nil {
		return authorizationEvaluation{}, err
	}
	decision.Trace = append([]engine.TraceStep{engine.Passed("application", "the application installation and API key authority cover the subject and resource")}, decision.Trace...)
	return authorizationEvaluation{decision: decision, policyVersion: policyVersion, memberID: memberID, spaceID: spaceID, userID: resolved.UserID}, nil
}

func (a *API) keyOperationDecision(ctx context.Context, key application.Key, permission, spaceID, groupID, ownerID string) (engine.Decision, int64, error) {
	if !contains(key.Scopes, permission) {
		return engine.Decision{}, 0, apierr.New("PERMISSION_DENIED", "API key is not scoped for this operation.")
	}
	if a.Applications == nil || a.Authorization == nil {
		return engine.Decision{}, 0, apierr.New("UNAVAILABLE", "application authorization is unavailable")
	}
	memberID, denyCode, err := a.Applications.ResolveKeyInstallation(ctx, key, spaceID)
	if err != nil {
		return engine.Decision{}, 0, err
	}
	if denyCode != "" {
		version, err := a.Authorization.PolicyVersion(ctx, spaceID)
		if err != nil {
			return engine.Decision{}, 0, err
		}
		return engine.Reject(denyCode), version, nil
	}
	return a.Authorization.Check(ctx, authorization.CheckRequest{
		MemberID: memberID, Permission: permission, ResourceSpace: spaceID,
		ResourceGroup: groupID, ResourceOwner: ownerID,
	})
}

func (a *API) resolveSubject(ctx context.Context, key application.Key, subject CheckSubject, spaceID string) (resolvedSubject, error) {
	return a.resolveSubjectWithQueries(ctx, nil, key, subject, spaceID)
}

// Mutations supply their transaction's queries. For ordinary checks, only a
// native Agent key needs a transaction to record credential usage.
func (a *API) resolveSubjectWithQueries(ctx context.Context, q *db.Queries, key application.Key, subject CheckSubject, spaceID string) (resolvedSubject, error) {
	if strings.HasPrefix(subject.Token, "ply_ag_") && a.Agents != nil {
		var credential agent.Credential
		var err error
		if q == nil {
			credential, err = a.Agents.AuthenticateKey(ctx, subject.Token)
		} else {
			credential, err = a.Agents.AuthenticateKeyTx(ctx, q, subject.Token)
		}
		if err != nil {
			return resolvedSubject{}, err
		}
		return resolvedSubject{ID: credential.MemberID, Type: "agent", SpaceID: credential.SpaceID}, nil
	}
	if a.Authorization == nil || a.Authorization.Store == nil {
		return resolvedSubject{}, apierr.New("UNAVAILABLE", "authorization is unavailable")
	}
	if q == nil {
		q = a.Authorization.Store.Queries()
	}
	if subject.Token != "" {
		if a.Sessions == nil {
			return resolvedSubject{}, apierr.New("UNAVAILABLE", "authentication is unavailable")
		}
		claims, active, err := a.Sessions.IntrospectForSpaceTx(ctx, q, subject.Token, key.ClientID, spaceID)
		if err != nil {
			return resolvedSubject{}, err
		}
		if !active {
			return resolvedSubject{}, apierr.New("UNAUTHENTICATED", "the subject token is invalid")
		}
		if claims.Type == "agent" {
			if claims.SpaceID == "" {
				return resolvedSubject{}, apierr.New("SUBJECT_NOT_FOUND", "Agent token has no Space")
			}
			return resolvedSubject{ID: claims.Subject, Type: "agent", SpaceID: claims.SpaceID, Scopes: claims.Scopes}, nil
		}
		if claims.MemberID != "" && subject.MemberID != "" && subject.MemberID != claims.MemberID {
			return resolvedSubject{}, apierr.New("SUBJECT_NOT_FOUND", "the subject token and member do not match")
		}
		var member authorization.Member
		if claims.MemberID != "" {
			if spaceID == "" {
				member, err = a.Authorization.GetMemberAnySpaceTx(ctx, q, claims.MemberID)
			} else {
				member, err = a.Authorization.GetMemberTx(ctx, q, claims.MemberID, spaceID)
			}
		} else {
			if spaceID == "" {
				return resolvedSubject{}, apierr.New("VALIDATION_FAILED", "resource.space_id is required when the subject has no selected member")
			}
			member, err = a.Authorization.GetMemberForUserTx(ctx, q, claims.Subject, spaceID)
		}
		if err != nil {
			return resolvedSubject{}, err
		}
		if subject.MemberID != "" && subject.MemberID != member.ID {
			return resolvedSubject{}, apierr.New("SUBJECT_NOT_FOUND", "the subject token and member do not match")
		}
		return resolvedSubject{ID: member.ID, Type: member.Kind, SpaceID: member.SpaceID, UserID: claims.Subject}, nil
	}
	if subject.MemberID == "" {
		return resolvedSubject{}, apierr.New("VALIDATION_FAILED", "subject.token is required")
	}
	if !key.AllowSubjectAssertion {
		return resolvedSubject{}, apierr.New("VALIDATION_FAILED", "member_id subject assertions are not enabled for this API key")
	}
	var member authorization.Member
	var err error
	if spaceID == "" {
		member, err = a.Authorization.GetMemberAnySpaceTx(ctx, q, subject.MemberID)
	} else {
		member, err = a.Authorization.GetMemberTx(ctx, q, subject.MemberID, spaceID)
	}
	if err != nil {
		return resolvedSubject{}, err
	}
	if subject.UserID != "" {
		if member.Kind != "human" {
			return resolvedSubject{}, apierr.New("SUBJECT_NOT_FOUND", "the asserted user is not bound to this member")
		}
		bound, err := a.Authorization.UserBoundToMemberTx(ctx, q, subject.UserID, member.ID)
		if err != nil {
			return resolvedSubject{}, err
		}
		if !bound {
			return resolvedSubject{}, apierr.New("SUBJECT_NOT_FOUND", "the asserted user is not bound to this member")
		}
	}
	return resolvedSubject{ID: member.ID, Type: member.Kind, SpaceID: member.SpaceID, UserID: subject.UserID}, nil
}

func (a *API) writeDecisionWithVersion(ctx context.Context, key application.Key, body CheckBody, evaluation authorizationEvaluation) (*CheckOutput, error) {
	out := &CheckOutput{}
	out.Body.Data.Decision = string(evaluation.decision.Effect)
	out.Body.Data.DecisionID = string(ids.New[ids.ID]("dec"))
	out.Body.Data.PolicyVersion = strconv.FormatInt(evaluation.policyVersion, 10)
	if evaluation.decision.Effect == engine.Deny {
		out.Body.Data.DenyCode = evaluation.decision.Code
	}
	if err := a.writeDenyAudit(ctx, key, body, evaluation, out.Body.Data.DecisionID, "authz.check"); err != nil {
		return nil, err
	}
	return out, nil
}

func (a *API) writeDenyAudit(ctx context.Context, key application.Key, body CheckBody, evaluation authorizationEvaluation, decisionID, action string) error {
	if evaluation.decision.Effect == engine.Deny && a.Applications != nil && a.Applications.Store != nil {
		return a.Applications.Store.InTx(ctx, func(q *db.Queries) error {
			return audit.WriteAuthorizationDecision(ctx, q, audit.AuthorizationDecision{
				KeyID: key.ID, ApplicationID: key.ApplicationID, MemberID: evaluation.memberID,
				UserID: evaluation.userID, SpaceID: evaluation.spaceID, GroupID: body.Resource.GroupID,
				ResourceType: body.Resource.Type, ResourceID: body.Resource.ID,
				Permission: strings.TrimSpace(body.Action), Action: action,
				DecisionID: decisionID, DenyCode: evaluation.decision.Code, PolicyVersion: evaluation.policyVersion,
				Asserted: body.Subject.Token == "",
			})
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
	trace := make([]ExplainStep, 0, len(decision.Trace))
	for _, step := range decision.Trace {
		trace = append(trace, ExplainStep(step))
	}
	return trace
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
	identity, active, err := a.introspectIdentity(ctx, in.Body.Token, key.ClientID)
	if err != nil {
		return nil, err
	}
	out := &IntrospectOutput{}
	if active {
		spaceID := identity.SpaceID
		if spaceID == "" {
			spaceID = key.SpaceID
		}
		decision, _, err := a.keyOperationDecision(ctx, key, "auth.tokens:introspect", spaceID, "", "")
		if err != nil {
			return nil, err
		}
		if decision.Effect != engine.Allow {
			return out, nil
		}
		identity.Active = true
		out.Body.Data = identity
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
