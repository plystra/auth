package engine

// TraceStep describes an evaluated condition using fixed, non-identifying text.
// Never include persisted identities, credential values, or policy contents.
type TraceStep struct {
	Step   string `json:"step"`
	Result string `json:"result"`
	Detail string `json:"detail"`
}

func Passed(step, detail string) TraceStep {
	return TraceStep{Step: step, Result: "pass", Detail: detail}
}

// Reject appends the actual failure to the steps reached before it.
func Reject(code string, reached ...TraceStep) Decision {
	step, detail := denialDetail(code)
	trace := append([]TraceStep(nil), reached...)
	trace = append(trace, TraceStep{Step: step, Result: "fail", Detail: detail})
	return Decision{Effect: Deny, Code: code, Trace: trace}
}

func denialDetail(code string) (string, string) {
	switch code {
	case "INVALID_SUBJECT":
		return "subject", "subject or permission is missing"
	case "SUBJECT_NOT_FOUND":
		return "subject", "subject is unavailable in the caller's visible scope"
	case "UNKNOWN_PERMISSION":
		return "catalog", "permission is not registered"
	case "PERMISSION_DISABLED":
		return "catalog", "permission is disabled"
	case "ACTOR_USER_INACTIVE":
		return "subject", "subject user is inactive"
	case "ACTOR_MEMBER_INACTIVE":
		return "subject", "subject member is inactive"
	case "BINDING_REVOKED":
		return "subject", "the user binding is no longer valid"
	case "SPACE_INACTIVE":
		return "space", "a required Space or ancestor is inactive"
	case "RESOURCE_GROUP_NOT_FOUND":
		return "resource_group", "resource group was not found in the Space"
	case "RESOURCE_GROUP_INACTIVE":
		return "resource_group", "resource group or ancestor is inactive"
	case "APPLICATION_NOT_INSTALLED":
		return "application", "the application has no active installation covering the request"
	case "KEY_SCOPE_EXCLUDED":
		return "application", "the API key scope does not cover the request"
	case "TOKEN_SCOPE_EXCLUDED":
		return "token_scope", "the delegated token scope excludes the permission"
	case "PRINCIPAL_KIND_NOT_ALLOWED":
		return "principal_kind", "the permission does not allow this principal type"
	case "NO_MATCHING_PERMISSION":
		return "permission", "no matching permission assignment was found"
	case "ENVELOPE_EXCLUDED":
		return "envelope", "the permission is excluded by the effective envelope"
	case "SCOPE_OUT_OF_BOUNDS":
		return "scope", "the assignment scope does not cover the resource"
	case "OWNER_INACTIVE":
		return "owner_envelope", "owner chain contains an unavailable or inactive member"
	case "OWNER_ENVELOPE_EXCLUDED":
		return "owner_envelope", "an owner is not allowed the same permission on the resource"
	case "APPROVAL_REQUIRED":
		return "approval", "human approval is required"
	case "APPROVAL_PENDING":
		return "approval", "human approval is pending"
	case "APPROVAL_REJECTED":
		return "approval", "human approval was rejected"
	default:
		return "authorization", "authorization denied"
	}
}

// WithApprovalStatus preserves the evaluated authority checks while replacing
// the unresolved approval step with its persisted state.
func (d Decision) WithApprovalStatus(code string) Decision {
	trace := d.Trace
	if len(trace) > 0 && trace[len(trace)-1].Step == "approval" {
		trace = trace[:len(trace)-1]
	}
	return Reject(code, trace...)
}
