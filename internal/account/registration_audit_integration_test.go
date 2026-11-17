package account

import (
	"context"
	"testing"

	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/requestinfo"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/space"
)

func TestRegistrationAuditFailureRollsBackIdentityVerificationAndMail(t *testing.T) {
	t.Parallel()
	for _, action := range []string{"member.default_bind", "auth.register"} {
		t.Run(action, func(t *testing.T) {
			t.Parallel()
			ctx := requestinfo.With(context.Background(), requestinfo.Info{ID: "req_pending_registration", Plane: "principal"})
			st := newAccountStore(t)
			if _, err := st.Pool.Exec(ctx, `UPDATE instance_settings SET registration_mode = 'open', require_email_verification = true`); err != nil {
				t.Fatal(err)
			}
			if _, err := st.Pool.Exec(ctx, `CREATE FUNCTION reject_pending_registration_audit() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN IF NEW.action = '`+action+`' THEN RAISE EXCEPTION 'injected registration audit failure'; END IF; RETURN NEW; END $$;
			CREATE TRIGGER reject_pending_registration_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_pending_registration_audit()`); err != nil {
				t.Fatal(err)
			}
			accounts := &Service{Store: st, Authorization: &authorization.Service{Store: st}, Passwords: security.DefaultPasswordHasher(), Settings: &space.Service{Store: st}, Mailer: newTestMailer(t, st)}
			state := func() string {
				t.Helper()
				var value string
				if err := st.Pool.QueryRow(ctx, `SELECT jsonb_build_array((SELECT count(*) FROM users), (SELECT count(*) FROM members),
				(SELECT count(*) FROM user_members), (SELECT count(*) FROM authorization_grants), (SELECT count(*) FROM audit_logs),
				(SELECT count(*) FROM email_verification_tokens), (SELECT count(*) FROM river_job), (SELECT count(*) FROM sessions),
				(SELECT policy_version FROM spaces WHERE id = $1))::text`, DefaultSpaceID).Scan(&value); err != nil {
					t.Fatal(err)
				}
				return value
			}
			before := state()
			input := RegisterInput{Email: "pending-audit@example.test", Password: "a-long-registration-password"}
			if _, err := accounts.Register(ctx, input, nil, "test"); err == nil || state() != before {
				t.Fatal("audit failure left an account, membership, grant, token, mail job, policy change, or audit")
			}
			if _, err := st.Pool.Exec(ctx, `DROP TRIGGER reject_pending_registration_audit ON audit_logs`); err != nil {
				t.Fatal(err)
			}
			result, err := accounts.Register(ctx, input, nil, "test")
			if err != nil || result.User.Status != "pending" || result.Tokens != nil {
				t.Fatal("registration could not retry with verification still required")
			}
			var audits, identities, verification, mailJobs int
			if err := st.Pool.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM audit_logs WHERE request_id = 'req_pending_registration' AND space_id = $1 AND user_id = $2 AND credential_type = 'public_registration' AND member_id IS NOT NULL),
			(SELECT count(*) FROM members m JOIN user_members b ON b.member_id = m.id WHERE b.user_id = $2 AND b.status = 'active' AND m.space_id = $1),
			(SELECT count(*) FROM email_verification_tokens WHERE user_id = $2),
			(SELECT count(*) FROM river_job WHERE kind = 'email_delivery')`, DefaultSpaceID, result.User.ID).Scan(&audits, &identities, &verification, &mailJobs); err != nil {
				t.Fatal(err)
			}
			if audits != 2 || identities != 1 || verification != 1 || mailJobs != 1 {
				t.Fatal("recovery did not commit exactly one complete pending registration")
			}
		})
	}
}
