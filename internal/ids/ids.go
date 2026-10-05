package ids

import (
	"crypto/rand"
	"fmt"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
)

type ID string
type UserID string
type SessionID string
type RefreshTokenID string
type RefreshFamilyID string
type FactorID string
type SpaceID string
type GroupID string
type MemberID string
type RoleID string
type PermissionID string
type ApplicationID string
type APIKeyID string
type AgentID string
type AuditID string

type prefixer interface{ ~string }

func New[T prefixer](prefix string) T {
	return T(fmt.Sprintf("%s_%s", prefix, ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader).String()))
}
func valid(v string, prefix string) bool {
	return strings.HasPrefix(v, prefix+"_") && len(v) > len(prefix)+2
}
func (id UserID) Valid() bool          { return valid(string(id), "usr") }
func (id SessionID) Valid() bool       { return valid(string(id), "ses") }
func (id RefreshTokenID) Valid() bool  { return valid(string(id), "rft") }
func (id RefreshFamilyID) Valid() bool { return valid(string(id), "rtf") }
func (id FactorID) Valid() bool        { return valid(string(id), "fac") }
func (id SpaceID) Valid() bool         { return valid(string(id), "spc") }
func (id GroupID) Valid() bool         { return valid(string(id), "grp") }
func (id MemberID) Valid() bool        { return valid(string(id), "mem") }
func (id RoleID) Valid() bool          { return valid(string(id), "rol") }
func (id PermissionID) Valid() bool    { return valid(string(id), "prm") }
func (id ApplicationID) Valid() bool   { return valid(string(id), "app") }
func (id APIKeyID) Valid() bool        { return valid(string(id), "key") }
func (id AgentID) Valid() bool         { return valid(string(id), "agt") }
func (id AuditID) Valid() bool         { return valid(string(id), "aud") }
