package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

type PasswordHasher struct {
	Time    uint32
	Memory  uint32
	Threads uint8
	KeyLen  uint32
	SaltLen uint32
}

const MaxPasswordBytes = 1024

func DefaultPasswordHasher() PasswordHasher {
	return PasswordHasher{Time: 3, Memory: 64 * 1024, Threads: 4, KeyLen: 32, SaltLen: 16}
}
func (h PasswordHasher) Hash(password string) (string, error) {
	if password == "" {
		return "", fmt.Errorf("password is required")
	}
	if len(password) > MaxPasswordBytes {
		return "", fmt.Errorf("password is too long")
	}
	salt := make([]byte, h.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	sum := argon2.IDKey([]byte(password), salt, h.Time, h.Memory, h.Threads, h.KeyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", h.Memory, h.Time, h.Threads, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(sum)), nil
}

func (h PasswordHasher) NeedsRehash(encoded string) bool {
	params, salt, expected, ok := parseArgon2(encoded)
	if !ok {
		return true
	}
	return params["m"] != uint64(h.Memory) || params["t"] != uint64(h.Time) || params["p"] != uint64(h.Threads) || len(salt) != int(h.SaltLen) || len(expected) != int(h.KeyLen)
}
func (h PasswordHasher) Verify(password, encoded string) bool {
	params, salt, expected, ok := parseArgon2(encoded)
	if !ok {
		return false
	}
	if params["m"] == 0 || params["t"] == 0 || params["p"] == 0 {
		return false
	}
	actual := argon2.IDKey([]byte(password), salt, uint32(params["t"]), uint32(params["m"]), uint8(params["p"]), uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

func parseArgon2(encoded string) (map[string]uint64, []byte, []byte, bool) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" || parts[4] == "" || parts[5] == "" {
		return nil, nil, nil, false
	}
	params := map[string]uint64{}
	for _, part := range strings.Split(parts[3], ",") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 || (kv[0] != "m" && kv[0] != "t" && kv[0] != "p") {
			return nil, nil, nil, false
		}
		if _, exists := params[kv[0]]; exists {
			return nil, nil, nil, false
		}
		value, err := strconv.ParseUint(kv[1], 10, 32)
		if err != nil || value == 0 {
			return nil, nil, nil, false
		}
		params[kv[0]] = value
	}
	if len(params) != 3 {
		return nil, nil, nil, false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) == 0 {
		return nil, nil, nil, false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(expected) == 0 {
		return nil, nil, nil, false
	}
	return params, salt, expected, true
}
