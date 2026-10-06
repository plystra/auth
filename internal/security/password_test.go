package security

import (
	"strings"
	"testing"
)

func TestPasswordHashCarriesArgon2idParameters(t *testing.T) {
	hasher := DefaultPasswordHasher()
	hash, err := hasher.Hash("a sufficiently long password")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=65536,t=3,p=4$") {
		t.Fatalf("hash = %q, want Argon2id parameters in encoded hash", hash)
	}
	if !hasher.Verify("a sufficiently long password", hash) || hasher.Verify("wrong password", hash) {
		t.Fatal("Argon2id verification did not enforce the encoded parameters and password")
	}
}
