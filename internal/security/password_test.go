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

func TestPasswordHasherRejectsOverlongInputAndDetectsRehash(t *testing.T) {
	hasher := DefaultPasswordHasher()
	if _, err := hasher.Hash(strings.Repeat("x", MaxPasswordBytes+1)); err == nil {
		t.Fatal("password longer than the configured maximum was accepted")
	}
	legacy := PasswordHasher{Time: 1, Memory: 8 * 1024, Threads: 1, KeyLen: 32, SaltLen: 16}
	hash, err := legacy.Hash("a sufficiently long password")
	if err != nil {
		t.Fatal(err)
	}
	if !hasher.Verify("a sufficiently long password", hash) || !hasher.NeedsRehash(hash) {
		t.Fatalf("legacy hash verification/rehash detection failed: %q", hash)
	}
	current, err := hasher.Hash("a sufficiently long password")
	if err != nil {
		t.Fatal(err)
	}
	if hasher.NeedsRehash(current) {
		t.Fatal("current hash was marked for rehash")
	}
	for _, malformed := range []string{
		"$argon2id$v=19$m=65536,t=3,p=4$not-base64$hash",
		"$argon2id$v=19$m=65536,t=3,p=4,m=1$YWJj$YWJj",
		"$argon2id$v=19$m=65536,t=3$YWJj$YWJj",
	} {
		if !hasher.NeedsRehash(malformed) || hasher.Verify("a sufficiently long password", malformed) {
			t.Fatalf("malformed hash was accepted as current: %q", malformed)
		}
	}
}
