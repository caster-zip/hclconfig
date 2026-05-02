package main

import (
	"strings"
	"testing"

	"github.com/caster-zip/hclconfig"
)

func TestRewriteCipherToPlain_RoundTrip(t *testing.T) {
	key, _ := hclconfig.GenerateKey()
	c1, _ := hclconfig.Encrypt("first", key)
	c2, _ := hclconfig.Encrypt("two with \"quotes\"", key)

	src := []byte(`
db {
  password = CIPHER["` + c1 + `"]
}
api = CIPHER["` + c2 + `"]
`)
	dec, err := rewriteCipherToPlain(src, key)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(dec), `PLAIN["first"]`) {
		t.Errorf("expected PLAIN[\"first\"], got: %s", dec)
	}
	if !strings.Contains(string(dec), `PLAIN["two with \"quotes\""]`) {
		t.Errorf("expected escaped quotes preserved, got: %s", dec)
	}

	enc, err := rewritePlainToCipher(dec, key)
	if err != nil {
		t.Fatal(err)
	}
	// Round-trip via decrypt to verify content survived
	for _, ct := range cipherRE.FindAllSubmatch(enc, -1) {
		// just confirm parse-back works; we don't compare bytes (nonces differ)
		pt, err := hclconfig.Decrypt(string(ct[1]), key)
		if err != nil {
			t.Fatalf("re-encrypted CIPHER failed to decrypt: %v", err)
		}
		if pt != "first" && pt != `two with "quotes"` {
			t.Errorf("unexpected plaintext after round-trip: %q", pt)
		}
	}
}

func TestRewritePlainToCipher_NewSecret(t *testing.T) {
	key, _ := hclconfig.GenerateKey()
	src := []byte(`new_secret = PLAIN["i added this"]`)
	out, err := rewritePlainToCipher(src, key)
	if err != nil {
		t.Fatal(err)
	}
	matches := cipherRE.FindAllSubmatch(out, -1)
	if len(matches) != 1 {
		t.Fatalf("expected 1 CIPHER match, got %d", len(matches))
	}
	pt, err := hclconfig.Decrypt(string(matches[0][1]), key)
	if err != nil || pt != "i added this" {
		t.Errorf("decrypt = %q (err=%v), want %q", pt, err, "i added this")
	}
}

func TestLegacyDecryptMigration(t *testing.T) {
	src := []byte(`
a = decrypt("aGVsbG8=", env("HCLCONFIG_KEY"))
b = decrypt("d29ybGQ=", env("MY_KEY"))
c = decrypt("Zm9v", "literal-key")
unrelated = "decrypt-not-a-call"
`)
	out := legacyDecryptRE.ReplaceAllFunc(src, func(match []byte) []byte {
		sub := legacyDecryptRE.FindSubmatch(match)
		return []byte(`CIPHER["` + string(sub[1]) + `"]`)
	})
	want := `
a = CIPHER["aGVsbG8="]
b = CIPHER["d29ybGQ="]
c = CIPHER["Zm9v"]
unrelated = "decrypt-not-a-call"
`
	if string(out) != want {
		t.Errorf("migrate mismatch:\n--- got ---\n%s\n--- want ---\n%s", out, want)
	}
}
