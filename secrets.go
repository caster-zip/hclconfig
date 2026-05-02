package hclconfig

import (
	"fmt"
	"os"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// SentinelCipher is the reserved variable name for at-rest encrypted values.
// `CIPHER["base64-ciphertext"]` evaluates to the decrypted plaintext.
const SentinelCipher = "CIPHER"

// SentinelPlain is the reserved variable name for plaintext values inside
// `hclconfig edit` tempfiles. Encountering it during a normal Load is an error
// (the file is an unencrypted edit tempfile, not a config to be loaded).
const SentinelPlain = "PLAIN"

// resolveCipherSentinel scans body for CIPHER["..."] references, decrypts each
// ciphertext, and returns a cty.MapVal of ciphertext->plaintext suitable for
// injection as the CIPHER variable. Returns cty.NilVal if no CIPHER references
// are found. Returns an error if any PLAIN["..."] reference is found, or if
// CIPHER references are present but no key is configured.
func resolveCipherSentinel(body *hclsyntax.Body, key string) (cty.Value, error) {
	if plainKeys := extractIndexKeys(body, SentinelPlain); len(plainKeys) > 0 {
		return cty.NilVal, fmt.Errorf("PLAIN[\"...\"] sentinel found in config: this looks like an `hclconfig edit` tempfile, not an at-rest config. Run `hclconfig edit` to manage secrets")
	}

	cipherKeys := extractIndexKeys(body, SentinelCipher)
	if len(cipherKeys) == 0 {
		return cty.NilVal, nil
	}
	if key == "" {
		return cty.NilVal, fmt.Errorf("CIPHER[\"...\"] sentinel found but no encryption key configured (set HCLCONFIG_KEY or use WithEncryptionKey)")
	}

	m := make(map[string]cty.Value, len(cipherKeys))
	for _, ct := range cipherKeys {
		pt, err := Decrypt(ct, key)
		if err != nil {
			return cty.NilVal, fmt.Errorf("decrypting CIPHER[%q]: %w", ct, err)
		}
		m[ct] = cty.StringVal(pt)
	}
	return cty.MapVal(m), nil
}

// extractIndexKeys walks all expressions in body and returns the literal string
// keys used in NAME["..."] traversals (i.e. ScopeTraversalExpr with root NAME
// and a string-typed TraverseIndex step).
func extractIndexKeys(body *hclsyntax.Body, name string) []string {
	var keys []string
	seen := make(map[string]bool)
	add := func(k string) {
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	walkBodyExpressions(body, func(expr hclsyntax.Expression) {
		t, ok := expr.(*hclsyntax.ScopeTraversalExpr)
		if !ok || len(t.Traversal) < 2 {
			return
		}
		root, ok := t.Traversal[0].(hcl.TraverseRoot)
		if !ok || root.Name != name {
			return
		}
		idx, ok := t.Traversal[1].(hcl.TraverseIndex)
		if !ok || idx.Key.Type() != cty.String {
			return
		}
		add(idx.Key.AsString())
	})
	return keys
}

func walkBodyExpressions(body *hclsyntax.Body, visit func(hclsyntax.Expression)) {
	for _, attr := range body.Attributes {
		hclsyntax.Walk(attr.Expr, exprVisitor{visit: visit})
	}
	for _, block := range body.Blocks {
		walkBodyExpressions(block.Body, visit)
	}
}

type exprVisitor struct {
	visit func(hclsyntax.Expression)
}

func (v exprVisitor) Enter(node hclsyntax.Node) hcl.Diagnostics {
	if e, ok := node.(hclsyntax.Expression); ok {
		v.visit(e)
	}
	return nil
}

func (v exprVisitor) Exit(node hclsyntax.Node) hcl.Diagnostics { return nil }

// envEncryptionKey returns the encryption key from HCLCONFIG_KEY if set.
func envEncryptionKey() string { return os.Getenv("HCLCONFIG_KEY") }
