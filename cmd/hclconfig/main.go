package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/caster-zip/hclconfig"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "genkey":
		cmdGenkey()
	case "encrypt":
		cmdEncrypt(os.Args[2:])
	case "decrypt":
		cmdDecrypt(os.Args[2:])
	case "edit":
		cmdEdit(os.Args[2:])
	case "migrate":
		cmdMigrate(os.Args[2:])
	case "rekey":
		cmdRekey(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `Usage: hclconfig <command> [options]

Commands:
  genkey                          Generate a new encryption key
  encrypt [options] <plaintext>   Encrypt a secret and output a CIPHER[...] snippet
  decrypt [options] <ciphertext>  Decrypt an encrypted value
  edit <file>                     Edit a config in $EDITOR with secrets transparently decrypted
  migrate <file>                  Rewrite legacy decrypt(...) calls to CIPHER["..."]
  rekey <file>                    Re-encrypt all CIPHER values with a new key (-old-key, -new-key)

The -key flag is optional for encrypt/decrypt. If omitted, the key is
read from the HCLCONFIG_KEY environment variable.`)
}

func resolveKey(flagKey string) string {
	if flagKey != "" {
		return flagKey
	}
	if key := os.Getenv("HCLCONFIG_KEY"); key != "" {
		return key
	}
	fmt.Fprintln(os.Stderr, "error: no key provided; use -key flag or set HCLCONFIG_KEY environment variable")
	os.Exit(1)
	return ""
}

func cmdGenkey() {
	key, err := hclconfig.GenerateKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(key)
}

func cmdEncrypt(args []string) {
	fs := flag.NewFlagSet("encrypt", flag.ExitOnError)
	keyFlag := fs.String("key", "", "base64-encoded 256-bit encryption key")
	fs.Parse(args)

	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: hclconfig encrypt [options] <plaintext>")
		os.Exit(1)
	}

	key := resolveKey(*keyFlag)
	plaintext := fs.Arg(0)

	ciphertext, err := hclconfig.Encrypt(plaintext, key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("CIPHER[%q]\n", ciphertext)
}

func cmdDecrypt(args []string) {
	fs := flag.NewFlagSet("decrypt", flag.ExitOnError)
	keyFlag := fs.String("key", "", "base64-encoded 256-bit encryption key")
	fs.Parse(args)

	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: hclconfig decrypt [options] <ciphertext>")
		os.Exit(1)
	}

	key := resolveKey(*keyFlag)
	ciphertext := fs.Arg(0)

	plaintext, err := hclconfig.Decrypt(ciphertext, key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(plaintext)
}

// cipherRE matches CIPHER["base64"] in source text. Base64 alphabet only.
var cipherRE = regexp.MustCompile(`CIPHER\["([A-Za-z0-9+/=]+)"\]`)

// plainRE matches PLAIN["..."] with Go-style escapes inside the string.
var plainRE = regexp.MustCompile(`PLAIN\["((?:[^"\\]|\\.)*)"\]`)

// legacyDecryptRE matches decrypt("base64", env("...")) or decrypt("base64", "...") for migration.
var legacyDecryptRE = regexp.MustCompile(`decrypt\(\s*"([A-Za-z0-9+/=]+)"\s*,\s*(?:env\("[^"]*"\)|"[^"]*")\s*\)`)

func cmdEdit(args []string) {
	fs := flag.NewFlagSet("edit", flag.ExitOnError)
	keyFlag := fs.String("key", "", "base64-encoded 256-bit encryption key")
	fs.Parse(args)

	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: hclconfig edit [options] <file>")
		os.Exit(1)
	}
	key := resolveKey(*keyFlag)
	path := fs.Arg(0)

	src, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading %s: %v\n", path, err)
		os.Exit(1)
	}

	// CIPHER["..."] -> PLAIN["..."] with Go-quoted plaintext.
	decrypted, err := rewriteCipherToPlain(src, key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error decrypting %s: %v\n", path, err)
		os.Exit(1)
	}

	tmpFile, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".edit-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating tempfile: %v\n", err)
		os.Exit(1)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)
	if err := tmpFile.Chmod(0600); err != nil {
		tmpFile.Close()
		fmt.Fprintf(os.Stderr, "error chmod tempfile: %v\n", err)
		os.Exit(1)
	}
	if _, err := tmpFile.Write(decrypted); err != nil {
		tmpFile.Close()
		fmt.Fprintf(os.Stderr, "error writing tempfile: %v\n", err)
		os.Exit(1)
	}
	if err := tmpFile.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "error closing tempfile: %v\n", err)
		os.Exit(1)
	}

	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vi"
	}
	// Invoke via shell so $EDITOR can include flags (e.g. "code --wait").
	cmd := exec.Command("sh", "-c", editor+` "$1"`, "sh", tmpPath)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "editor exited with error: %v (changes discarded)\n", err)
		os.Exit(1)
	}

	edited, err := os.ReadFile(tmpPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading edited file: %v\n", err)
		os.Exit(1)
	}

	// PLAIN["..."] -> CIPHER["..."]
	reencrypted, err := rewritePlainToCipher(edited, key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error re-encrypting: %v\n", err)
		os.Exit(1)
	}

	if err := atomicWrite(path, reencrypted); err != nil {
		fmt.Fprintf(os.Stderr, "error saving %s: %v\n", path, err)
		os.Exit(1)
	}
}

func cmdMigrate(args []string) {
	fs := flag.NewFlagSet("migrate", flag.ExitOnError)
	fs.Parse(args)
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: hclconfig migrate <file>")
		os.Exit(1)
	}
	path := fs.Arg(0)
	src, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading %s: %v\n", path, err)
		os.Exit(1)
	}
	out := legacyDecryptRE.ReplaceAllFunc(src, func(match []byte) []byte {
		sub := legacyDecryptRE.FindSubmatch(match)
		return []byte(fmt.Sprintf("CIPHER[%q]", string(sub[1])))
	})
	if err := atomicWrite(path, out); err != nil {
		fmt.Fprintf(os.Stderr, "error writing %s: %v\n", path, err)
		os.Exit(1)
	}
}

func cmdRekey(args []string) {
	fs := flag.NewFlagSet("rekey", flag.ExitOnError)
	oldKey := fs.String("old-key", "", "current encryption key (defaults to HCLCONFIG_KEY)")
	newKey := fs.String("new-key", "", "new encryption key (required)")
	fs.Parse(args)
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: hclconfig rekey -new-key <newkey> [-old-key <oldkey>] <file>")
		os.Exit(1)
	}
	if *newKey == "" {
		fmt.Fprintln(os.Stderr, "error: -new-key is required")
		os.Exit(1)
	}
	old := *oldKey
	if old == "" {
		old = os.Getenv("HCLCONFIG_KEY")
	}
	if old == "" {
		fmt.Fprintln(os.Stderr, "error: no old key provided; use -old-key or set HCLCONFIG_KEY")
		os.Exit(1)
	}

	path := fs.Arg(0)
	src, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading %s: %v\n", path, err)
		os.Exit(1)
	}

	var rekeyErr error
	out := cipherRE.ReplaceAllFunc(src, func(match []byte) []byte {
		if rekeyErr != nil {
			return match
		}
		sub := cipherRE.FindSubmatch(match)
		ct := string(sub[1])
		pt, err := hclconfig.Decrypt(ct, old)
		if err != nil {
			rekeyErr = fmt.Errorf("decrypting %q with old key: %w", ct, err)
			return match
		}
		newCt, err := hclconfig.Encrypt(pt, *newKey)
		if err != nil {
			rekeyErr = fmt.Errorf("encrypting with new key: %w", err)
			return match
		}
		return []byte(fmt.Sprintf("CIPHER[%q]", newCt))
	})
	if rekeyErr != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", rekeyErr)
		os.Exit(1)
	}
	if err := atomicWrite(path, out); err != nil {
		fmt.Fprintf(os.Stderr, "error writing %s: %v\n", path, err)
		os.Exit(1)
	}
}

func rewriteCipherToPlain(src []byte, key string) ([]byte, error) {
	var firstErr error
	out := cipherRE.ReplaceAllFunc(src, func(match []byte) []byte {
		if firstErr != nil {
			return match
		}
		sub := cipherRE.FindSubmatch(match)
		pt, err := hclconfig.Decrypt(string(sub[1]), key)
		if err != nil {
			firstErr = fmt.Errorf("decrypting %q: %w", string(sub[1]), err)
			return match
		}
		return []byte("PLAIN[" + strconv.Quote(pt) + "]")
	})
	return out, firstErr
}

func rewritePlainToCipher(src []byte, key string) ([]byte, error) {
	var firstErr error
	out := plainRE.ReplaceAllFunc(src, func(match []byte) []byte {
		if firstErr != nil {
			return match
		}
		sub := plainRE.FindSubmatch(match)
		quoted := `"` + string(sub[1]) + `"`
		pt, err := strconv.Unquote(quoted)
		if err != nil {
			firstErr = fmt.Errorf("parsing PLAIN value %s: %w", quoted, err)
			return match
		}
		ct, err := hclconfig.Encrypt(pt, key)
		if err != nil {
			firstErr = fmt.Errorf("encrypting: %w", err)
			return match
		}
		return []byte(fmt.Sprintf("CIPHER[%q]", ct))
	})
	return out, firstErr
}

func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, path)
}
