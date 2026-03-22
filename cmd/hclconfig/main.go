package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/bntso/hclconfig"
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
  encrypt [options] <plaintext>   Encrypt a secret and output an HCL snippet
  decrypt [options] <ciphertext>  Decrypt an encrypted value

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
	keyEnvFlag := fs.String("key-env", "CONFIG_SECRET_KEY", "env var name to reference in the output snippet")
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

	fmt.Printf("decrypt(%q, env(%q))\n", ciphertext, *keyEnvFlag)
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
