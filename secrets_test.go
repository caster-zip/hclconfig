package hclconfig

import (
	"strings"
	"testing"
)

type CipherDBConfig struct {
	Host     string `hcl:"host,attr"`
	Password string `hcl:"password,attr"`
}

type CipherAppConfig struct {
	DBUrl   string   `hcl:"db_url,attr"`
	APIKeys []string `hcl:"api_keys,attr"`
}

type CipherTestConfig struct {
	DB  CipherDBConfig  `hcl:"db,block"`
	App CipherAppConfig `hcl:"app,block"`
}

func TestLoad_Cipher_BlockAttribute(t *testing.T) {
	key, _ := GenerateKey()
	t.Setenv("HCLCONFIG_KEY", key)

	pw, _ := Encrypt("super-secret", key)
	src := []byte(`
db {
  host     = "localhost"
  password = CIPHER["` + pw + `"]
}
app {
  db_url   = "postgres://localhost"
  api_keys = []
}
`)
	var cfg CipherTestConfig
	if err := Load(src, "test.hcl", &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.DB.Password != "super-secret" {
		t.Errorf("password = %q, want %q", cfg.DB.Password, "super-secret")
	}
}

func TestLoad_Cipher_CrossBlockInterpolation(t *testing.T) {
	key, _ := GenerateKey()
	t.Setenv("HCLCONFIG_KEY", key)

	pw, _ := Encrypt("p@ssw0rd", key)
	src := []byte(`
db {
  host     = "db.example.com"
  password = CIPHER["` + pw + `"]
}
app {
  db_url   = "postgres://user:${db.password}@${db.host}/mydb"
  api_keys = []
}
`)
	var cfg CipherTestConfig
	if err := Load(src, "test.hcl", &cfg); err != nil {
		t.Fatal(err)
	}
	expected := "postgres://user:p@ssw0rd@db.example.com/mydb"
	if cfg.App.DBUrl != expected {
		t.Errorf("db_url = %q, want %q", cfg.App.DBUrl, expected)
	}
}

func TestLoad_Cipher_InsideList(t *testing.T) {
	key, _ := GenerateKey()
	t.Setenv("HCLCONFIG_KEY", key)

	k1, _ := Encrypt("first", key)
	k2, _ := Encrypt("second", key)
	src := []byte(`
db {
  host     = "x"
  password = "y"
}
app {
  db_url   = ""
  api_keys = [CIPHER["` + k1 + `"], CIPHER["` + k2 + `"]]
}
`)
	var cfg CipherTestConfig
	if err := Load(src, "test.hcl", &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.App.APIKeys) != 2 || cfg.App.APIKeys[0] != "first" || cfg.App.APIKeys[1] != "second" {
		t.Errorf("api_keys = %v, want [first second]", cfg.App.APIKeys)
	}
}

func TestLoad_Cipher_InStringInterpolation(t *testing.T) {
	key, _ := GenerateKey()
	t.Setenv("HCLCONFIG_KEY", key)

	pw, _ := Encrypt("inner-secret", key)
	src := []byte(`
db {
  host     = "h"
  password = "p"
}
app {
  db_url   = "prefix-${CIPHER["` + pw + `"]}-suffix"
  api_keys = []
}
`)
	var cfg CipherTestConfig
	if err := Load(src, "test.hcl", &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.App.DBUrl != "prefix-inner-secret-suffix" {
		t.Errorf("db_url = %q, want %q", cfg.App.DBUrl, "prefix-inner-secret-suffix")
	}
}

func TestLoad_Cipher_AsFreeVariable(t *testing.T) {
	key, _ := GenerateKey()
	t.Setenv("HCLCONFIG_KEY", key)

	pw, _ := Encrypt("free-var-secret", key)
	src := []byte(`
secret = CIPHER["` + pw + `"]

service {
  url = "https://user:${secret}@example.com"
}
`)
	type Cfg struct {
		Service struct {
			URL string `hcl:"url,attr"`
		} `hcl:"service,block"`
		Secret string `hcl:"secret,attr"`
	}
	var cfg Cfg
	if err := Load(src, "test.hcl", &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Secret != "free-var-secret" {
		t.Errorf("secret = %q, want %q", cfg.Secret, "free-var-secret")
	}
	if cfg.Service.URL != "https://user:free-var-secret@example.com" {
		t.Errorf("service.url = %q", cfg.Service.URL)
	}
}

func TestLoad_Cipher_NoKeySet(t *testing.T) {
	t.Setenv("HCLCONFIG_KEY", "")

	src := []byte(`
db {
  host     = "x"
  password = CIPHER["abc"]
}
app {
  db_url   = ""
  api_keys = []
}
`)
	var cfg CipherTestConfig
	err := Load(src, "test.hcl", &cfg)
	if err == nil {
		t.Fatal("expected error when no key set")
	}
	if !strings.Contains(err.Error(), "no encryption key") {
		t.Errorf("expected 'no encryption key' in error, got: %v", err)
	}
}

func TestLoad_Cipher_WithEncryptionKeyOption(t *testing.T) {
	key, _ := GenerateKey()
	t.Setenv("HCLCONFIG_KEY", "") // ensure env not used

	pw, _ := Encrypt("via-option", key)
	src := []byte(`
db {
  host     = "h"
  password = CIPHER["` + pw + `"]
}
app {
  db_url   = ""
  api_keys = []
}
`)
	var cfg CipherTestConfig
	if err := Load(src, "test.hcl", &cfg, WithEncryptionKey(key)); err != nil {
		t.Fatal(err)
	}
	if cfg.DB.Password != "via-option" {
		t.Errorf("password = %q, want %q", cfg.DB.Password, "via-option")
	}
}

func TestLoad_Cipher_BadCiphertext(t *testing.T) {
	key, _ := GenerateKey()
	t.Setenv("HCLCONFIG_KEY", key)

	src := []byte(`
db {
  host     = "x"
  password = CIPHER["not-real-base64-tampered"]
}
app {
  db_url   = ""
  api_keys = []
}
`)
	var cfg CipherTestConfig
	err := Load(src, "test.hcl", &cfg)
	if err == nil {
		t.Fatal("expected decryption error for bad ciphertext")
	}
	if !strings.Contains(err.Error(), "decrypting") {
		t.Errorf("expected 'decrypting' in error, got: %v", err)
	}
}

func TestLoad_Plain_ErrorsAtLoadTime(t *testing.T) {
	src := []byte(`
db {
  host     = "x"
  password = PLAIN["leaked-secret"]
}
app {
  db_url   = ""
  api_keys = []
}
`)
	var cfg CipherTestConfig
	err := Load(src, "test.hcl", &cfg)
	if err == nil {
		t.Fatal("expected error for PLAIN sentinel at load time")
	}
	if !strings.Contains(err.Error(), "PLAIN") {
		t.Errorf("expected PLAIN-related error, got: %v", err)
	}
}

func TestLoad_Cipher_BackwardsCompat_DecryptStillWorks(t *testing.T) {
	key, _ := GenerateKey()
	t.Setenv("LEGACY_KEY", key)

	pw, _ := Encrypt("legacy-secret", key)
	src := []byte(`
db {
  host     = "x"
  password = decrypt("` + pw + `", env("LEGACY_KEY"))
}
app {
  db_url   = ""
  api_keys = []
}
`)
	var cfg CipherTestConfig
	if err := Load(src, "test.hcl", &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.DB.Password != "legacy-secret" {
		t.Errorf("password = %q, want %q", cfg.DB.Password, "legacy-secret")
	}
}
