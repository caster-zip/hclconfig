package hclconfig

import (
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
)

// --- Test struct types ---

type DatabaseConfig struct {
	Host string `hcl:"host,attr"`
	Port int    `hcl:"port,attr"`
}

type AppConfig struct {
	DBUrl string `hcl:"db_url,attr"`
}

type SimpleConfig struct {
	Database DatabaseConfig `hcl:"database,block"`
}

type CrossRefConfig struct {
	Database DatabaseConfig `hcl:"database,block"`
	App      AppConfig      `hcl:"app,block"`
}

type ServiceConfig struct {
	Name string `hcl:"name,label"`
	Host string `hcl:"host,attr"`
	Port int    `hcl:"port,attr"`
}

type LabeledAppConfig struct {
	APIURL string `hcl:"api_url,attr"`
	WebURL string `hcl:"web_url,attr"`
}

type LabeledConfig struct {
	Services []ServiceConfig `hcl:"service,block"`
	App      LabeledAppConfig `hcl:"app,block"`
}

type CredentialsConfig struct {
	Username string `hcl:"username,attr"`
	Password string `hcl:"password,attr"`
}

type NestedDBConfig struct {
	Host        string            `hcl:"host,attr"`
	Port        int               `hcl:"port,attr"`
	Credentials CredentialsConfig `hcl:"credentials,block"`
}

type NestedAppConfig struct {
	ConnString string `hcl:"conn_string,attr"`
}

type NestedConfig struct {
	Database NestedDBConfig  `hcl:"database,block"`
	App      NestedAppConfig `hcl:"app,block"`
}

type CycleAlpha struct {
	Value string `hcl:"value,attr"`
}

type CycleBeta struct {
	Value string `hcl:"value,attr"`
}

type CycleConfig struct {
	Alpha CycleAlpha `hcl:"alpha,block"`
	Beta  CycleBeta  `hcl:"beta,block"`
}

type OptionalConfig struct {
	Database DatabaseConfig `hcl:"database,block"`
	App      *AppConfig     `hcl:"app,block"`
}

type InstanceConfig struct {
	Name     string   `hcl:"name,label"`
	NoRun    bool     `hcl:"norun,attr"`
	Image    string   `hcl:"image,attr"`
	Networks []string `hcl:"networks,attr"`
	Build    []string `hcl:"build,attr"`
}

type HeredocVarsConfig struct {
	Group     string           `hcl:"group,attr"`
	Instances []InstanceConfig `hcl:"instance,block"`
	MyVar     string           `hcl:"myvar,attr"`
	MySubVar  string           `hcl:"mysubvar,attr"`
}

type BadFieldConfig struct {
	Database DatabaseConfig `hcl:"database,block"`
	Count    int            `hcl:"count,attr"`
}

type VarServiceConfig struct {
	URL string `hcl:"url,attr"`
}

type VarTestConfig struct {
	Service VarServiceConfig `hcl:"service,block"`
}

// --- Tests ---

func TestLoadFile_Simple(t *testing.T) {
	var cfg SimpleConfig
	err := LoadFile("testdata/simple.hcl", &cfg)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Database.Host != "localhost" {
		t.Errorf("host = %q, want %q", cfg.Database.Host, "localhost")
	}
	if cfg.Database.Port != 5432 {
		t.Errorf("port = %d, want %d", cfg.Database.Port, 5432)
	}
}

func TestLoadFile_CrossRef(t *testing.T) {
	var cfg CrossRefConfig
	err := LoadFile("testdata/cross_ref.hcl", &cfg)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Database.Host != "localhost" {
		t.Errorf("database.host = %q, want %q", cfg.Database.Host, "localhost")
	}
	expected := "postgres://localhost:5432/mydb"
	if cfg.App.DBUrl != expected {
		t.Errorf("app.db_url = %q, want %q", cfg.App.DBUrl, expected)
	}
}

func TestLoadFile_EnvVar(t *testing.T) {
	os.Setenv("DB_HOST", "envhost.example.com")
	defer os.Unsetenv("DB_HOST")

	var cfg SimpleConfig
	err := LoadFile("testdata/env_var.hcl", &cfg)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Database.Host != "envhost.example.com" {
		t.Errorf("host = %q, want %q", cfg.Database.Host, "envhost.example.com")
	}
}

func TestLoadFile_Labeled(t *testing.T) {
	var cfg LabeledConfig
	err := LoadFile("testdata/labeled.hcl", &cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Services) != 2 {
		t.Fatalf("expected 2 services, got %d", len(cfg.Services))
	}

	expected := "http://api.example.com:8080"
	if cfg.App.APIURL != expected {
		t.Errorf("app.api_url = %q, want %q", cfg.App.APIURL, expected)
	}
	expected = "http://web.example.com:3000"
	if cfg.App.WebURL != expected {
		t.Errorf("app.web_url = %q, want %q", cfg.App.WebURL, expected)
	}
}

func TestLoadFile_Cycle(t *testing.T) {
	var cfg CycleConfig
	err := LoadFile("testdata/cycle.hcl", &cfg)
	if err == nil {
		t.Fatal("expected cycle error")
	}
	if _, ok := err.(*CycleError); !ok {
		t.Fatalf("expected CycleError, got %T: %v", err, err)
	}
}

func TestLoadFile_Nested(t *testing.T) {
	var cfg NestedConfig
	err := LoadFile("testdata/nested.hcl", &cfg)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Database.Credentials.Username != "admin" {
		t.Errorf("credentials.username = %q, want %q", cfg.Database.Credentials.Username, "admin")
	}
	expected := "postgres://admin:secret@localhost:5432/mydb"
	if cfg.App.ConnString != expected {
		t.Errorf("conn_string = %q, want %q", cfg.App.ConnString, expected)
	}
}

func TestLoad_OptionalBlock_Present(t *testing.T) {
	src := []byte(`
database {
    host = "localhost"
    port = 5432
}
app {
    db_url = "postgres://${database.host}:${database.port}/mydb"
}
`)
	var cfg OptionalConfig
	err := Load(src, "test.hcl", &cfg)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.App == nil {
		t.Fatal("expected app to be non-nil")
	}
	expected := "postgres://localhost:5432/mydb"
	if cfg.App.DBUrl != expected {
		t.Errorf("app.db_url = %q, want %q", cfg.App.DBUrl, expected)
	}
}

func TestLoad_OptionalBlock_Missing(t *testing.T) {
	src := []byte(`
database {
    host = "localhost"
    port = 5432
}
`)
	var cfg OptionalConfig
	err := Load(src, "test.hcl", &cfg)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.App != nil {
		t.Error("expected app to be nil")
	}
}

func TestLoad_CustomEvalContext(t *testing.T) {
	src := []byte(`
database {
    host = myvar
    port = 5432
}
`)
	customCtx := &hcl.EvalContext{
		Variables: map[string]cty.Value{
			"myvar": cty.StringVal("custom-host"),
		},
	}

	var cfg SimpleConfig
	err := Load(src, "test.hcl", &cfg, WithEvalContext(customCtx))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Database.Host != "custom-host" {
		t.Errorf("host = %q, want %q", cfg.Database.Host, "custom-host")
	}
}

func TestLoad_ReverseOrder(t *testing.T) {
	// Test that dependency resolution works even when dependent block comes first
	src := []byte(`
app {
    db_url = "postgres://${database.host}:${database.port}/mydb"
}
database {
    host = "dbhost"
    port = 3306
}
`)
	var cfg CrossRefConfig
	err := Load(src, "test.hcl", &cfg)
	if err != nil {
		t.Fatal(err)
	}
	expected := "postgres://dbhost:3306/mydb"
	if cfg.App.DBUrl != expected {
		t.Errorf("app.db_url = %q, want %q", cfg.App.DBUrl, expected)
	}
}

func TestDiagnosticsError_IncludesLocation(t *testing.T) {
	// Parse error: invalid HCL syntax should report file and line
	src := []byte(`
database {
    host = "localhost"
    port = !!!
}
`)
	var cfg SimpleConfig
	err := Load(src, "bad.hcl", &cfg)
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "bad.hcl") {
		t.Errorf("error should contain filename, got: %s", msg)
	}
	if !strings.Contains(msg, ":4,") {
		t.Errorf("error should contain line number, got: %s", msg)
	}
}

func TestDiagnosticsError_IncludesDetail(t *testing.T) {
	// Reference to an undefined variable should include detail text
	src := []byte(`
database {
    host = undefined_var
    port = 5432
}
`)
	var cfg SimpleConfig
	err := Load(src, "detail.hcl", &cfg)
	if err == nil {
		t.Fatal("expected error")
	}
	diagErr, ok := err.(*DiagnosticsError)
	if !ok {
		t.Fatalf("expected DiagnosticsError, got %T: %v", err, err)
	}
	msg := diagErr.Error()
	// Should contain filename and line
	if !strings.Contains(msg, "detail.hcl") {
		t.Errorf("error should contain filename, got: %s", msg)
	}
	// Should contain both summary and detail
	if !strings.Contains(msg, ":") {
		t.Errorf("error should contain separator between summary and detail, got: %s", msg)
	}
	// The message should be more than just a bare summary
	if len(msg) < 20 {
		t.Errorf("error message too short, expected location and detail, got: %s", msg)
	}
}

func TestDiagnosticsError_BlockErrorIncludesBlockContext(t *testing.T) {
	// Unknown attribute inside a block should mention the block
	src := []byte(`
database {
    host = "localhost"
    port = 5432
    unknown_field = "oops"
}
`)
	var cfg SimpleConfig
	err := Load(src, "block.hcl", &cfg)
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "block.hcl") {
		t.Errorf("error should contain filename, got: %s", msg)
	}
}

func TestDiagnosticsError_UndefinedRefInBlock(t *testing.T) {
	// Reference to an undefined block should report location
	src := []byte(`
app {
    db_url = "postgres://${nonexistent.host}/mydb"
}
`)
	var cfg CrossRefConfig
	err := Load(src, "ref.hcl", &cfg)
	if err == nil {
		t.Fatal("expected error")
	}
	diagErr, ok := err.(*DiagnosticsError)
	if !ok {
		t.Fatalf("expected DiagnosticsError, got %T: %v", err, err)
	}
	msg := diagErr.Error()
	if !strings.Contains(msg, "ref.hcl") {
		t.Errorf("error should contain filename, got: %s", msg)
	}
	if !strings.Contains(msg, "3,") || !strings.Contains(msg, ":3,") {
		t.Errorf("error should reference line 3, got: %s", msg)
	}
}

func TestDiagnosticsError_LabeledBlockError(t *testing.T) {
	// Bad attribute inside a labeled block
	src := []byte(`
service "api" {
    host = "localhost"
    port = 8080
    bogus = true
}
`)
	type MinimalLabeledConfig struct {
		Services []ServiceConfig `hcl:"service,block"`
	}
	var cfg MinimalLabeledConfig
	err := Load(src, "labeled.hcl", &cfg)
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "labeled.hcl") {
		t.Errorf("error should contain filename, got: %s", msg)
	}
}

func TestLoadFile_HeredocVars(t *testing.T) {
	var cfg HeredocVarsConfig
	err := LoadFile("testdata/heredoc_vars.hcl", &cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Top-level simple attribute
	if cfg.Group != "mygroup" {
		t.Errorf("group = %q, want %q", cfg.Group, "mygroup")
	}

	// mysubvar has no dependencies — should resolve directly
	if !strings.Contains(cfg.MySubVar, "pgdg/apt.postgresql.org.sh") {
		t.Errorf("mysubvar should contain pgdg script, got: %q", cfg.MySubVar)
	}

	// myvar depends on mysubvar — should contain the resolved content
	if !strings.Contains(cfg.MyVar, "postgresql-common") {
		t.Errorf("myvar should contain postgresql-common, got: %q", cfg.MyVar)
	}
	if !strings.Contains(cfg.MyVar, "pgdg/apt.postgresql.org.sh") {
		t.Errorf("myvar should contain resolved mysubvar, got: %q", cfg.MyVar)
	}

	// Instance block
	if len(cfg.Instances) != 1 {
		t.Fatalf("expected 1 instance, got %d", len(cfg.Instances))
	}
	inst := cfg.Instances[0]
	if inst.Name != "mytest" {
		t.Errorf("instance name = %q, want %q", inst.Name, "mytest")
	}
	if !inst.NoRun {
		t.Error("expected norun to be true")
	}
	if inst.Image != "images:ubuntu/24.04" {
		t.Errorf("image = %q, want %q", inst.Image, "images:ubuntu/24.04")
	}
	if len(inst.Networks) != 1 || inst.Networks[0] != "web" {
		t.Errorf("networks = %v, want [web]", inst.Networks)
	}

	// build should contain resolved myvar (which itself contains resolved mysubvar)
	if len(inst.Build) != 1 {
		t.Fatalf("expected 1 build entry, got %d", len(inst.Build))
	}
	if !strings.Contains(inst.Build[0], "postgresql-common") {
		t.Errorf("build[0] should contain resolved myvar, got: %q", inst.Build[0])
	}
	if !strings.Contains(inst.Build[0], "pgdg/apt.postgresql.org.sh") {
		t.Errorf("build[0] should contain fully resolved chain, got: %q", inst.Build[0])
	}
}

func TestLoad_Var_Basic(t *testing.T) {
	var cfg VarTestConfig
	err := LoadFile("testdata/var.hcl", &cfg)
	if err != nil {
		t.Fatal(err)
	}
	expected := "http://api.example.com:8080/api"
	if cfg.Service.URL != expected {
		t.Errorf("service.url = %q, want %q", cfg.Service.URL, expected)
	}
}

func TestLoad_Var_Chain(t *testing.T) {
	src := []byte(`
var "base" {
  default = "example.com"
}

var "api_host" {
  default = "api.${var.base}"
}

service {
  url = "http://${var.api_host}/api"
}
`)
	var cfg VarTestConfig
	err := Load(src, "test.hcl", &cfg)
	if err != nil {
		t.Fatal(err)
	}
	expected := "http://api.example.com/api"
	if cfg.Service.URL != expected {
		t.Errorf("service.url = %q, want %q", cfg.Service.URL, expected)
	}
}

func TestLoad_Var_WithEnv(t *testing.T) {
	os.Setenv("TEST_VAR_HOST", "envhost.example.com")
	defer os.Unsetenv("TEST_VAR_HOST")

	src := []byte(`
var "host" {
  default = env("TEST_VAR_HOST")
}

service {
  url = "http://${var.host}/api"
}
`)
	var cfg VarTestConfig
	err := Load(src, "test.hcl", &cfg)
	if err != nil {
		t.Fatal(err)
	}
	expected := "http://envhost.example.com/api"
	if cfg.Service.URL != expected {
		t.Errorf("service.url = %q, want %q", cfg.Service.URL, expected)
	}
}

func TestLoad_Var_NumericType(t *testing.T) {
	src := []byte(`
var "api_host" {
  default = "api.example.com"
}

var "api_port" {
  default = 8080
}

service {
  url = "http://${var.api_host}:${var.api_port}/api"
}
`)
	var cfg VarTestConfig
	err := Load(src, "test.hcl", &cfg)
	if err != nil {
		t.Fatal(err)
	}
	expected := "http://api.example.com:8080/api"
	if cfg.Service.URL != expected {
		t.Errorf("service.url = %q, want %q", cfg.Service.URL, expected)
	}
}

func TestLoad_Var_MissingDefault(t *testing.T) {
	src := []byte(`
var "host" {
}

service {
  url = "http://${var.host}/api"
}
`)
	var cfg VarTestConfig
	err := Load(src, "test.hcl", &cfg)
	if err == nil {
		t.Fatal("expected error for missing default")
	}
	if !strings.Contains(err.Error(), "missing required \"default\" attribute") {
		t.Errorf("expected missing default error, got: %v", err)
	}
}

func TestLoad_Var_Cycle(t *testing.T) {
	src := []byte(`
var "a" {
  default = "${var.b}"
}

var "b" {
  default = "${var.a}"
}
`)
	var cfg struct{}
	err := Load(src, "test.hcl", &cfg)
	if err == nil {
		t.Fatal("expected cycle error")
	}
	if _, ok := err.(*CycleError); !ok {
		t.Fatalf("expected CycleError, got %T: %v", err, err)
	}
}

func TestLoad_Decrypt(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	secret := "super-secret-password"
	encrypted, err := Encrypt(secret, key)
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv("TEST_DECRYPT_KEY", key)

	src := []byte(`
database {
    host = "localhost"
    port = 5432
}
app {
    db_url = decrypt("` + encrypted + `", env("TEST_DECRYPT_KEY"))
}
`)
	var cfg CrossRefConfig
	err = Load(src, "test.hcl", &cfg)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.App.DBUrl != secret {
		t.Errorf("app.db_url = %q, want %q", cfg.App.DBUrl, secret)
	}
}

func TestLoad_DecryptWithVar(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	secret := "my-db-password"
	encrypted, err := Encrypt(secret, key)
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv("TEST_DECRYPT_KEY", key)

	src := []byte(`
var "secret_key" {
    default = env("TEST_DECRYPT_KEY")
}

db_url = "postgres://user:${decrypt("` + encrypted + `", var.secret_key)}@localhost/mydb"
`)

	type Config struct {
		DBUrl string `hcl:"db_url,attr"`
	}
	var cfg Config
	err = Load(src, "test.hcl", &cfg)
	if err != nil {
		t.Fatal(err)
	}
	expected := "postgres://user:" + secret + "@localhost/mydb"
	if cfg.DBUrl != expected {
		t.Errorf("db_url = %q, want %q", cfg.DBUrl, expected)
	}
}

func TestLoad_Var_NoVars(t *testing.T) {
	// Regression: configs without var blocks should still work
	src := []byte(`
database {
    host = "localhost"
    port = 5432
}
`)
	var cfg SimpleConfig
	err := Load(src, "test.hcl", &cfg)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Database.Host != "localhost" {
		t.Errorf("host = %q, want %q", cfg.Database.Host, "localhost")
	}
}
