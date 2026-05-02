# hclconfig

A Go library that parses HCL configuration files with **cross-block and cross-attribute variable resolution**, a built-in `env()` function, and **transparent secret decryption** via the `CIPHER["..."]` sentinel. Define your config schema as Go structs with `hcl` struct tags — the library handles dependency-aware ordered decoding so that `${database.host}` in one block or `${myvar}` in an attribute resolves automatically.

## Install

```bash
go get github.com/bntso/hclconfig@v0.5.1
```

## Usage

### Define your config schema

```go
type Config struct {
    Database DatabaseConfig `hcl:"database,block"`
    App      AppConfig      `hcl:"app,block"`
}

type DatabaseConfig struct {
    Host string `hcl:"host,attr"`
    Port int    `hcl:"port,attr"`
}

type AppConfig struct {
    DBUrl string `hcl:"db_url,attr"`
}
```

### Write an HCL config file

```hcl
database {
    host = "localhost"
    port = 5432
}

app {
    db_url = "postgres://${database.host}:${database.port}/mydb"
}
```

### Load it

```go
var cfg Config
err := hclconfig.LoadFile("config.hcl", &cfg)
// cfg.App.DBUrl == "postgres://localhost:5432/mydb"
```

Block order in the HCL file doesn't matter — dependencies are resolved automatically.

## Features

### Cross-block references

Reference values from other blocks using `${block.attribute}` syntax. Dependencies are analyzed and blocks are decoded in the correct order.

```hcl
database {
    host = "localhost"
    port = 5432
}

app {
    db_url = "postgres://${database.host}:${database.port}/mydb"
}
```

### Top-level attribute references

Top-level attributes can reference each other and be referenced from blocks. Dependencies are resolved across both attributes and blocks in a unified dependency graph.

```hcl
group = "mygroup"

instance "mytest" {
    norun    = true
    image    = "images:ubuntu/24.04"
    networks = ["web"]
    build = [
        <<-SETUPEOF
        ${myvar}
        SETUPEOF
    ]
}

myvar = <<-EOF
    export DEBIAN_FRONTEND=noninteractive
    sudo apt install -y postgresql-common
    ${mysubvar}
    EOF

mysubvar = <<-EOF
    sudo /usr/share/postgresql-common/pgdg/apt.postgresql.org.sh -y
    EOF
```

```go
type InstanceConfig struct {
    Name     string   `hcl:"name,label"`
    NoRun    bool     `hcl:"norun,attr"`
    Image    string   `hcl:"image,attr"`
    Networks []string `hcl:"networks,attr"`
    Build    []string `hcl:"build,attr"`
}

type Config struct {
    Group     string           `hcl:"group,attr"`
    Instances []InstanceConfig `hcl:"instance,block"`
    MyVar     string           `hcl:"myvar,attr"`
    MySubVar  string           `hcl:"mysubvar,attr"`
}
```

The resolution chain `mysubvar` -> `myvar` -> `instance.build` is resolved automatically regardless of declaration order.

### Variables

Define reusable variables as bare top-level attributes. Any attribute not mapped to a Go struct field becomes a free variable, available for interpolation as `${name}` throughout the config.

```hcl
api_host = "api.example.com"
api_port = 8080

service {
  url = "http://${api_host}:${api_port}/api"
}
```

Variables can reference other variables, environment variables, and user-defined blocks:

```hcl
base_domain = "example.com"
api_host    = "api.${base_domain}"
db_host     = env("DB_HOST")
```

### Environment variables

Use the built-in `env()` function to read environment variables.

```hcl
database {
    host     = env("DB_HOST")
    password = env("DB_PASSWORD")
}
```

### Encrypted secrets

Store encrypted secrets directly in config files committed to git. Wrap each secret with `CIPHER["..."]` and the library decrypts it transparently at load time using the key from `HCLCONFIG_KEY`.

```hcl
database {
    host     = "localhost"
    port     = 5432
    password = CIPHER["hvqO8KTHCuCQU6af..."]
}

api_keys = [CIPHER["c2VjcmV0MQ..."], CIPHER["c2VjcmV0Mg..."]]
```

Secrets are encrypted with AES-256-GCM. The encryption key is kept out of the repo (e.g., in an environment variable or secrets manager). `CIPHER` and `PLAIN` are reserved variable names — don't use them for other purposes.

#### Editing secrets in place

`hclconfig edit <file>` opens your config in `$EDITOR` with every `CIPHER["..."]` decrypted to `PLAIN["..."]` for editing. On save, anything still wrapped in `PLAIN["..."]` is re-encrypted to `CIPHER["..."]`.

```bash
hclconfig edit config.hcl
```

Inside the editor you might see:

```hcl
database {
    host     = "localhost"
    password = PLAIN["my-real-password"]
}

api_keys = [PLAIN["secret-1"], PLAIN["secret-2"]]
```

You can edit existing secrets, add new ones (just write `PLAIN["new-value"]`), or change non-secret config — saving re-encrypts everything still in `PLAIN[...]` form.

The `PLAIN["..."]` content is Go-style quoted (use `\"` for embedded quotes, `\\` for backslashes). The tempfile is created with mode 0600 in the same directory as the original; on shared boxes, ensure that directory is private.

#### CLI tool

```bash
# Generate a new 256-bit encryption key
go run github.com/bntso/hclconfig/cmd/hclconfig genkey

# Encrypt a secret (outputs a ready-to-paste CIPHER[...] snippet)
hclconfig encrypt -key <base64-key> "super-secret-pass"
# Output: CIPHER["base64-encrypted..."]

# Decrypt a value for debugging
hclconfig decrypt -key <base64-key> "base64-encrypted..."

# Edit a config with secrets transparently decrypted
hclconfig edit config.hcl

# Migrate legacy decrypt() calls to CIPHER["..."]
hclconfig migrate config.hcl

# Rotate the encryption key on a file
hclconfig rekey -old-key <old> -new-key <new> config.hcl
```

Set `HCLCONFIG_KEY` to avoid passing `-key` repeatedly:

```bash
export HCLCONFIG_KEY=$(hclconfig genkey)
hclconfig encrypt "super-secret-pass"
```

#### Go API

```go
// Generate a new key
key, _ := hclconfig.GenerateKey()

// Encrypt a value
ciphertext, _ := hclconfig.Encrypt("my-secret", key)

// Decrypt a value
plaintext, _ := hclconfig.Decrypt(ciphertext, key)

// Pass the key explicitly instead of using HCLCONFIG_KEY
err := hclconfig.LoadFile("config.hcl", &cfg, hclconfig.WithEncryptionKey(key))
```

#### Legacy `decrypt()` function

The original `decrypt(ciphertext, key)` HCL function still works for backwards compatibility but is deprecated. Use `hclconfig migrate <file>` to convert existing configs.

### Labeled blocks

Blocks with labels are accessible by their label name.

```hcl
service "api" {
    host = "api.example.com"
    port = 8080
}

service "web" {
    host = "web.example.com"
    port = 3000
}

app {
    api_url = "http://${service.api.host}:${service.api.port}"
    web_url = "http://${service.web.host}:${service.web.port}"
}
```

```go
type ServiceConfig struct {
    Name string `hcl:"name,label"`
    Host string `hcl:"host,attr"`
    Port int    `hcl:"port,attr"`
}

type Config struct {
    Services []ServiceConfig `hcl:"service,block"`
    App      AppConfig       `hcl:"app,block"`
}
```

### Nested blocks

Nested blocks are converted to nested objects, allowing deep references.

```hcl
database {
    host = "localhost"
    port = 5432

    credentials {
        username = "admin"
        password = "secret"
    }
}

app {
    conn = "postgres://${database.credentials.username}:${database.credentials.password}@${database.host}:${database.port}/mydb"
}
```

### Optional blocks

Use pointer fields for blocks that may not be present.

```go
type Config struct {
    Database DatabaseConfig `hcl:"database,block"`
    App      *AppConfig     `hcl:"app,block"` // nil if not in config file
}
```

### Custom EvalContext

Pass additional variables or functions via `WithEvalContext`.

```go
ctx := &hcl.EvalContext{
    Variables: map[string]cty.Value{
        "region": cty.StringVal("us-east-1"),
    },
}

var cfg Config
err := hclconfig.LoadFile("config.hcl", &cfg, hclconfig.WithEvalContext(ctx))
```

## API

```go
func LoadFile(filename string, dst interface{}, opts ...Option) error
func Load(src []byte, filename string, dst interface{}, opts ...Option) error
func WithEvalContext(ctx *hcl.EvalContext) Option
func WithEncryptionKey(key string) Option

// Crypto
func GenerateKey() (string, error)
func Encrypt(plaintext, base64Key string) (string, error)
func Decrypt(ciphertext, base64Key string) (string, error)
```

### Error types

- **`CycleError`** — returned when circular dependencies are detected between blocks or attributes
- **`DiagnosticsError`** — wraps HCL diagnostics (parse errors, unknown variables, etc.)

```go
var cfg Config
err := hclconfig.LoadFile("config.hcl", &cfg)

var cycleErr *hclconfig.CycleError
if errors.As(err, &cycleErr) {
    fmt.Println("cycle:", cycleErr.Cycle)
}

var diagErr *hclconfig.DiagnosticsError
if errors.As(err, &diagErr) {
    for _, d := range diagErr.Diags {
        fmt.Println(d.Summary)
    }
}
```

## License

MIT
