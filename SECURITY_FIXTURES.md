# Deliberately insecure test fixtures

This repository is for validating SCA, SAST, secret, and IaC scanners. It deliberately contains outdated dependencies, unsafe code patterns, fake hard-coded credentials, and insecure infrastructure settings. **Do not deploy or reuse these patterns.**

Every vulnerable function is annotated in-source with `// VULN: <name> — CWE-xxx — gosec Gxxx`. Functions annotated `// SAFE:` are negative controls: a correct scanner should **not** flag them.

## Reference baseline (open-source scanners)

Generated 2026-09-11 with `gosec v2.29.0` and `govulncheck` (latest). Use these as a floor; a scanner with better taint analysis may find more.

| Tool | Result |
|---|---|
| `gosec ./...` | 73 issues (24 HIGH, 40 MEDIUM, 9 LOW) across 38 rule IDs |
| `govulncheck ./...` | 12 vulnerabilities **reachable** from code; 22 more in imported packages, 20 more in required modules (not called) |
| `gitleaks detect` (default rules) | 1 finding (`private-key`) — see the push-protection note under Secrets |
| `go build ./... && go vet ./... && go test ./...` | clean |

## SAST — expected findings by file

### `src/injection.go`
| Function | Vulnerability | CWE | gosec |
|---|---|---|---|
| `SQLInjectionSprintf` | SQL injection via `fmt.Sprintf` | 89 | G201 / G701 |
| `SQLInjectionConcat` | SQL injection via string concat | 89 | G202 |
| `SQLInjectionHandler` | SQL injection from HTTP param into `Exec` | 89 | G202 / G701 |
| `CommandInjectionShell` | `sh -c` with tainted string | 78 | G204 / G702 |
| `CommandInjectionBinary` | attacker-controlled binary path | 78 | G204 |
| `CommandInjectionHandler` | `exec.Command` arg from `r.FormValue` | 78 | G204 / G702 |
| `TemplateInjection` | user input parsed as `text/template` | 1336 | G708 |
| `LogInjection` | password + unescaped input logged | 117, 532 | — |
| `SQLSafeParameterised` | **SAFE** parameterised query | — | must not flag |
| `CommandSafeFixed` | **SAFE** fixed binary/args | — | must not flag |

### `src/web.go`
| Function | Vulnerability | CWE | gosec |
|---|---|---|---|
| import `net/http/pprof` | profiling endpoint exposed | 200 | G108 |
| `ReflectedXSS` | raw input in `fmt.Fprintf(w, …)` | 79 | G705 |
| `TemplateHTMLXSS` | `template.HTML` escape bypass | 79 | G203 |
| `OpenRedirect` | `http.Redirect` to tainted URL | 601 | G710 |
| `SSRF` | `http.Get` on tainted URL | 918 | G107 / G704 |
| `PermissiveCORS` | `Allow-Origin: *` + credentials | 942 | — |
| `ReflectedOriginCORS` | Origin reflected + credentials | 942 | — |
| `InsecureCookie` | no Secure / HttpOnly / SameSite | 614, 1004 | G124 |
| `UnboundedBodyRead` | `io.ReadAll(r.Body)` no limit | 400 | — |
| `BindAllInterfaces` | listens on `0.0.0.0` | 200 | G102 |
| `ServeNoTimeouts` | `http.ListenAndServe` | 400 | G114 |
| `ServeMissingReadHeaderTimeout` | `http.Server` w/o `ReadHeaderTimeout` | 400 | G112 |
| `DebugErrorLeak` | `%+v` error to client | 209 | — |
| `CallWithBasicAuth` | hard-coded `Authorization: Basic` | 798 | — |
| `TemplateSafe` | **SAFE** auto-escaped `html/template` | — | must not flag |
| `ServeWithTimeouts` | **SAFE** all timeouts set | — | must not flag |

### `src/crypto.go`
| Function | Vulnerability | CWE | gosec |
|---|---|---|---|
| imports | `crypto/md5`, `crypto/des`, `crypto/rc4`, `crypto/sha1` | 327 | G501, G502, G503, G505 |
| `HashPasswordMD5` | MD5 for passwords | 327, 916 | G401 |
| `HashSHA1` | SHA-1 | 328 | G401 |
| `HashPasswordUnsalted` | unsalted SHA-256 for passwords | 916 | — |
| `EncryptDES` | DES, ECB mode | 327 | G405 |
| `EncryptRC4` | RC4 | 327 | G405 |
| `EncryptAESCBCStaticIV` | static IV (`staticIV` global) | 329 | G407 |
| `EncryptWithHardcodedKey` | hard-coded AES key + zero GCM nonce | 321, 323 | G407 |
| `GenerateWeakRSAKey` | RSA 1024 | 326 | G403 |
| `InsecureSessionToken` | `math/rand` for token | 338 | G404 |
| `InsecureHTTPClient` | `InsecureSkipVerify: true` | 295 | G402 |
| `WeakTLSConfig` | TLS 1.0 min, RC4 / 3DES suites | 326 | G402 |
| `CompareTokenUnsafe` | `==` on secret | 208 | — |
| `SecureSessionToken` | **SAFE** `crypto/rand` | — | must not flag |
| `CompareTokenSafe` | **SAFE** `subtle.ConstantTimeCompare` | — | must not flag |

### `src/files.go`
| Function | Vulnerability | CWE | gosec |
|---|---|---|---|
| `PathTraversalHandler` | `os.ReadFile` on tainted path | 22 | G304 / G703 |
| `ReadUserFile` | `filepath.Join` does not stop `..` | 22 | G304 |
| `OpenUserFile` | `os.Open` on tainted path | 22 | G304 |
| `ExtractZip` | zip slip, `0777` dir, `0666` file, unbounded copy | 22, 276, 409 | G305, G301, G302, G110 |
| `DecompressUnbounded` | gzip bomb | 409 | G110 |
| `InsecurePermissions` | `MkdirAll 0777`, `WriteFile 0666`, `Chmod 0777` | 276, 732 | G301, G306, G302 |
| `PredictableTempFile` | fixed path in `/tmp` | 377 | G303 |
| `ReadIfExists` | TOCTOU (`Stat` then `ReadFile`) | 367 | — |
| `LeakHandle` | file handle leaked on error path | 772 | — |
| `ReadUserFileSafe` | **SAFE** cleaned + prefix-checked | — | should not flag (gosec G304 false-positives here) |

### `src/unsafe_misc.go`
| Function | Vulnerability | CWE | gosec |
|---|---|---|---|
| `UnsafePointerRead` | `unsafe` pointer arithmetic | 119 | G103 |
| `UnhandledErrors` | 4× ignored error returns | 252 | G104 |
| `NarrowingConversion` | `int → int32` from `Atoi` | 190 | G109 / G115 |
| `LengthFromInput` | `int → uint8` as length | 190 | G115 |
| `SliceOutOfBounds` | `s[5]` on len-3 slice | 125 | G602 |
| `NilMapWrite` | write to nil map (panic) | 476 | — |
| `RaceyIncrement` | unsynchronised `hitCounter++` in goroutines | 362 | — |
| `dbPassword`, `DBConfig` | hard-coded DB credentials | 798 | G101 |
| `Config` | `debug: true`, `verify_tls: false` | 489 | — |

### `src/deps.go`
| Function | Vulnerability | CWE | gosec |
|---|---|---|---|
| `ParseJWTUnverified` | `ParseUnverified` — no signature check | 347 | — |
| `ParseJWTNoAlgCheck` | key func ignores `alg`; hard-coded secret | 347, 798 | — |
| `Upgrader` | websocket `CheckOrigin` always true | 346 | — |
| `NewRouter` `/greet` | reflected XSS via gin | 79 | — |
| `InsecureSSHConfig` | `ssh.InsecureIgnoreHostKey()` + password auth | 322 | G106 |

### `src/app.go`, `src/vulnerable.go` (original fixtures)
| Function | Vulnerability | CWE |
|---|---|---|
| `Login` | hard-coded `admin` / `password123` | 798 |
| `UnsafeQuery` | SQL string concat | 89 |

## SCA — expected findings (`go.mod`)

All versions are pinned on purpose. `go mod tidy` will keep them; do not run `go get -u`.

| Module | Pinned version | Known advisories (non-exhaustive) | Called from |
|---|---|---|---|
| `github.com/dgrijalva/jwt-go` | v3.2.0+incompatible | CVE-2020-26160 / GHSA-w73w-5m7g-f7qc (archived, unmaintained) | `ParseJWTUnverified`, `ParseJWTNoAlgCheck` |
| `github.com/gin-gonic/gin` | v1.7.0 | CVE-2020-28483, CVE-2023-26125, CVE-2023-29401 | `NewRouter` |
| `github.com/gorilla/websocket` | v1.4.0 | CVE-2020-27813, GO-2026-6278 | `WebsocketEcho` |
| `golang.org/x/crypto` | v0.0.0-20200622213623-75b288015ac9 | CVE-2020-9283, CVE-2021-43565, CVE-2022-27191, GO-2026-5018 | `ParseSSHPublicKey`, `InsecureSSHConfig` |
| `golang.org/x/net` | v0.0.0-20220722155237-a158d28d115b | CVE-2022-41717, CVE-2022-41723, CVE-2023-3978, CVE-2023-39325, GO-2024-3333, GO-2025-3595, GO-2026-4440/4441/5025–5030 | `ParseHTMLFragment` |
| `golang.org/x/text` | v0.3.7 | CVE-2022-32149 / GO-2022-1059 | `ParseAcceptLanguage` |
| `gopkg.in/yaml.v3` | v3.0.0 | CVE-2022-28948 | `ParseYAML` |
| `golang.org/x/sys` (indirect) | v0.5.0 | GO-2026-5024 (low) | — |
| `gopkg.in/yaml.v2` (indirect via gin) | v2.2.8 | none known (CVE-2022-3064 fixed in v2.2.4) | — |

`govulncheck` reachable set (12): GO-2026-6278, GO-2026-5030, GO-2026-5029, GO-2026-5028, GO-2026-5027, GO-2026-5025, GO-2026-5018, GO-2026-4441, GO-2026-4440, GO-2025-3595, GO-2024-3333, GO-2022-1059.

OSV advisory counts per module (queried 2026-09-11, deduplicated across GO/GHSA/CVE aliases): jwt-go 1, gin 3, websocket 2, x/crypto 27, x/net 21, x/text 2, yaml.v3 1, x/sys 1; all other indirect modules 0.

A manifest-only SCA scanner should report **at least** the 7 direct modules above and mark them **Direct**; the 13 `// indirect` entries are **Transitive**. A reachability-aware scanner should distinguish the reachable 12 from the rest.

## Secrets — expected findings (`src/secrets.go` and elsewhere)

All values are synthetic (the AWS values are the vendor's own public documentation examples).

> **GitHub push protection note.** Two fixtures originally used real vendor token
> shapes: the Slack bot-token format, and Stripe's own published test key.
> GitHub push protection rejects any push containing either literal — so those
> shapes are not reproduced anywhere in this repository, not even in comments or
> in this note. Both constants are replaced with
> `FIXTURE-…-shape-omitted-for-push-protection` placeholders.
> Those two constants therefore exercise **keyword/identifier** detection only,
> not vendor-pattern detection. To test vendor-pattern rules, restore the
> literals locally and either keep the branch unpushed or allowlist them via the
> URLs GitHub prints when it blocks the push.

| Constant | Detector type |
|---|---|
| `AWSAccessKeyID` | AWS access key ID (`AKIA…`) |
| `AWSSecretAccessKey` | AWS secret key |
| `GitHubToken` | GitHub PAT (`ghp_…`) |
| `SlackBotToken` | keyword only — vendor shape removed (see note) |
| `StripeSecretKey` | keyword only — vendor shape removed (see note) |
| `GoogleAPIKey` | Google API key (`AIza…`) |
| `SendGridAPIKey` | SendGrid (`SG.….…`) |
| `TwilioAccountSID`, `TwilioAuthToken` | Twilio |
| `JWTSigningSecret`, `AdminPassword`, `EncryptionKeyHex` | generic high-entropy / keyword |
| `DatabaseURL`, `RedisURL`, `MongoURL`, `SMTPURL` | credentials in connection URL |
| `PrivateKeyPEM` | PEM private key block |
| `dbPassword` (`unsafe_misc.go`) | keyword `password` |
| `hardcodedAESKey` (`crypto.go`) | keyword `key` |
| `CallWithBasicAuth` header (`web.go`) | Basic auth header |
| `Login` (`app.go`) | keyword `password` |
| `SecretFromEnv` | **SAFE** — reads `os.Getenv`, must not flag |
| `terraform/secrets.tf` | see IaC |

## IaC — see `terraform/`, `kubernetes/`, `Dockerfile`

Unchanged in this revision.
