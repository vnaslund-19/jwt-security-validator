# jwtcheck

A config-driven command line tool that detects and explains a fixed set of JWT
implementation weaknesses in web apps and APIs. You point it at your own app with
a small config file. Nothing about the app is hardcoded, so no code changes are
needed to test a new one.

## Install

From the project root:

```sh
pip install .
```

Requires Python 3.10+. This installs the `jwtcheck` command and its runtime
dependencies (PyJWT, jsonschema, requests).

If you are working on the tool itself, running the demo apps, or running the
tests, see [DEV.md](DEV.md) for the development setup.

## Configure jwtcheck for your app

A config is a JSON file that describes your app so the tool can log in, send a
token, and reach a normal and an admin endpoint. Here is a config for an app
that returns the token in the login JSON and expects it back in an
`Authorization: Bearer` header:

```json
{
  "name": "my-app",
  "base_url": "http://127.0.0.1:8000",
  "login": {
    "path": "/login",
    "credentials": { "username": "alice", "password": "s3cret" },
    "token_from": { "source": "json", "field": "token" }
  },
  "send_token": { "via": "header", "name": "Authorization", "prefix": "Bearer " },
  "endpoints": { "user": "/me", "admin": "/admin" },
  "claims": { "subject": "sub", "role": "role", "admin_value": "admin" }
}
```

If your app carries the token in a cookie instead of a header, change the two
transport fields:

```json
  "login": { "path": "/login", "credentials": { "...": "..." },
             "token_from": { "source": "cookie", "name": "session" } },
  "send_token": { "via": "cookie", "name": "session" }
```

### Testing for a weak signing secret (SEC-01)

SEC-01 recovers the HMAC signing secret by brute force. If it succeeds, the
secret is guessable and anyone can forge valid tokens, so the finding is
`VULNERABLE` with the forged request as proof.

The built-in list is only a dozen of the most common secrets, enough to flag an
obviously weak one. For a realistic test, point `wordlist` at a full list. The
usual choice is `rockyou.txt`:

```sh
curl -L -o rockyou.txt \
  https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
```

Then set the path in your config:

```json
"wordlist": "rockyou.txt"
```

rockyou has about 14 million entries, so a secret near the bottom is a full scan
of roughly a minute and a half. It is ordered most-common-first, so for a run
that finishes in under a second and still catches weak secrets, use just the top
of it:

```sh
head -n 100000 rockyou.txt > rockyou-top100k.txt
```

Fields:

- `name` identifies the target and names its report files.
- `base_url` is where the app runs.
- `login.token_from` says where the login response carries the token: a JSON
  `field`, or a `cookie` by `name`.
- `send_token` says how to send it back: a header `name` with an optional
  `prefix`, or a cookie by `name`.
- `endpoints.user` is any authenticated endpoint; `endpoints.admin` is
  admin-only.
- `claims` names the subject and role claims and the value that means admin.
- `wordlist` (optional) is a path for the SEC-01 brute force; a small built-in
  list is the default.
- `public_key` (optional) is a path to the RSA public key, used by SIG-03.

The full contract is [jwtcheck/config-schema.json](jwtcheck/config-schema.json).
Add a `"$schema"` key pointing at it to get editor validation while you write
the config.

## Run

```sh
jwtcheck --config config.json
```

The summary prints a verdict for each check to stdout. Verdicts are colored on a
terminal and plain when the output is redirected or `NO_COLOR` is set.

Flags:

- `--report-dir DIR` writes a JSON and a Markdown report for the run into `DIR`,
  each finding carrying the request/response that proves it.
- `--log-level {debug,info,warning,error}` controls logging (default `warning`,
  so it stays quiet). `info` shows the signing path the tool found; `debug`
  shows every request.
- `--log-file PATH` sends logs to a file instead of stderr.

A saved report contains live credentials: it records the tokens the checks send,
and the signing secret if SEC-01 cracks one. Anyone who has the file could use
them to log in to the app you tested, so keep the reports private and out of
version control.

## What it checks

| ID     | Group          | Detects                                             |
|--------|----------------|-----------------------------------------------------|
| SIG-01 | Signature      | `alg:none` / unsigned token accepted                |
| SIG-02 | Signature      | Tampered payload accepted (signature not verified)  |
| SIG-03 | Signature      | Algorithm confusion RS256 to HS256 (RSA targets)    |
| SEC-01 | Weak secret    | HMAC secret brute-forced from a wordlist            |
| CLM-01 | Claims         | Expired token (`exp`) accepted                      |
| CLM-02 | Claims         | `nbf` (not-before) not enforced                     |
| CLM-03 | Claims         | `iss` (issuer) not validated                        |
| CLM-04 | Claims         | `aud` (audience) not validated                      |
| ACL-01 | Access control | Role escalation via `role`-claim tampering          |
| ACL-02 | Access control | Identity swap via `sub`-claim tampering             |

Each check returns one of four verdicts: `VULNERABLE` (weakness exploited, with
the HTTP request/response that proves it), `SAFE` (attack ran and was rejected),
`SKIPPED` (not applicable to this config), or `ERROR` (check could not complete).

## Development

The repo also contains demo target apps, an evaluation harness that scores the
tool against an expected-results manifest, and the test suite. Those are for
developing and proving the tool, not for using it. See [DEV.md](DEV.md).
