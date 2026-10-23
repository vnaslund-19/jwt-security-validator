# jwtcheck

A config-driven command line tool that detects and explains a fixed set of JWT
implementation weaknesses in web apps and APIs. You point it at a target app with
a small config file. The tool hardcodes nothing about the target app, so no code
changes are needed to test a new one.

## Install

From the project root:

```sh
pip install .
```

Requires Python 3.10+. This installs the `jwtcheck` command and its runtime
dependencies (PyJWT, jsonschema, requests).

If you are working on the tool itself, running the demo apps, or running the
tests, see [DEV.md](DEV.md) for development setup.

## Configure jwtcheck for a target app

A config is a JSON file that describes the target app so the tool can log in, send a
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

If the app uses a cookie instead, set `token_from` to that cookie and leave out
`send_token`. The token is sent back in the same cookie:

```json
  "login": { "path": "/login", "credentials": { "...": "..." },
             "token_from": { "source": "cookie", "name": "session" } }
```

Fields:

- `name` (optional) names the target and its report files. Defaults to the
  config's filename.
- `base_url` is where the app runs.
- `login.token_from` says where the login response carries the token: a JSON
  `field`, or a `cookie` by `name`.
- `send_token` says how to send the token back: a header `name` with an optional
  `prefix`, or a cookie by `name`. For a cookie you can omit it, and the token is
  sent back in the cookie it came from.
- `endpoints.user` is any authenticated endpoint; `endpoints.admin` is
  admin-only.
- `claims` names the subject and role claims and the value that means admin.
- `login.impersonate` (optional) is a second real account on the target. The
  identity-swap check (ACL-02) logs in as it, then forges a token claiming to be
  that user. Without it the check uses an invented username, which would be
  rejected by an app that checks whether the user exists.
- `public_key` (optional) is a path to the RSA public key, used by SIG-03.
- `signing_key` (optional) is a path to a file holding the app's signing secret,
  or its private key. With it, the claim and role checks run white-box: the tool
  signs its own token carrying a bad claim and sees whether the app accepts it,
  so it can test claims an outsider could never forge a token for (a wrong `iss`
  or `aud`, an ignored `exp`). Findings that relied on it are marked white-box in
  their explanation.

The full contract is [jwtcheck/config-schema.json](jwtcheck/config-schema.json).
Add a `"$schema"` key pointing at it to get editor validation while you write
the config.

### Testing for a weak signing secret (SEC-01)

SEC-01 recovers the HMAC signing secret by brute force. If it succeeds, the
secret is guessable and anyone can forge valid tokens, so the finding is
`VULNERABLE` with the forged request as proof.

The built-in list is only a dozen of the most common secrets. For a realistic
test, pass a full list with `--wordlist`. The usual choice is `rockyou.txt`:

```sh
curl -L -o rockyou.txt \
  https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
jwtcheck config.json --wordlist rockyou.txt
```

rockyou has about 14 million entries, so a secret near the bottom is a full scan
of roughly a minute and a half. It is ordered most common first, so for a run
that finishes in under a second and still catches weak secrets, use just the top
of it:

```sh
head -n 100000 rockyou.txt > rockyou-top100k.txt
```

## Run

```sh
jwtcheck config.json
```

The summary prints a verdict for each check to stdout. Verdicts are colored on a
terminal and plain when the output is redirected or `NO_COLOR` is set.

Flags:

- `--report-dir DIR` writes a JSON and a Markdown report for the run into `DIR`,
  each finding carrying the request/response that proves it.
- `--wordlist PATH` uses this wordlist for the SEC-01 brute force instead of the
  small built-in list.
- `--no-redact` writes the tokens and any cracked secret into the report in full
  (redacted by default). The report could then contain live credentials,
  so keep it private.
- `--log-level {debug,info,warning,error}` controls logging (default `warning`,
  so it stays quiet). `info` shows the signing path the tool found; `debug`
  shows every request.
- `--log-file PATH` sends logs to a file instead of stderr.

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

The repo also contains demo apps and tests. These are used to make sure the
tool works as expected. They are mainly for developers working on the tool, but
can also help users see what the vulnerabilities look like and how to fix them.
See [DEV.md](DEV.md).

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
