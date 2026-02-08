# AGENTS.md -- AI Coding Agent Guidelines

## Project Overview

This is a Go web application that automates filing abuse reports with hosting
providers. It uses chi for routing, html/template for SSR, SQLite via
modernc.org/sqlite (no CGO), and htmx for progressive enhancement. Templates
and static files are embedded into the binary.

## Code Style

- Standard `gofmt` formatting. Run `go vet ./...` before committing.
- Error handling: always check errors. Use `log.Printf("ERROR: ...")` for
  operational errors. Return errors to callers with `fmt.Errorf("context: %w", err)`.
- SQL: always use parameterized queries (`?` placeholders). Never concatenate
  user input into SQL strings.
- Templates: use `html/template` (not `text/template`). All user-facing data
  is auto-escaped.
- Imports: stdlib first, then third-party, then internal packages (goimports
  ordering).

## Architecture Rules

- **internal/** packages are not importable outside this module. All application
  logic lives here.
- **model/** contains only data types and constants. No business logic, no
  imports beyond stdlib.
- **store/** defines the `Store` interface and the SQLite implementation. All
  database access goes through this interface.
- **server/** contains HTTP handlers, middleware, and routing. Handlers call
  store methods and render templates. Also contains:
  - `blocklist.go` — top-site domain blocklist (`//go:embed blocked_domains.txt`).
    `isDomainBlocked(domain)` checks exact + subdomain match. Edit
    `blocked_domains.txt` to update the list (one domain per line, `#` comments).
  - `recaptcha.go` — reCAPTCHA v3 server-side verification. Returns score 1.0
    (pass) when secret key is empty (dev mode). Threshold is 0.5.
- **admin/** contains admin-specific handlers. It receives dependencies via
  constructor injection (store, templates, etc.).
- **infra/** handles infrastructure discovery (DNS, ASN, RDAP, BGP). It makes
  external network calls and should always use context timeouts. Results are
  cached via a generic TTL cache (`cache.go`, 1-hour default) to avoid
  amplifying lookups against external services.
- **report/** handles X-ARF generation and email composition/sending.
- **escalation/** is a background worker. It runs in its own goroutine. Supports
  recursive upstream chain walking for multi-level escalation.
- **email/** fetches provider replies via IMAP and associates them with outgoing
  report emails. Runs on a 5-minute polling ticker.
- **boilerplate/** contains a known-domain context database. Provides background
  information for abuse reports targeting well-known problem domains.
- **snapshot/** handles URL text extraction.
- **gdrive/** handles Google Drive URL parsing and metadata verification.

## Database

- SQLite with WAL mode and `busy_timeout(5000)`.
- Migrations are embedded SQL files in `internal/store/migrations/`. They run
  automatically on startup in filename order.
- New migrations: create `NNN_description.sql` with the next sequence number.
  Use `ALTER TABLE ... ADD COLUMN` for additive changes. SQLite does not support
  `DROP COLUMN` or `ALTER COLUMN`.
- All times stored as `TEXT` in `datetime('now')` / RFC3339-like format using
  the `timeFormat` constant in `sqlite.go`.
- Boolean fields stored as `INTEGER` (0/1).

## CI

CircleCI runs `go install ./...` and `go test ./...` on Go 1.25
(`.circleci/config.yml`).

## Testing

- Run `go test ./...` to execute all tests.
- Test files live alongside the code they test (e.g., `gdrive_test.go`).
- Mock the `Store` interface for handler/engine tests (see
  `escalation/escalation_test.go` for an example mock store).
- External network calls (DNS, RDAP, etc.) should be mockable via interfaces.
- `recaptcha_test.go` uses `setRecaptchaVerifyURL()` to point at an
  `httptest.Server` mock. The timeout test case takes ~10s due to httptest
  close behavior — this is expected.
- `blocklist_test.go` tests exact match, subdomain match, case insensitivity,
  and edge cases via table-driven tests.

## Anti-Abuse Measures

- **reCAPTCHA v3**: Step 1 (URL entry) runs invisible reCAPTCHA. Configured via
  `WIZARD_RECAPTCHA_SITE_KEY` / `WIZARD_RECAPTCHA_SECRET_KEY` env vars. When
  keys are unset, verification is skipped (score returns 1.0). Scores below 0.5
  are rejected. CSP headers allow `google.com/recaptcha/` and
  `gstatic.com/recaptcha/` origins.
- **Top-site blocklist**: `internal/server/blocked_domains.txt` (embedded) blocks
  reports against the SimilarWeb top 50 sites. Subdomain matching is automatic
  (e.g. `docs.google.com` is blocked because `google.com` is in the list). To
  update the list, edit the txt file — it's parsed at init time.
- **User banning**: Admins can ban users via the admin dashboard.

## Security Considerations

- All POST endpoints are CSRF-protected. Templates must include
  `<input type="hidden" name="csrf_token" value="{{ .CSRFToken }}">`.
- Rate limiting is applied globally. Report-specific rate limits exist per-user.
- Never serve user-controlled content inline. Use `Content-Disposition: attachment`.
- Never trust `Content-Type` headers alone; validate magic bytes for file uploads.
- The session secret (`WIZARD_SESSION_SECRET`) must be cryptographically random
  and at least 32 characters in production.
- Google OAuth tokens are stored on the user record for Drive API access. These
  are sensitive and should be treated as credentials.

## Evidence Model

Evidence is URL-based. Users provide links to files in their own cloud storage.
The application does NOT store evidence files locally. The `evidence/` directory
is vestigial and will be removed.

For Google Drive URLs, the app extracts file IDs, calls the Drive API for
metadata verification, and stores results on the Evidence record (`DriveFileID`,
`DriveFileName`, `DriveMimeType`, `DriveSize`, `DriveVerified`).

## Legal/Duty-of-Care

This application has important legal and ethical constraints:

- **Retaliation warnings**: Users must be warned that hosting providers will
  forward reports to site operators, who may retaliate.
- **NCII identity**: NCII reports must come from the affected person or their
  authorized representative.
- **Not DMCA**: Copyright reports are ToS-based, not DMCA takedown notices.
- **CSAM**: Must direct users to NCMEC CyberTipline and IC3. The application
  must not be used to handle CSAM.
- **Report content**: Outgoing emails are sent under the organization's identity.
  The individual reporter's email is never included in outgoing reports.

## Environment Variables

All configuration is via env vars. Key additions beyond the basics:

| Variable | Description |
|---|---|
| `WIZARD_RECAPTCHA_SITE_KEY` | reCAPTCHA v3 site key (optional, skipped if unset) |
| `WIZARD_RECAPTCHA_SECRET_KEY` | reCAPTCHA v3 secret key (optional, skipped if unset) |
| `WIZARD_IMAP_SERVER` | IMAP server for fetching provider replies |
| `WIZARD_IMAP_USERNAME` | IMAP username |
| `WIZARD_IMAP_PASSWORD` | IMAP password |

See `README.md` for the full configuration table.

## Common Tasks

### Adding a new violation type
1. Add the constant to `model/models.go`
2. Add the mapping in `report/xarf.go` (`violationMapping`)
3. Add the label in `report/email.go` (`violationLabel`)
4. Add the `<option>` in `templates/wizard/step3_evidence.html`
5. Add any type-specific disclaimer (see NCII/copyvio patterns in step3)

### Adding a new migration
1. Create `internal/store/migrations/NNN_description.sql`
2. Update model structs in `model/models.go`
3. Update SQL queries in `store/sqlite.go`
4. Update the `Store` interface in `store/store.go`
5. Update mock stores in test files (e.g., `escalation_test.go`)

### Adding a new template
1. Create the `.html` file in `templates/`
2. Use `{{ template "layout" . }}` and `{{ define "content" }}...{{ end }}`
3. Pass data via `s.render(w, r, "name.html", map[string]interface{}{...})`
4. `RecaptchaSiteKey` and `CSRFToken` are automatically available in all templates

### Updating the blocked domains list
1. Edit `internal/server/blocked_domains.txt` (one domain per line, `#` comments)
2. Subdomain matching is automatic — adding `example.com` blocks `*.example.com`
3. Run `go test ./internal/server/... -run TestIsDomainBlocked` to verify

### Adding a known problem domain (boilerplate)
1. Add a `DomainInfo` entry in `internal/boilerplate/boilerplate.go`
2. Include `Domain`, `DisplayName`, `Summary`, and `Context` at minimum
3. Run `go test ./internal/boilerplate/...` to verify
