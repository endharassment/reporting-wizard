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
  store methods and render templates.
- **admin/** contains admin-specific handlers. It receives dependencies via
  constructor injection (store, templates, etc.).
- **infra/** handles infrastructure discovery (DNS, ASN, RDAP, BGP). It makes
  external network calls and should always use context timeouts.
- **report/** handles X-ARF generation and email composition/sending.
- **escalation/** is a background worker. It runs in its own goroutine.
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

## Testing

- Run `go test ./...` to execute all tests.
- Test files live alongside the code they test (e.g., `gdrive_test.go`).
- Mock the `Store` interface for handler/engine tests (see
  `escalation/escalation_test.go` for an example mock store).
- External network calls (DNS, RDAP, etc.) should be mockable via interfaces.

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
