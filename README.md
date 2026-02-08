# End Network Harassment Inc Reporting Wizard

A Go web application that automates filing abuse reports with hosting providers
on behalf of individuals targeted by online harassment, hate speech, doxxing,
non-consensual intimate imagery (NCII), and copyright/likeness violations.

Reports are generated in [X-ARF v4](https://x-arf.org/) format and sent via
email to the abuse contacts discovered through DNS, ASN, RDAP, and BGP lookups.

**This tool files Terms of Service abuse reports. It does not file DMCA takedown
notices or law enforcement reports.** See the in-app disclaimers for details.

## License

Apache 2.0. See [LICENSE](LICENSE).

## Architecture

```
cmd/wizard/main.go          Entry point, config, server startup
internal/
  server/                   HTTP handlers, middleware, routing (chi)
    blocklist.go            Top-site domain blocklist (embedded txt)
    recaptcha.go            reCAPTCHA v3 server-side verification
  store/                    SQLite persistence (modernc.org/sqlite)
    migrations/             Embedded SQL migrations
  model/                    Domain types (User, Report, Evidence, etc.)
  infra/                    Infrastructure discovery (DNS, ASN, RDAP, BGP)
    cache.go                Generic TTL cache for external lookups
  report/                   X-ARF generation, email composition, SendGrid
  escalation/               Background engine for report escalation
  email/                    IMAP reply fetcher for provider responses
  boilerplate/              Known-domain context DB for abuse reports
  snapshot/                 URL text snapshotting (plain HTTP / Tor)
  gdrive/                   Google Drive URL parsing and metadata verification
  admin/                    Admin handlers (dashboard, approval queue)
templates/                  html/template files (embedded)
static/                     CSS, htmx (embedded)
.circleci/config.yml        CI: build + test on Go 1.25
```

The application uses server-side rendering with `html/template` and
[htmx](https://htmx.org/) for progressive enhancement. Templates and static
assets are embedded into the binary via `//go:embed`.

## Prerequisites

- Go 1.25+ (uses `modernc.org/sqlite`, no CGO required)
- A Google OAuth 2.0 client ID (for authentication and optional Drive verification)
- A SendGrid API key (for sending abuse report emails)
- Optionally: a GitHub OAuth app for GitHub login

## Configuration

All configuration is via environment variables (with flag overrides for some):

| Variable | Required | Default | Description |
|---|---|---|---|
| `WIZARD_LISTEN` | No | `:8080` | HTTP listen address |
| `WIZARD_DB_PATH` | No | `./wizard.db` | SQLite database file path |
| `WIZARD_BASE_URL` | Yes | `http://localhost:8080` | Public base URL (used for OAuth callbacks) |
| `WIZARD_SESSION_SECRET` | **Yes** | -- | Secret key for CSRF tokens (min 32 chars, must be set in production) |
| `WIZARD_GOOGLE_CLIENT_ID` | Yes | -- | Google OAuth client ID |
| `WIZARD_GOOGLE_SECRET` | Yes | -- | Google OAuth client secret |
| `WIZARD_GITHUB_CLIENT_ID` | No | -- | GitHub OAuth client ID |
| `WIZARD_GITHUB_SECRET` | No | -- | GitHub OAuth client secret |
| `WIZARD_SENDGRID_KEY` | Yes | -- | SendGrid API key for outgoing emails |
| `WIZARD_FROM_EMAIL` | No | `reports@endharassment.net` | Sender email address |
| `WIZARD_FROM_NAME` | No | `End Network Harassment Inc` | Sender display name |
| `WIZARD_RECAPTCHA_SITE_KEY` | No | -- | reCAPTCHA v3 site key (skipped if unset) |
| `WIZARD_RECAPTCHA_SECRET_KEY` | No | -- | reCAPTCHA v3 secret key (skipped if unset) |
| `WIZARD_IMAP_SERVER` | No | -- | IMAP server for fetching provider replies |
| `WIZARD_IMAP_USERNAME` | No | -- | IMAP username |
| `WIZARD_IMAP_PASSWORD` | No | -- | IMAP password |

### Google OAuth Setup

1. Create a project in the [Google Cloud Console](https://console.cloud.google.com/).
2. Enable the **Google Drive API**.
3. Configure the OAuth consent screen. Add the scopes: `openid`, `email`,
   `profile`, `https://www.googleapis.com/auth/drive.metadata.readonly`.
4. Create an OAuth 2.0 Client ID (Web application type).
5. Add `{WIZARD_BASE_URL}/auth/google/callback` as an authorized redirect URI.
6. Set `WIZARD_GOOGLE_CLIENT_ID` and `WIZARD_GOOGLE_SECRET`.

The `drive.metadata.readonly` scope allows the app to verify that Google Drive
evidence links are accessible and to pull file metadata (name, type, size). It
does **not** allow reading file contents.

## Building and Running

```bash
go build -o wizard ./cmd/wizard
export WIZARD_SESSION_SECRET="$(openssl rand -hex 32)"
export WIZARD_GOOGLE_CLIENT_ID="..."
export WIZARD_GOOGLE_SECRET="..."
export WIZARD_SENDGRID_KEY="..."
export WIZARD_BASE_URL="https://your-domain.example.com"
./wizard
```

The SQLite database and migrations are created automatically on first run.

## Supported Violation Types

- Harassment
- Hate speech
- Non-consensual intimate imagery (NCII)
- Doxxing
- Copyright/likeness violations (ToS-based, not DMCA)
- Self-harm facilitation
- Defamation
- Threats of violence

## Development

```bash
go build ./...       # compile
go vet ./...         # static analysis
go test ./...        # run tests
```

CI runs on CircleCI (Go 1.25, `go install` + `go test`).

## Report Workflow

1. **Reporter enters URLs** of abusive content (all must be on the same domain).
   URLs targeting top-50 websites (SimilarWeb) are blocked with a message
   directing the reporter to that site's own abuse process. reCAPTCHA v3
   provides invisible bot detection (zero user friction).
2. **Infrastructure discovery** runs automatically: DNS resolution, IP-to-ASN
   mapping (Team Cymru), RDAP abuse contact lookup, BGP upstream discovery,
   Cloudflare detection. Results are cached (1-hour TTL) to avoid amplifying
   lookups against external services.
3. **Reporter provides evidence** by pasting links to files in their own cloud
   storage (Google Drive recommended for automatic metadata verification).
   Describes the violation and selects a category.
4. **Reporter reviews** the generated report, including an email preview and
   X-ARF attachment. URL text snapshots are captured automatically.
5. **Admin reviews and approves** the report. Approved reports are sent to the
   hosting provider's abuse contact via SendGrid.
6. **Escalation engine** monitors sent reports. If no response is received
   within the configured period (default 14 days), reports are automatically
   escalated to upstream providers via recursive upstream chain walking.
7. **Email reply fetcher** polls an IMAP mailbox for provider responses and
   associates them with the corresponding outgoing report emails.

## Evidence Handling

Users upload evidence to their own cloud storage accounts (Google Drive,
Dropbox, iCloud, etc.) and provide share links. The application does **not**
store evidence files.

For Google Drive links, the application:
- Extracts the file ID from the URL
- Verifies the file exists via the Drive API (using the reporter's OAuth token)
- Pulls metadata: file name, MIME type, size, creation date
- Displays a "Verified" badge in the UI

For non-Drive links, URLs are stored as-is and displayed without verification.

## Important Disclaimers

The application prominently warns users that:

- **Hosting providers will forward abuse reports to the site operator.** There
  is no expectation of privacy for abuse reports.
- **Site operators may retaliate** by publicly posting complaints and
  encouraging further harassment.
- **NCII reports** must be filed by the person depicted or their authorized
  representative.
- **DMCA takedown notices** are a separate legal process that this tool does
  not perform. Copyright reports are ToS-based only.
- **CSAM** must be reported to [NCMEC CyberTipline](https://report.cybertip.org/)
  and [IC3](https://www.ic3.gov/), not through this tool.

## Security

See [SECURITY_REVIEW.md](SECURITY_REVIEW.md) for a detailed security audit.

Key security features:
- CSRF protection (HMAC double-submit cookie)
- Per-IP and per-user rate limiting (token bucket)
- reCAPTCHA v3 bot detection on report creation (optional, graceful skip in dev)
- Top-site domain blocklist prevents misuse against major websites
- Security headers (CSP, X-Frame-Options, etc.)
- Parameterized SQL queries (no string concatenation)
- `html/template` auto-escaping (XSS prevention)
- `crypto/rand` for all token generation
- Admin approval required before any email is sent
- Audit logging for all admin actions
- User banning support

## Pre-Launch Checklist

Before deploying to production:

- [ ] Set a strong `WIZARD_SESSION_SECRET` (the app will refuse to start with the default)
- [ ] Configure SPF/DKIM/DMARC for your sending domain
- [ ] Use a dedicated SendGrid IP and warm it gradually
- [ ] Retain legal counsel re: CSAM reporting obligations (18 USC 2258A) and GDPR
- [ ] Create a Terms of Service with reporter attestation language
- [ ] Create a Privacy Policy with data retention schedule
- [ ] Set `WIZARD_BASE_URL` to your HTTPS domain (enables Secure cookie flag)
- [ ] Review and customize the `ReporterOrg` fields in the email config
- [ ] Set up monitoring/alerting for the application
