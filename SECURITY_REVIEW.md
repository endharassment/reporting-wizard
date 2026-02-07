# Security Review: Reporting Wizard

**Date**: 2026-02-07
**Reviewer**: Security review agent
**Scope**: Full codebase review of the endharassment.net Reporting Wizard

---

## 1. Weaponization of the Reporting System

### 1.1 False Reports Against Legitimate Sites
**Severity**: HIGH

**Risk**: An adversary (including operators of sites like Kiwi Farms) could create accounts and file fabricated abuse reports against legitimate sites, their critics' hosting providers, or competing organizations. Because the tool automates infrastructure discovery and generates professional-looking X-ARF reports, false reports would carry more weight than manual ones.

**Current mitigations**:
- Human-in-the-loop: All outgoing emails require admin approval before sending (good).
- Audit log tracks admin actions.

**Additional mitigations needed**:
- **Reporter attestation**: Require reporters to attest under penalty of perjury (or equivalent ToS language) that their reports are truthful. Store the attestation timestamp and IP.
- **Account verification**: Require email verification at signup. Consider requiring a verified identity (phone number, OAuth with established account) before reports can be submitted.
- **Report deduplication**: Detect and flag duplicate reports targeting the same domain/IP from different accounts. This pattern suggests coordinated abuse.
- **Reporter trust scoring**: New accounts should have reports scrutinized more heavily. Track report outcomes (accepted, rejected, effective) to build a trust score over time.
- **Rate limits per user**: Limit reports per user per day/hour (implemented in `ratelimit.go`).
- **Domain allowlist/blocklist**: Admins should be able to flag domains that should never be reported (e.g., the org's own infrastructure) and domains that are known-bad.

### 1.2 Harassment of Hosting Providers via Report Floods
**Severity**: MEDIUM

**Risk**: Mass account creation followed by mass report submission could flood hosting providers' abuse desks, harming the org's reputation and the providers' willingness to process legitimate reports.

**Current mitigations**:
- Admin approval queue prevents automated sending.

**Additional mitigations needed**:
- **Per-provider daily sending cap**: Limit outgoing emails to any single abuse contact to prevent flooding a single provider.
- **Aggregate volume monitoring**: Alert admins when total pending reports exceed a threshold.
- **CAPTCHA or proof-of-work**: On account creation and report submission to prevent bot-driven mass creation.

---

## 2. Denial of Service Vectors

### 2.1 Mass Account Creation
**Severity**: HIGH

**Risk**: Automated account creation via magic link requests could exhaust SendGrid quota (magic link emails) and fill the database with garbage accounts.

**Mitigations needed**:
- **Per-IP rate limiting** on the magic link request endpoint (implemented in `ratelimit.go`).
- **CAPTCHA** on login/signup forms.
- **Magic link rate limit**: Max 3 magic links per email address per hour.

### 2.2 Large File Uploads Exhausting Disk
**Severity**: HIGH

**Risk**: Current code limits individual files to 20MB but does not enforce a per-report or per-user total. An attacker could upload many 20MB files to fill disk.

**Current mitigations**:
- 20MB per-file limit in `evidence.go` (good).
- Allowed content type checking (good).

**Additional mitigations needed**:
- **Per-report total evidence cap**: 100MB total per report (implemented in `safety.go`).
- **Per-user daily upload cap**: 500MB/day.
- **Disk usage monitoring**: Alert when evidence directory exceeds a threshold.
- **Evidence directory size cap**: Reject uploads when total evidence storage exceeds configured maximum.

### 2.3 DNS/RDAP/BGP Lookup Amplification
**Severity**: MEDIUM

**Risk**: Each report submission triggers multiple external network requests (DNS, ASN via Team Cymru, RDAP, BGP whois). An attacker submitting many reports could use this for amplification against external services.

**Current mitigations**:
- `MaxConcurrency = 8` limits parallel lookups per discovery run (good).

**Additional mitigations needed**:
- **Infra discovery result caching**: Cache DNS, ASN, RDAP, and BGP results by domain/IP with a TTL (e.g., 1 hour). Most reports target the same small set of domains.
- **Per-user discovery rate limit**: Max 5 infra discoveries per user per hour.
- **Context timeouts**: All external lookups should have explicit timeouts (10s for DNS, 15s for RDAP, 10s for BGP whois). The BGP client currently has no deadline on the TCP connection beyond the parent context.

### 2.4 SQLite Write Contention
**Severity**: LOW

**Risk**: SQLite with WAL mode handles concurrent reads well but serializes writes. Under heavy load, write operations could queue up.

**Current mitigations**:
- WAL mode enabled via pragma (good).

**Additional mitigations needed**:
- **Connection pool sizing**: Set `SetMaxOpenConns(1)` for writes (SQLite best practice) with a separate read-only connection pool if needed.
- **Busy timeout pragma**: Add `_pragma=busy_timeout(5000)` to the SQLite connection string to wait up to 5s for locks instead of failing immediately.

---

## 3. Dangerous Content Exposure

### 3.1 CSAM in Evidence Uploads
**Severity**: CRITICAL

**Risk**: Reporters documenting NCII may upload content that constitutes CSAM (child sexual abuse material). Once uploaded, the org becomes aware of it and is legally obligated to report.

**Legal requirement**: Under 18 USC 2258A, electronic service providers who become aware of apparent CSAM **must** report to NCMEC within a defined timeframe. Failure to report is a federal offense.

**Mitigations needed**:
- **NCMEC reporting workflow**: Design and implement a workflow for CSAM discovery:
  1. Do NOT delete the content.
  2. Preserve all metadata (uploader IP, account, timestamps).
  3. File a report with NCMEC's CyberTipline.
  4. Lock the reporter's account pending investigation.
  5. Document the incident in the audit log.
- **PhotoDNA/hash matching interface**: Implement a hook for hash-based CSAM detection (placeholder in `safety.go`). Even before integrating a hash service, the interface should exist so it can be wired up.
- **Content warnings**: Admin review UI must show content behind explicit click-to-reveal with warnings.
- **Metadata-only review mode**: Admins should be able to review file metadata (filename, hash, size, content type) without viewing content (implemented in `safety.go`).
- **Legal counsel**: Consult a lawyer about whether endharassment.net qualifies as an "electronic service provider" under 18 USC 2258A.

### 3.2 Admin Exposure to Disturbing Content
**Severity**: HIGH

**Risk**: Admins reviewing evidence will be exposed to harassment, hate speech, gore, NCII, and other traumatic content.

**Mitigations needed**:
- **Content warnings with click-to-reveal** in the admin UI.
- **Admin rotation policy**: No single admin should review all reports. Implement assignment/rotation.
- **Exposure tracking**: Track how many graphic reports each admin has reviewed. Flag when thresholds are exceeded.
- **Wellness resources**: Link to mental health resources in admin UI. Consider providing access to counseling.
- **Auto-blur/low-resolution preview**: Show thumbnails at very low resolution by default.

### 3.3 Content Type Validation
**Severity**: MEDIUM

**Finding**: The current `evidence.go` allows `video/mp4` and `image/tiff` uploads, and also accepts **any** `image/*` subtype via the `strings.HasPrefix(ct, "image/")` wildcard. This means:
- `image/svg+xml` is accepted, which can contain JavaScript (XSS vector if served inline).
- `video/mp4` allows large video files that are harder to review and moderate.

**Mitigations**:
- **Remove the `image/*` wildcard**: Only accept explicitly listed image types (implemented in `safety.go`).
- **Remove `image/tiff` and `image/bmp`**: These are rarely needed and can contain embedded content.
- **Remove `video/mp4`** or cap video duration/size strictly.
- **Validate file magic bytes**: Don't trust `Content-Type` header alone; check actual file magic bytes (implemented in `safety.go`).

---

## 4. Legal Risk

### 4.1 18 USC 2258A (CSAM Reporting)
**Severity**: CRITICAL

**Question**: Does operating this reporting tool make endharassment.net an "electronic service provider" under the statute?

**Analysis**: If the org stores user-uploaded content (which it does, in the evidence directory), it likely qualifies. The safe course is to assume the obligation applies and implement NCMEC reporting.

**Recommendation**: Retain legal counsel experienced in internet law and CSAM reporting obligations before launching.

### 4.2 GDPR Compliance
**Severity**: HIGH

**Risk**: EU reporters using the system triggers GDPR obligations.

**Data collected**: Email addresses, IP addresses (in reports and evidence), session data, uploaded files potentially containing PII of third parties.

**Mitigations needed**:
- **Privacy policy**: Document what data is collected, why, retention periods, and legal basis.
- **Lawful basis**: Legitimate interest (abuse reporting) is likely the appropriate basis, but document the balancing test.
- **Right to deletion**: Implement a process for users to request deletion of their data. Note tension with evidence retention.
- **Data retention policy**: Define how long evidence, reports, and user data are kept.
- **Data minimization**: Only collect what's needed. Consider whether IP logging is necessary for reporters.

### 4.3 Defamation Risk
**Severity**: MEDIUM

**Risk**: If a report falsely characterizes a site's content, the site operator could sue for defamation.

**Mitigations**:
- **Reporter attestation**: Reporter certifies that claims are truthful.
- **Terms of service**: Clear language that the org transmits reports filed by users and does not independently verify all claims.
- **Admin review**: The approval queue provides a check, but admins should not be expected to verify every factual claim.
- **Insurance**: Consider errors & omissions insurance.

### 4.4 Evidence Retention
**Severity**: MEDIUM

**Mitigations needed**:
- **Retention policy**: Define retention periods (e.g., 2 years after report resolution, or longer if required by legal hold).
- **Legal hold mechanism**: Ability to flag reports as under legal hold to prevent deletion.
- **Automated expiry**: For reports not under hold, implement automated evidence cleanup after the retention period.

### 4.5 CDA Section 230
**Severity**: LOW (informational)

**Analysis**: Section 230 generally protects platforms from liability for user-generated content. However, the org is not merely hosting content -- it is actively transmitting abuse reports to third parties. The good-faith content moderation provisions of 230(c)(2) may provide some protection for the reporting activity itself. Legal counsel should evaluate.

---

## 5. Email Reputation and Deliverability

### 5.1 Sender Reputation
**Severity**: HIGH

**Risk**: Abuse reports sent via SendGrid could be flagged as spam by receiving mail servers or by SendGrid itself, resulting in account suspension.

**Mitigations needed**:
- **SPF/DKIM/DMARC**: Configure all three for the sending domain. Verify alignment.
- **Dedicated IP**: Use a dedicated SendGrid IP (not shared pool) to control reputation.
- **IP warming**: Start with very low volume (5-10 emails/day) and gradually increase.
- **Proper headers**: Include `List-Unsubscribe`, proper `Message-ID`, and X-ARF headers that abuse desks expect.
- **Bounce handling**: Monitor bounces via SendGrid webhooks. Remove invalid addresses promptly.
- **Content quality**: Ensure email bodies are professional and not flagged by spam filters. Avoid ALL CAPS, excessive punctuation, spam trigger words.
- **SendGrid category/subuser**: Use a dedicated SendGrid subuser for abuse reports, separate from magic link emails, to isolate reputation.

### 5.2 Volume Management
**Severity**: MEDIUM

**Mitigations**:
- **Daily sending cap**: Configurable maximum emails per day.
- **Batch spacing**: Space outgoing emails by at least 30 seconds.
- **SendGrid event webhooks**: Monitor delivery, bounce, spam report events.

---

## 6. Application Security

### 6.1 Evidence File Serving
**Severity**: HIGH

**Finding**: No evidence serving handler exists yet in the codebase. When implemented:
- Evidence **must** be served via an authenticated handler that checks session + authorization (user owns the report, or user is admin).
- Evidence directory **must** be outside the web root (the current `./evidence` path is outside, which is good).
- Set `Content-Disposition: attachment` to prevent inline rendering.
- Set `X-Content-Type-Options: nosniff` on all responses (implemented in `middleware.go`).
- **Never serve SVG inline** -- it can contain JavaScript.

### 6.2 SQL Injection
**Severity**: LOW (currently mitigated)

**Finding**: All SQL queries in `sqlite.go` use parameterized queries (`?` placeholders). This is correct and prevents SQL injection. No string concatenation of user input into queries was found.

**Recommendation**: Maintain this practice. Consider adding a linter rule to flag string concatenation in SQL.

### 6.3 Path Traversal in Evidence Storage
**Severity**: MEDIUM

**Finding**: In `evidence.go`, the `filename` parameter is stored in the database but not used for the storage path -- the storage path is constructed from `reportID` (UUID) and `evidenceID` (UUID), which eliminates path traversal in storage. However, the `filename` field stored in the DB comes from user input and could contain `../` sequences.

**Mitigations needed**:
- **Sanitize the filename**: Strip directory components and null bytes before storing (implemented in `safety.go`).
- **Validate reportID is a UUID**: Ensure `reportID` passed to `HandleUpload` is a valid UUID to prevent path traversal via that parameter.

### 6.4 Magic Link Security
**Severity**: MEDIUM

**Finding**: Magic link tokens are stored in the database. Key concerns:

- **Token entropy**: Tokens should be generated with `crypto/rand` (at least 32 bytes). If using `uuid.New()`, this is acceptable (UUIDv4 uses `crypto/rand`).
- **Timing attacks**: Token comparison via SQL `WHERE token = ?` is generally safe against timing attacks because the database lookup time varies based on index structure, not byte-by-byte comparison. However, consider using `hmac.Equal` for an additional layer if tokens are ever compared in Go code.
- **Single use**: The `MarkMagicLinkUsed` function exists but the check-and-mark is not atomic. Under concurrent requests, a magic link could be used twice.
  - **Mitigation**: Use `UPDATE magic_links SET used = 1 WHERE token = ? AND used = 0` and check affected rows.
- **Expiry**: 15-minute expiry is appropriate.
- **Cleanup**: Expired magic links should be periodically deleted to prevent table bloat.

### 6.5 Session Security
**Severity**: MEDIUM

**Mitigations needed** (for when session management is implemented):
- **Session ID entropy**: Use `crypto/rand` for session IDs (at least 32 bytes).
- **Secure cookie flags**: `Secure`, `HttpOnly`, `SameSite=Lax`.
- **Session expiry**: Enforce server-side expiry check on every request.
- **Session fixation**: Generate a new session ID upon login.
- **Concurrent session limit**: Consider limiting active sessions per user.

### 6.6 CSRF Protection
**Severity**: HIGH

**Finding**: No CSRF protection exists in the current codebase. All state-changing POST endpoints are vulnerable.

**Mitigation**: CSRF middleware with per-session tokens (implemented in `middleware.go`).

### 6.7 OAuth State Parameter
**Severity**: MEDIUM

**Finding**: OAuth is planned but not yet implemented.

**Mitigations needed** (for when implemented):
- Generate a cryptographically random `state` parameter for each OAuth flow.
- Store it in the session and verify on callback.
- Use `state` with sufficient entropy (32 bytes minimum).

### 6.8 Security Headers
**Severity**: MEDIUM

**Finding**: No security headers are set in the current codebase.

**Mitigation**: Security headers middleware (implemented in `middleware.go`):
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `X-XSS-Protection: 0` (disabled, as CSP is the modern replacement)
- `Permissions-Policy: camera=(), microphone=(), geolocation=()`

### 6.9 Request Size Limits
**Severity**: MEDIUM

**Finding**: No HTTP request body size limits exist. Large POST bodies could exhaust memory.

**Mitigations needed**:
- Limit request body size globally (e.g., 25MB for upload endpoints, 1MB for form endpoints).
- Use `http.MaxBytesReader` on the request body.

---

## 7. Findings Summary

| # | Finding | Severity | Status |
|---|---------|----------|--------|
| 1 | False report weaponization | HIGH | Partially mitigated (admin queue) |
| 2 | CSAM handling and NCMEC reporting | CRITICAL | Not implemented |
| 3 | No rate limiting | HIGH | Implemented in `ratelimit.go` |
| 4 | No CSRF protection | HIGH | Implemented in `middleware.go` |
| 5 | No security headers | MEDIUM | Implemented in `middleware.go` |
| 6 | `image/*` wildcard allows SVG XSS | MEDIUM | Fixed in `safety.go` |
| 7 | No filename sanitization | MEDIUM | Implemented in `safety.go` |
| 8 | Magic link not atomically single-use | MEDIUM | Needs fix in store layer |
| 9 | No per-report evidence size cap | HIGH | Implemented in `safety.go` |
| 10 | BGP client has no connection timeout | MEDIUM | Needs fix |
| 11 | No GDPR compliance | HIGH | Needs policy and implementation |
| 12 | No evidence retention policy | MEDIUM | Needs policy |
| 13 | Email reputation not protected | HIGH | Needs SendGrid configuration |
| 14 | No request body size limits | MEDIUM | Needs implementation |
| 15 | No busy timeout on SQLite | LOW | Needs connection string change |
| 16 | Admin content exposure | HIGH | Needs UI implementation |

---

## 8. Immediate Action Items (Pre-Launch Blockers)

1. **Retain legal counsel** for CSAM reporting obligations and GDPR compliance.
2. **Implement NCMEC reporting workflow** (even if manual initially).
3. **Configure SPF/DKIM/DMARC** for sending domain.
4. **Add CSRF protection** to all forms (done in `middleware.go`).
5. **Add rate limiting** (done in `ratelimit.go`).
6. **Add content safety validation** (done in `safety.go`).
7. **Create Terms of Service** with reporter attestation.
8. **Create Privacy Policy** with data retention schedule.
9. **Fix magic link race condition** (atomic check-and-mark).
10. **Add busy_timeout pragma** to SQLite connection string.
