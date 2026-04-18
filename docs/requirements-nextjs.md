# OWASP Scanner — React/Next.js Extension Requirements

## Context

The scanner currently handles Python projects with regex rules, AST-based
dataflow analysis, and LLM-powered scanning (GPT-5.4-nano). This extension
adds first-class support for React/Next.js App Router applications.

**Core thesis:** The highest-value findings for a Next.js scanner are not
generic React bugs — they are framework-shaped bugs: middleware-only
authorization, Server Action misuse, server-to-client data overexposure,
cache confusion between HTML and RSC payloads, SSRF through framework
helpers, and configuration mistakes that turn App Router conveniences into
attack surface. The scanner must model framework semantics first, syntax
second.

**Design principle:** Extend, don't fork. The persistence layer, MCP tools,
dedup, audit trail, reporting, SARIF export, and LLM integration are
language-agnostic. Only the scanning rules, file-type classifier, and
framework-specific prompts change.

---

## Real-World Attack Surface (CVE-Anchored)

These are the verified vulnerabilities that shape our rule priorities.
Every scanner rule should trace back to a real CVE or documented incident.

### Middleware Bypass (Critical — Drives Rule Priority)

| CVE | Impact | Versions | Root Cause |
|-----|--------|----------|------------|
| CVE-2024-51479 | Auth bypass for root-level pages | >=9.5.5, <14.2.15 | Pathname-based middleware protection skipped for routes directly under `/` |
| CVE-2025-29927 | Complete middleware bypass | 12-15 (multiple ranges) | Attacker sets `x-middleware-subrequest` header to skip middleware entirely |

**Scanner implication:** "Auth enforced only in middleware" must be a
critical finding, not a best-practice note. Two real CVEs prove middleware
is not a reliable sole authorization layer.

### Server Action Vulnerabilities

| CVE | Impact | Versions | Root Cause |
|-----|--------|----------|------------|
| CVE-2024-34351 | SSRF via Server Action redirect | <14.1.1 | Server-side HEAD request honored attacker-controlled `Host` header during redirect |
| CVE-2024-56332 | DoS / denial-of-wallet | 13.0-15.1.2 | Server Actions could hang until infrastructure timeout; exploitable for billing abuse |
| CVE-2026-27978 | CSRF bypass on Server Actions | 16.0.1-16.1.7 | `Origin: null` treated as absent rather than hostile |

**Scanner implication:** Server Actions are public HTTP endpoints regardless
of whether they're "behind a form." Every used Server Action needs auth and
input validation checks.

### RSC Protocol / Cache

| CVE | Impact | Versions | Root Cause |
|-----|--------|----------|------------|
| CVE-2025-49005 | Cache poisoning (HTML ↔ RSC confusion) | >=15.3.0, <15.3.3 | Missing `Vary` header allowed HTML response cached for RSC request |
| CVE-2025-55182 | RCE via RSC protocol | Upstream React | React Server Components protocol vulnerability |
| CVE-2025-55183 | Server Function source exposure | Multiple | Crafted requests returned compiled Server Function source, exposing hardcoded secrets |

**Scanner implication:** Cache mode, middleware redirects, and RSC/HTML
content negotiation are security-sensitive. Server Functions should never
contain hardcoded secrets.

### Auth.js / NextAuth

| CVE | Impact | Versions |
|-----|--------|----------|
| CVE-2023-27490 | OAuth compromise | <4.20.1 |
| CVE-2023-48309 | Mock authenticated user via replayed JWT | <4.24.5 |

**Scanner implication:** Even with a dedicated auth library, middleware-based
auth assumptions are fragile. Scanner should check for proper claims/role
validation, not just session existence.

### Server Component Data Leakage (No CVE — Documented Incident)

A U.S. government site built on Next.js leaked removed identifiers in
`self.__next_f` RSC hydration payloads. Props passed from Server Components
to Client Components are fully serialized into the RSC payload and shipped
to the browser, whether or not the component visibly renders them.

**Scanner implication:** This is a first-class vulnerability class even
without a framework CVE. Every Server→Client prop edge is an exposure
boundary.

---

## App Router Security Model

### Server/Client Boundary

- Server Components run only on the server and can access secrets, DBs, APIs
- Client Components (`'use client'`) pre-render on server but must be treated
  under browser security assumptions
- **Props passed from Server → Client go through RSC serialization.** Full
  prop objects (not just rendered fields) are exposed in `self.__next_f`
  hydration scripts. Functions and classes are blocked; plain objects, arrays,
  strings, numbers are all serialized.
- `server-only` package, DTO shaping, and React taint APIs are preventive
  controls — they are not scanners

### Server Actions

- Publicly callable HTTP endpoints, even when developers think of them as
  form handlers
- Action IDs in Next.js 15+ are unguessable and non-deterministic
- Form presence is NOT a defense — actions can be invoked with crafted POST
- CSRF protection is `Origin` header checking — has had edge cases
  (CVE-2026-27978 `Origin: null`)
- Every used Server Action must validate auth and input at the function level

### Middleware Execution Order

`next.config.js headers` → `next.config.js redirects` → `middleware` →
`rewrites + filesystem routing`

Middleware runs before cached content and route matching, but NOT before
config-level headers/redirects. Security implemented only in middleware
can be bypassed by framework CVEs AND by matcher mistakes.

### File Type Classification

| Signal | File Type | Trust Level |
|--------|-----------|------------|
| Default in `app/` | Server Component | Server (can access secrets) |
| `'use client'` directive | Client Component | Browser (untrusted) |
| `'use server'` directive | Server Action | Server (but publicly callable) |
| `route.ts` / `route.js` | Route Handler | Server |
| `middleware.ts` | Middleware | Edge |
| `layout.tsx` | Layout | Server (default) |
| `page.tsx` | Page | Server (default) |
| `error.tsx` | Error Boundary | Client (always) |

---

## 1. Project Detection

When `scan_directory` is called, detect project type:

| Signal | Type |
|--------|------|
| `next.config.js` / `.mjs` / `.ts` | Next.js |
| `package.json` with `"next"` in deps | Next.js |
| `package.json` without `"next"` | React (generic) |
| `pyproject.toml` or `requirements.txt` | Python |
| Both | Monorepo — scan both |

Return `"project_type": "nextjs"` in scan response.

---

## 2. Regex Rules

New file: `src/owasp_scanner/rules/nextjs_patterns.py`

### A01 — Broken Access Control

| Rule ID | Pattern | Severity | CVE Anchor |
|---------|---------|----------|------------|
| `JS-A01-001` | Route handler (`route.ts`) without auth check | high | CVE-2024-51479, CVE-2025-29927 |
| `JS-A01-002` | Server Action (`'use server'`) without auth check | high | CVE-2026-27978 |
| `JS-A01-003` | `Object.fromEntries(formData)` spread into ORM update (mass assignment) | critical | — |
| `JS-A01-004` | `redirect()` with user-controlled destination | high | — |
| `JS-A01-005` | `revalidatePath()` / `revalidateTag()` with user input | medium | CVE-2025-49005 |

### A02 — Security Misconfiguration

| Rule ID | Pattern | Severity | CVE Anchor |
|---------|---------|----------|------------|
| `JS-A02-001` | `NEXT_PUBLIC_` env var containing SECRET/KEY/TOKEN/PASSWORD | critical | — |
| `JS-A02-002` | `images.remotePatterns` with wildcard `hostname: '**'` | high | SSRF via `next/image` |
| `JS-A02-003` | Missing security headers in `next.config.js` | medium | — |
| `JS-A02-004` | `poweredByHeader` not disabled | low | — |
| `JS-A02-005` | `rewrites` proxying to internal services | high | — |

### A05 — Injection

| Rule ID | Pattern | Severity | CVE Anchor |
|---------|---------|----------|------------|
| `JS-A05-001` | `dangerouslySetInnerHTML` with non-static content | high | — |
| `JS-A05-002` | `innerHTML` assignment | high | — |
| `JS-A05-003` | `eval()` / `new Function()` | critical | — |
| `JS-A05-004` | Prisma `$queryRawUnsafe` or `$executeRawUnsafe` | critical | — |
| `JS-A05-005` | Prisma `$queryRaw` with string concatenation (not tagged template) | critical | — |
| `JS-A05-006` | `child_process.exec()` with template literal | critical | — |
| `JS-A05-007` | `document.write()` | high | — |
| `JS-A05-008` | `router.push()` / `router.replace()` with user input (XSS via `javascript:`) | high | — |

### A04 — Cryptographic Failures

| Rule ID | Pattern | Severity |
|---------|---------|----------|
| `JS-A04-001` | `Math.random()` for tokens/IDs/nonces | high |
| `JS-A04-002` | `cookies().set()` without `httpOnly`/`secure`/`sameSite` | high |

### A06 — Insecure Design (LLM-primary, regex as heuristic)

| Rule ID | Pattern | Severity |
|---------|---------|----------|
| `JS-A06-001` | API route without rate limiting imports | medium |
| `JS-A06-002` | Middleware matcher that doesn't cover `/api/` routes | high |

### A07 — Authentication Failures

| Rule ID | Pattern | Severity |
|---------|---------|----------|
| `JS-A07-001` | Database connection string in files under `app/` | critical |
| `JS-A07-002` | API keys hardcoded in client components (`'use client'` files) | critical |

### A10 — Exception Handling

| Rule ID | Pattern | Severity |
|---------|---------|----------|
| `JS-A10-001` | Empty `catch {}` block | high |
| `JS-A10-002` | `catch` returning raw `e.message` or `e.stack` to client | medium |
| `JS-A10-003` | Route segment with data fetching but no `error.tsx` | medium |

**Total: ~28 regex rules**

---

## 3. Next.js Config Scanner

Extend `core/config_scanner.py` with `scan_nextjs_config(content)`:

**next.config.js checks:**
- Security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)
- `images.remotePatterns` permissiveness
- `rewrites` / `redirects` exposing internal services
- `poweredByHeader: false`
- `reactStrictMode: true`
- `experimental` flags with security implications

**middleware.ts checks:**
- Does middleware exist?
- Does the `matcher` cover all route segments that need auth?
- Does it check auth tokens/sessions?
- Does it cover API routes?

**.env file checks:**
- `NEXT_PUBLIC_` vars that look like secrets
- `.env.local` in `.gitignore`

---

## 4. LLM Prompts (The Differentiator)

### Next.js-specific system prompt

Add `NEXTJS_SCAN_SYSTEM_PROMPT` to `core/prompts.py`. Key additions over
the generic prompt:

```
You are scanning a Next.js App Router application. Understand the security
model:

SERVER/CLIENT BOUNDARY:
- Files in app/ are Server Components by default (run on server only)
- 'use client' marks Client Components (run in browser)
- Props passed from Server → Client are serialized into RSC payload and
  visible in the browser (self.__next_f). Full objects are exposed, not
  just rendered fields. This is a data leak vector.
- Server Components can access secrets, databases, internal APIs. Client
  Components cannot.

SERVER ACTIONS:
- 'use server' functions are public HTTP endpoints, callable without forms
- CSRF protection is Origin-header based (has had bypasses: CVE-2026-27978)
- Every Server Action must validate auth AND input at the function level
- Object.fromEntries(formData) spread into ORM updates = mass assignment

MIDDLEWARE:
- Middleware has been bypassed twice (CVE-2024-51479, CVE-2025-29927)
- Auth enforced ONLY in middleware is a critical finding
- Middleware matchers that miss route segments create auth gaps
- Auth should be re-checked in pages, actions, and route handlers

Focus on these high-priority patterns:
1. Server Component over-fetching (full DB record → Client Component prop)
2. Server Action mass assignment (formData → ORM without field allowlist)
3. Route handlers without auth checks
4. Middleware matcher gaps
5. NEXT_PUBLIC_ exposing secrets
6. Prisma raw SQL injection
7. Open redirect via redirect() with user input
8. Cache poisoning via user-controlled revalidatePath/revalidateTag
9. Image SSRF via permissive remotePatterns
10. Cookie manipulation without secure flags
```

### Boundary-aware file context

When scanning Next.js files, include file type classification:

```
File: app/dashboard/page.tsx
Type: SERVER COMPONENT (default in app/ directory)
Trust: Server-side. Can access secrets, databases, internal APIs.
Risk: Props passed to Client Components cross the trust boundary.
      Data fetched here is serialized into RSC payload.

[file content]
```

This primes the LLM to evaluate boundary violations, not just syntax.

---

## 5. Cross-Boundary Dataflow (LLM-First)

### Server → Client data exposure

The most characteristic App Router vulnerability:

```tsx
// app/dashboard/page.tsx (SERVER COMPONENT)
async function DashboardPage() {
  const user = await prisma.user.findUnique({ where: { id: userId } });
  // user = { id, name, email, ssn, creditCard, passwordHash }
  return <ClientDashboard user={user} />;  // ALL fields in RSC payload
}
```

**Detection strategy:** Classify files → build import graph → identify all
Server→Client prop edges → assign data sensitivity to server-side values
(ORM full-row fetches, objects named `user`/`session`/`token`, calls to
`cookies()`/`headers()`) → LLM adjudicates "is this prop set bigger than
the UI contract?"

### Server Action mass assignment

```tsx
// Vulnerable
'use server'
export async function updateProfile(formData: FormData) {
  const data = Object.fromEntries(formData)
  await prisma.user.update({ where: { id: session.user.id }, data })
  // Attacker adds role=admin to form
}
```

### Taint sources (Next.js specific)

- `params` (dynamic route segments)
- `searchParams` (page props)
- `formData.get()` in server actions
- `request.json()` / `request.text()` in route handlers
- `cookies().get()` / `headers().get()`
- `useSearchParams()` / `useParams()` (client-side)

### Taint sinks (Next.js specific)

- Props passed from Server → Client Components (data exposure)
- `redirect(tainted)` (open redirect)
- `dangerouslySetInnerHTML={{ __html: tainted }}` (XSS)
- `$queryRawUnsafe(tainted)` (SQL injection)
- `exec(tainted)` / `execSync(tainted)` (command injection)
- `fetch(tainted)` (SSRF)
- `revalidatePath(tainted)` (cache poisoning)
- `cookies().set()` without flags (session hijacking)
- `res.json({ error: tainted })` (information leak)

### Implementation approach

**v1: LLM-only for cross-boundary analysis.** Tree-sitter (or regex) for
file-type classification. LLM reasons about data flows across the boundary.
No AST-based taint tracing for JS/TS — the Python taint tracer uses Python's
`ast` module and doesn't apply.

**v2 (optional): Tree-sitter structural extraction.** Feed component props,
imports, exports, and data-fetch patterns to the LLM as structured context.
This makes the LLM more accurate without requiring a full JS taint engine.

---

## 6. Parsing Strategy

**Primary: tree-sitter with `tree-sitter-typescript`**
- Python bindings, handles JSX/TSX, fast (C-based)
- Extracts: `'use client'`/`'use server'` directives, imports, exports,
  function definitions, JSX elements, component props
- Limitation: no type resolution (doesn't know what type a prop is)

**Secondary (optional): TypeScript compiler API via subprocess**
- Type resolution, symbol identity, module resolution
- Useful for: "is this prop a `PrismaClient`?", "what type does `user` have?"
- Requires Node.js runtime — only for deep analysis passes

**Semantic layer: LLM**
- Handles everything tree-sitter and TSC can't: business logic, data
  sensitivity, authorization intent, prop sufficiency
- File-type context priming makes the LLM dramatically more accurate

**Not using: SWC**
- No official Python bindings
- Next.js uses it internally but no security analysis API

---

## 7. Implementation Plan

### Phase 1: Regex rules + config scanner (zero new dependencies)

Files:
- Create `rules/nextjs_patterns.py` (~28 regex rules)
- Extend `config_scanner.py` with `scan_nextjs_config()`
- Update `detect_framework()` for Next.js/React signals
- Update `deep_analyze()` with Next.js file-type detection and
  framework-specific security checklist

Immediate value: catches `dangerouslySetInnerHTML`, Prisma raw SQL,
`NEXT_PUBLIC_` secrets, mass assignment patterns, missing auth in route
handlers, middleware matcher gaps, cookie flag issues.

### Phase 2: LLM prompts + boundary awareness (zero new dependencies)

Files:
- Add `NEXTJS_SCAN_SYSTEM_PROMPT` to `prompts.py`
- Update `llm_scanner.py` to detect Next.js projects and use the
  framework-specific prompt
- Include file-type context in LLM requests

This is the differentiator: LLM understands "this Server Component
over-fetched a secret field and crossed the RSC boundary" — something
no existing SAST tool catches.

### Phase 3: Tree-sitter parser (optional, new dependency)

Files:
- Create `core/ts_analyzer.py` with `TSFileInfo` dataclass
- Feed structural info into `deep_analyze` for richer LLM context

Dependencies:
```toml
[project.optional-dependencies]
nextjs = ["tree-sitter>=0.23", "tree-sitter-typescript>=0.23"]
```

Only needed for deep structural extraction. Phases 1-2 deliver the
highest-value features with zero new dependencies.

---

## 8. Competitive Positioning

### What existing tools catch

| Tool | Strengths | Next.js gaps |
|------|-----------|-------------|
| **Semgrep** | Dangerous API sinks, JS dataflow, custom rules | No App Router boundary model, no Server Action reasoning |
| **ESLint** | React best practices, hooks rules | Correctness-focused, not security. No auth/authz analysis |
| **CodeQL** | Semantic JS/TS analysis, has `NextParams` class | No out-of-box boundary analysis, requires custom queries |
| **Snyk** | Dependencies, broad code smells | No framework-specific semantic analysis |
| **SonarQube** | JS/TS quality + security rules, ESLint import | No App Router awareness |
| **Bearer** | React sink detection, data-flow | No Next.js boundary or Server Action modeling |

### What only we catch (LLM-powered)

| Finding | Why existing tools miss it |
|---------|--------------------------|
| Server Component over-fetching to Client Component | Not a dangerous API — it's an over-broad object crossing a framework boundary |
| Server Action mass assignment | Requires understanding that `Object.fromEntries(formData)` maps to privileged ORM columns |
| Middleware matcher gaps | Requires building a route coverage graph against the matcher config |
| Auth enforced only in middleware | Compositional reasoning — the code looks correct, the architecture is fragile |
| Cache poisoning via `revalidatePath` with user input | Requires understanding framework cache semantics |
| `NEXT_PUBLIC_` exposing a secret (vs publishable key) | Requires judging whether a value is secret based on naming and usage |
| Cookie set without secure flags in auth flow | Requires correlating cookie sensitivity with the route/action context |

---

## 9. Testing Strategy

### Fixtures needed

- `sample_nextjs_app/` — minimal App Router project with:
  - `app/page.tsx` (server component)
  - `app/dashboard/page.tsx` (server component with DB fetch)
  - `components/Dashboard.tsx` (`'use client'` with props)
  - `app/api/users/route.ts` (route handler, no auth)
  - `app/actions.ts` (`'use server'` with mass assignment)
  - `middleware.ts` (with incomplete matcher)
  - `next.config.js` (permissive image patterns)
  - `.env` (with `NEXT_PUBLIC_SECRET_KEY`)

### Test categories

- Rule tests: each regex rule with positive + negative match
- Config scanner tests: secure vs insecure `next.config.js`
- Framework detection: correctly identifies Next.js projects
- LLM prompt tests: verify file-type context is included in LLM requests
- Integration tests: end-to-end scan of the fixture project

### Verification

1. `uv run python -m pytest tests/ -v` — all pass
2. `uv run ruff check src/ tests/` — zero lint
3. Manual: scan a real Next.js project with `mode="hybrid"`
4. Manual: verify boundary-crossing findings appear in the report
