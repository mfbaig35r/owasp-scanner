# OWASP Scanner — React/Next.js Extension Requirements

## Context

The scanner currently handles Python projects with regex rules, AST-based
dataflow analysis, and LLM-powered scanning. This extension adds first-class
support for React/Next.js applications, targeting the unique security surface
of the App Router, Server Components, Server Actions, and API Routes.

The core value proposition: Next.js blurs the client/server boundary in ways
that create novel vulnerabilities. A server component can fetch secrets and a
client component can accidentally expose them. Server actions look like
function calls but cross a network boundary. Most SAST tools don't understand
this boundary. An LLM that does is genuinely differentiated.

## Design Principle

**Extend, don't fork.** The persistence layer, MCP tools, dedup, audit trail,
reporting, SARIF export, and LLM integration are language-agnostic. Only the
scanning rules, AST parser, and framework-specific config checks change.

---

## 1. Project Detection

### Requirements

**1.1 Auto-detect project type**

When `scan_directory` is called, detect the project type:

| Signal | Project type |
|--------|-------------|
| `pyproject.toml` or `requirements.txt` | Python |
| `next.config.js` or `next.config.mjs` or `next.config.ts` | Next.js |
| `package.json` with `"next"` in dependencies | Next.js |
| `package.json` without `"next"` | React (generic) |
| Both `pyproject.toml` and `package.json` | Monorepo — scan both |

Return the detected type in the scan response: `"project_type": "nextjs"`.

**1.2 Language-aware file collection**

Extend `SCANNABLE_EXTENSIONS` to include:
`.js`, `.jsx`, `.ts`, `.tsx`, `.mjs`, `.cjs`

These are already in the set but worth confirming they're scanned by default.
Add `.env`, `.env.local`, `.env.production` to the secrets scan (already
covered by `file_glob="*"` on secrets rules).

---

## 2. Regex Rules for React/Next.js

### Requirements

**2.1 XSS / Client-side injection (A05)**

| Rule ID | Pattern | Severity |
|---------|---------|----------|
| `JS-A05-001` | `dangerouslySetInnerHTML` with non-static content | high |
| `JS-A05-002` | `innerHTML` assignment | high |
| `JS-A05-003` | `document.write()` | high |
| `JS-A05-004` | `eval()` / `new Function()` in client code | critical |
| `JS-A05-005` | `__html` prop with template literal containing variables | high |
| `JS-A05-006` | `$.html()` (jQuery, if detected) | high |

**2.2 Server Action / API Route issues (A01, A06, A07)**

| Rule ID | Pattern | Severity |
|---------|---------|----------|
| `JS-A01-001` | API route (`route.ts`) without auth middleware import | high |
| `JS-A01-002` | Server action (`'use server'`) without input validation | high |
| `JS-A06-001` | API route without rate limiting | medium |
| `JS-A07-001` | `cookies()` or `headers()` used without validation | medium |
| `JS-A07-002` | JWT decoded without verification (`jwt.decode` without `verify`) | high |

**2.3 Data exposure (A02, A04)**

| Rule ID | Pattern | Severity |
|---------|---------|----------|
| `JS-A02-001` | `NEXT_PUBLIC_` env var containing `SECRET`, `KEY`, `TOKEN`, `PASSWORD` | critical |
| `JS-A02-002` | `console.log` with sensitive data patterns in production code | medium |
| `JS-A04-001` | `Math.random()` used for tokens/IDs | high |
| `JS-A04-002` | `crypto.randomBytes` not used where it should be | medium |

**2.4 Injection (A05)**

| Rule ID | Pattern | Severity |
|---------|---------|----------|
| `JS-A05-007` | Prisma `$queryRaw` / `$executeRaw` with template literal | critical |
| `JS-A05-008` | Drizzle `sql` with string concatenation | critical |
| `JS-A05-009` | `child_process.exec()` with template literal | critical |
| `JS-A05-010` | `fetch()` with user-controlled URL (SSRF) | high |

**2.5 Misconfiguration (A02)**

| Rule ID | Pattern | Severity |
|---------|---------|----------|
| `JS-A02-003` | Missing CSP in `next.config.js` headers | medium |
| `JS-A02-004` | `images.remotePatterns` with wildcard `**` | medium |
| `JS-A02-005` | `rewrites` proxying to internal services without auth | high |
| `JS-A02-006` | `output: 'export'` without understanding implications | low |

**2.6 Secrets in client bundles (A07)**

| Rule ID | Pattern | Severity |
|---------|---------|----------|
| `JS-A07-003` | AWS/OpenAI/Stripe/Firebase keys in `.env` without `NEXT_PUBLIC_` prefix but imported in client code | critical |
| `JS-A07-004` | API keys hardcoded in client components | critical |
| `JS-A07-005` | Database connection strings in any file under `app/` or `pages/` | critical |

**2.7 Error handling (A10)**

| Rule ID | Pattern | Severity |
|---------|---------|----------|
| `JS-A10-001` | Empty `catch {}` block | high |
| `JS-A10-002` | `catch` that returns raw error to client (`res.json({ error: e.message })`) | medium |
| `JS-A10-003` | Missing `error.tsx` boundary in route segments with data fetching | medium |

### Implementation

New file: `src/owasp_scanner/rules/nextjs_patterns.py`

Same `Rule` dataclass as Python rules. Each rule gets `file_glob="*.{js,jsx,ts,tsx}"` 
or specific patterns for config files. Loaded by `get_rules()` when the project
type is Next.js (or always — the file_glob filtering ensures they only match
relevant files).

---

## 3. Next.js Config Scanner

### Requirements

**3.1 `next.config.js` analysis**

Extend `core/config_scanner.py` with `scan_nextjs_config(content: str)`:

Checks:
- Security headers configured (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)
- `images.remotePatterns` not overly permissive
- `rewrites` / `redirects` not exposing internal services
- `experimental` flags that have security implications
- `poweredByHeader: false` (hides Next.js fingerprint)
- `reactStrictMode: true`

**3.2 `middleware.ts` analysis**

Check if middleware exists and what it protects:
- Does the project have a `middleware.ts`/`middleware.js`?
- Does it cover all route segments that need auth?
- Does it check auth tokens/sessions?
- Does it have a `matcher` config, and does that matcher cover API routes?

**3.3 `.env` file analysis**

- Check for secrets in `.env.local` that shouldn't be there
- Check for `NEXT_PUBLIC_` vars that look like secrets
- Check that `.env.local` is in `.gitignore`

### Implementation

Add to `core/config_scanner.py`:
- `scan_nextjs_config(content: str) -> list[ConfigCheck]`
- Update `detect_framework()` with Next.js signals

---

## 4. TypeScript/JSX AST Analysis

### Requirements

**4.1 Parser choice**

Use `tree-sitter` with the TypeScript/TSX grammar for AST parsing. Rationale:
- Python bindings available (`tree-sitter` package)
- Handles JSX/TSX natively
- Fast (written in C)
- Same parser used by many editors and tools
- No need to shell out to Node.js

Alternative: shell out to a small Node.js script using TypeScript's compiler
API. More accurate for type information but adds a Node.js runtime dependency.

Recommendation: **tree-sitter for structural analysis, LLM for semantic
understanding.** The tree-sitter parser identifies function boundaries,
component definitions, exports, and imports. The LLM handles the type-level
reasoning (is this prop user-controlled? does this server action validate its
input?).

**4.2 What to extract**

For each `.ts`/`.tsx` file:

- **File type**: server component (default in `app/`), client component
  (`'use client'`), server action (`'use server'`), API route (`route.ts`),
  middleware (`middleware.ts`), layout, page, error boundary
- **Exports**: what functions/components are exported
- **Imports**: especially `next/headers`, `next/cookies`, database clients,
  auth libraries
- **Props interface**: what data the component receives
- **Data fetching**: `fetch()` calls, database queries, `cache()`/
  `unstable_cache()` usage
- **Form actions**: `action={someServerAction}` in JSX
- **Dangerous patterns**: `dangerouslySetInnerHTML`, `eval`, `innerHTML`

**4.3 Server/client boundary detection**

The critical capability: understanding which code runs on the server vs client.

- Files in `app/` are server components by default
- `'use client'` at the top makes it a client component
- `'use server'` in a file or function makes it a server action
- API routes (`route.ts`) are always server-side
- `middleware.ts` runs on the edge
- A server component importing a client component creates a trust boundary
- Props passed from server to client components cross the boundary — this is
  where data leaks happen

**4.4 Integration with dataflow**

New file: `src/owasp_scanner/core/ts_analyzer.py`

```python
@dataclass
class TSFileInfo:
    file_type: str          # "server_component", "client_component", "server_action",
                            # "api_route", "middleware", "layout", "page", "lib"
    exports: list[str]
    imports: list[ImportInfo]
    components: list[ComponentInfo]
    data_fetches: list[DataFetchInfo]
    server_actions: list[ServerActionInfo]
    dangerous_patterns: list[DangerousPattern]
```

This feeds into `deep_analyze` — when the file is `.tsx`/`.ts`, use the TS
analyzer instead of the Python one. The security checklist adapts:

- Server component: "Does this fetch sensitive data? Are all fetched fields
  safe to render? Could any prop leak to a client component?"
- Client component: "Does this use `dangerouslySetInnerHTML`? Does it make
  client-side fetches that should be server-side?"
- Server action: "Does this validate all input? Does it check auth? Does it
  use parameterized queries?"
- API route: "Does this have auth middleware? Rate limiting? Input validation?"

---

## 5. LLM Prompts for React/Next.js

### Requirements

**5.1 Next.js-specific system prompt**

Add `NEXTJS_SCAN_SYSTEM_PROMPT` to `core/prompts.py`:

```
Focus on Next.js App Router security:
- Server/client boundary: data leaking from server components to client via props
- Server actions: input validation, auth checks, CSRF protection
- API routes: auth middleware, rate limiting, input validation
- Client-side: XSS via dangerouslySetInnerHTML, eval, innerHTML
- Environment variables: NEXT_PUBLIC_ exposing secrets
- Prisma/Drizzle: raw query injection
- Middleware: coverage gaps, auth bypass
- Data fetching: cache poisoning, SSRF, sensitive data in responses
```

**5.2 Boundary-aware analysis**

When the LLM scans a Next.js project, include the file type in the context:

```
File: app/dashboard/page.tsx (SERVER COMPONENT)
This file runs on the server. Data fetched here is rendered to HTML.
Props passed to client components cross the trust boundary.

[file content]
```

This primes the LLM to think about server/client boundary violations.

---

## 6. Cross-Boundary Dataflow

### Requirements

**6.1 Server → client data flow tracking**

The most novel analysis: tracking data from server-side fetches through to
client component props.

```tsx
// app/dashboard/page.tsx (server component)
async function DashboardPage() {
  const user = await db.user.findUnique({ where: { id: userId } });
  // user has { id, name, email, ssn, creditCard }
  return <ClientDashboard user={user} />;  // ALL fields exposed to client
}

// components/ClientDashboard.tsx ('use client')
export function ClientDashboard({ user }) {
  // user.ssn and user.creditCard are now in the client bundle
}
```

This is a data leak — sensitive fields flow from a server-side query to a
client component. The fix is selecting only the needed fields:
`{ id: user.id, name: user.name }`.

**6.2 Form → server action flow**

```tsx
// Client component with form
<form action={updateProfile}>
  <input name="role" />  {/* user can set their own role! */}
</form>

// Server action
async function updateProfile(formData: FormData) {
  const role = formData.get('role');
  await db.user.update({ where: { id: userId }, data: { role } });
  // Mass assignment — user escalated their own privileges
}
```

**6.3 Taint sources (Next.js specific)**

- `searchParams` (page props)
- `params` (dynamic route segments)
- `formData.get()` in server actions
- `request.json()` / `request.text()` in API routes
- `cookies().get()` / `headers().get()`
- `useSearchParams()` (client-side)
- `useParams()` (client-side)

**6.4 Taint sinks (Next.js specific)**

- `dangerouslySetInnerHTML={{ __html: tainted }}`
- `redirect(tainted)` (open redirect)
- `fetch(tainted)` (SSRF)
- `$queryRaw(tainted)` / `$executeRaw(tainted)` (SQL injection)
- `exec(tainted)` / `execSync(tainted)` (command injection)
- `eval(tainted)` / `new Function(tainted)` (code execution)
- Props passed from server to client components (data exposure)
- `res.json({ error: tainted })` (error information leak)
- `cookies().set()` without `httpOnly`/`secure`/`sameSite`

### Implementation approach

For v1: **LLM-only for cross-boundary analysis.** The tree-sitter parser
identifies file types (server/client/action/route) and the LLM reasons about
data flows across the boundary. No AST-based taint tracing for JS — the
Python taint tracer assumes Python's `ast` module.

For v2: Add tree-sitter-based taint tracing for JS/TS. Map the call graph
across server/client boundaries. This is significantly harder than Python
because of:
- Dynamic imports and code splitting
- Component composition (props drilling, context, render props)
- Async server components
- The module resolution algorithm (tsconfig paths, barrel exports)

---

## 7. Implementation Plan

### Phase 1: Regex rules + config scanner (no new parser)

- Add `rules/nextjs_patterns.py` with ~25 regex rules
- Add `scan_nextjs_config()` to `config_scanner.py`
- Update `detect_framework()` with Next.js/React signals
- Update `deep_analyze()` to detect Next.js file types and return
  appropriate security checklist
- All regex-based, no tree-sitter dependency

This gives immediate value — catches `dangerouslySetInnerHTML`, raw SQL,
`NEXT_PUBLIC_` secrets, missing auth in API routes, etc.

### Phase 2: LLM prompts + boundary awareness

- Add `NEXTJS_SCAN_SYSTEM_PROMPT` to `prompts.py`
- Update LLM scanner to include file type context (server/client/action)
  when scanning Next.js files
- The LLM handles cross-boundary analysis, server action validation,
  and design-level issues

This is where the real value is — the LLM understands "this server
component fetches sensitive data and passes all of it to a client
component" in a way no regex or AST can.

### Phase 3: Tree-sitter parser (optional, v2)

- Add `tree-sitter` and `tree-sitter-typescript` as optional deps
- Build `core/ts_analyzer.py` for structural extraction
- Feed structural info into `deep_analyze` for richer context
- Consider tree-sitter-based taint tracing (complex)

### Dependencies

```toml
[project.optional-dependencies]
nextjs = ["tree-sitter>=0.23", "tree-sitter-typescript>=0.23"]
```

Phase 1-2 require **zero new dependencies**. The regex rules work with
the existing scanner, and the LLM prompts work with the existing OpenAI
integration. Tree-sitter is only needed for Phase 3.

---

## 8. What This Catches That Others Don't

| Issue | Semgrep | ESLint | OWASP Scanner (LLM) |
|-------|---------|--------|---------------------|
| `dangerouslySetInnerHTML` | Yes | Yes | Yes |
| SQL injection in Prisma raw queries | Yes | No | Yes |
| Missing auth on API routes | Partial | No | **Yes** (design-level) |
| Server action without input validation | No | No | **Yes** |
| Sensitive data leaked via server→client props | No | No | **Yes** |
| `NEXT_PUBLIC_` exposing secrets | Partial | No | Yes |
| Mass assignment in server actions | No | No | **Yes** |
| Missing rate limiting on API routes | No | No | **Yes** |
| Middleware auth coverage gaps | No | No | **Yes** |
| Cache poisoning in `unstable_cache` | No | No | **Yes** |

The bolded items are the differentiation — design-level issues that require
understanding the Next.js execution model, not just pattern matching.
