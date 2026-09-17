# Gaps

What was discussed → how we solve it. Nothing else.

## Implementation constraints (build everything below to these)
- **Deploy target: AWS.** All new modules must run in AWS. Postgres = RDS (use existing DatabaseManager, connection from env/Secrets Manager, no localhost assumptions). Secrets/creds via AWS Secrets Manager + IAM roles, never hardcoded. Region-aware config via env.
- **LLM: Amazon Bedrock.** The LLM/brain layer (§2 novel payloads, §5 reasoning, §1 workflow step-labeling) calls Claude via Bedrock `bedrock-runtime` (Converse/InvokeModel), model id + region from env, auth via IAM role (not API keys). Reuse the existing Bedrock client; do not add other providers. Gate behind availability so deterministic paths run if Bedrock model access is not yet granted.
- **Payload auto-sync in AWS:** PATT/nuclei pulled to the instance/container FS (or an EFS/volume), PayloadUpdater re-ingests to RDS. Egress to github for pulls must be allowed for the agent host (infra allowlist), separate from scan-target egress rules.
- **Egress firewall stays intact** in AWS; scan-target scope enforcement unchanged. Bedrock + github endpoints are agent-infra, not scan targets.

## 0. CORE PROBLEM (generalizes the login/SQLi example — applies to ALL classes & ALL surfaces)

**Problem.** Testing is hardcoded, shallow, fragmented, and aimed at the wrong
place — for EVERY vuln class and EVERY surface, not just SQLi/login:
- **Hardcoded & shallow:** each probe carries a few fixed payloads while
  PayloadsAllTheThings documents dozens of techniques/variants/bypasses PER class.
  We use a fraction of each. Breadth we must cover (examples, not exhaustive):
  - **SQLi:** error / boolean-blind / time-blind / union / stacked / out-of-band / WAF-bypass encodings
  - **XSS:** reflected / stored / DOM / mutation / polyglot / attribute-break / event-handler / filter & CSP bypass
  - **SSRF:** internal IPs / cloud metadata (AWS/GCP/Azure) / gopher-dict-file schemes / redirect-to-internal / DNS rebinding / blind-OOB
  - **XXE:** classic file read / OOB / parameter-entity / SSRF-via-XXE / billion-laughs / SVG/DOCX/XLSX carriers
  - **SSTI:** per-engine (Jinja2/Twig/Freemarker/ERB/Velocity/…) detect → sandbox escape → RCE
  - **RCE / command injection:** separators / blind time / OOB / arg injection / deserialization gadgets
  - **LFI / path traversal:** traversal depth / null byte / wrappers / encoding / log poisoning
  - **IDOR / BOLA:** numeric/UUID/hash id enumeration / parameter & body id swap / method-based
  - **Privilege escalation:** vertical (user→admin) / horizontal (user→user) / mass-assignment role field / forced browsing to admin / JWT role claim tamper
  - **Auth / JWT:** alg=none / HS-RS confusion / weak-secret crack / kid injection / expiry ignore / replay across users
  - **File upload:** extension/content-type/magic-byte/polyglot/null-byte bypass + execution verification
  - **WebSocket:** CSWSH (origin) / no-auth / per-message IDOR / field injection / message tamper / tenant leak / replay / subprotocol abuse
  - **GraphQL:** introspection / deep-query & alias & batch DoS / field-level authz / mutation abuse / arg injection
  - **Cloud findings:** S3/GCS/Azure public buckets / IMDS credential theft via SSRF / subdomain takeover / exposed IAM/keys / misconfigured services
  - **Business logic:** step-skip / reorder / replay / value-tamper / coupon reuse / race / cross-user
  - **Others:** open-redirect, CORS, CSRF, request smuggling (CL-TE/TE-CL/TE-TE), cache poisoning/deception, host-header injection, prototype pollution, CRLF/email injection, deserialization, secrets/info disclosure — each with its own full variant set.
- **Wrong injection point:** payloads go into a guessed param (`?q=`), not the
  REAL input — login body fields, JSON keys, headers, cookies, path segments,
  multipart fields, WebSocket message fields, GraphQL args.
- **Fragmented / half-testing:** separate probes each do a slice; no surface gets
  the *complete* battery across *all* its injection points. Coverage looks done
  but is partial everywhere.
- **Not adaptive:** technique choice is fixed, not driven by what was learned
  (context, tech stack, WAF, prior results).

**Solution — one unified, context-aware injection engine (used by every surface):**
1. **Enumerate every injection point** of a discovered request from observed data:
   query params, JSON body keys, form fields, headers, cookies, path segments,
   multipart fields, WS message fields, GraphQL args.
2. **For each point, run the FULL technique set** for each applicable class,
   breadth sourced from the PayloadsAllTheThings catalog + nuclei (all variants/
   WAF-bypasses), not a hand-picked few. Mutate for the detected WAF/tech.
3. **Detect injection context** (HTML/attr/JS/JSON/SQL/header) and pick
   context-appropriate payloads + the right oracle to confirm.
4. **One coherent battery per surface** (login, upload, cart, api, ws, …) that
   covers all points × all applicable classes — replacing the scattered half-probes.
5. **Adaptive:** which techniques fire, and in what order, is chosen from learned
   context (HypothesisEngine + AdaptivePlanner + payload effectiveness feedback),
   LLM-enhanced for novel variants. Hardcoded lists = cold-start fallback only.

This is the general form of points 1–5 below: apply it to EVERY class and EVERY
surface, not login/SQLi alone.

---

## 1. Browser learns the business logic (e.g. ecommerce: login→search→cart→address→payment)
- **WorkflowRecorder**: drive the app in the browser (or replay captured requests in order); record each step — request fired, state change (cart_id/total), page reached.
- **WorkflowLearner**: build a state machine — states (guest→logged-in→cart→address→payment→order), transitions (each API call + preconditions + carried values like price/qty), invariants (qty>0, amount==total, order.user==session.user). Ordering from data dependencies; LLM labels what each step means.
- **WorkflowViolationTester**: skip a step (pay w/o address), reorder, replay (coupon reuse), tamper carried values (negative qty, pay less), cross-user (checkout another user's cart). Covers all ecommerce logics, not one.

## 2. Stop hardcoding paths/field-names — use what we fetched; any surface (e.g. WebSocket) → test everything + LLM
- **SurfaceClassifier**: read actual crawl output / captured requests / JS bundles → extract real endpoints, params, form field-names, tokens. Classify by behavior/shape, NOT name (multipart⇒upload, numeric id⇒IDOR, url-valued param⇒SSRF, ws://⇒socket). A renamed `/x7f2` upload is still found.
- **Dispatcher**: for any discovered surface, run the full applicable exploit battery with its real params. LLM generates novel payloads/messages from the observed protocol.

## 3. Comprehension-first order (understand → recon → OSINT → per-surface tests)
- Reorder pipeline:
  - Phase 0: understand app (browser: features, workflows, roles).
  - Phase 1: map what each login reaches (run classifier per identity, diff = privesc/IDOR).
  - Phase 2: targeted recon + OSINT.
  - Phase 3: per-surface tests (login⇒SQLi/auth-bypass; authed⇒JWT/IDOR/privesc/admin-access; etc.).
  - Phase 4: business-logic abuse. Phase 5: chain/escalate.
- Minimal recon still bootstraps Phase 0 (can't understand what you can't see).

## 4. Attacker-depth for EVERY surface (not just WebSocket)
- Every surface follows: discover → understand → full battery → authz-per-identity → chain.
- Applies to: login, authed session, registration, password-reset, search, upload, cart/payment, REST API, GraphQL, WebSocket, admin, profile, file access, SSRF, tokens/JWT, redirects/OAuth, multi-tenant.
- Delivered by the SurfaceClassifier (find it) + Dispatcher (right battery) + per-surface batteries.

## 5. Think like a human brain; LLM adaptive, no hardcoding/assuming
- One loop drives everything: observe → learn (KnowledgeGraph = memory) → infer what's possible (HypothesisEngine) → decide next test (AdaptivePlanner) → execute → feedback → repeat.
- Nothing predefined: a technique fires because learned context implies it (e.g. url-fetch param ⇒ try SSRF/DNS-rebind).
- LLM is the brain: prompts/objectives assembled from learned state (not fixed) → adapts, reasons a step ahead, generates novel tests. Predefined lists only as cold-start fallback.

## 6. Payloads auto-synced from PayloadsAllTheThings — stop hand-maintaining them across modules

**Problem.** Many separate modules (cloud, attack-surface, fuzzing, injection, security…)
each hardcode their own payloads. Keeping every module updated with new exploits
daily is unmaintainable. PayloadsAllTheThings (swisskyrepo) already curates payloads
for every use case and updates them when new exploits are found.

**Key split:**
- **Payloads / variants = DATA** → live in the catalog, auto-synced from PATT (+nuclei). Never hand-maintained in code. New PATT payload = picked up on next sync, zero code change.
- **Methods / detection / how-to-exploit = LOGIC** → stays as code (or LLM reasons it). Procedural techniques (e.g. DNS-rebinding steps) become an oracle once.

**Solution:**
1. Migrate EVERY module to pull payloads from the catalog; delete inline payload lists (cold-start fallback only).
2. Wire true auto-sync: PATT + nuclei as git submodules; PayloadUpdater runs on scan start (done) + optional daily scheduled pull → re-ingest.
3. Modules become thin executors + oracles; payload breadth + daily freshness come entirely from PATT.
4. Result: payloads maintained by PATT (free, daily); logic maintained rarely by us.

**Already done:** full PATT repo ingested into catalog (3,294 payloads, all categories) + bundle + PayloadUpdater (git-pull + re-ingest).
**Left:** most modules still hardcode payloads (only upload/email migrated); real submodule + scheduled-pull auto-sync not wired.

## 7. Full PayloadsAllTheThings category coverage — every category is a required capability

The agent must be able to test EVERY PATT category when the matching surface is
present (classifier decides "present", §2). Required categories (all of them):

API Key Leaks · Account Takeover · Brute Force / Rate Limit · Business Logic
Errors · CORS Misconfiguration · CRLF Injection · CSS Injection · CSV Injection ·
CVE Exploits · Clickjacking · Client-Side Path Traversal · Command Injection ·
CSRF · DNS Rebinding · DOM Clobbering · Denial of Service · Dependency Confusion ·
Directory Traversal · Encoding Transformations · External Variable Modification ·
File Inclusion · Google Web Toolkit · GraphQL Injection · HTTP Parameter Pollution ·
Headless Browser · Hidden Parameters · Insecure Deserialization · IDOR ·
Insecure Management Interface · Insecure Randomness · Insecure Source Code Mgmt ·
JWT · Java RMI · LDAP Injection · LaTeX Injection · Mass Assignment · NoSQL
Injection · OAuth Misconfiguration · ORM Leak · Open Redirect · Prompt Injection ·
Prototype Pollution · Race Condition · Regular Expression (ReDoS) · Request
Smuggling · Reverse Proxy Misconfig · SAML Injection · SQL Injection · SSI
Injection · SSRF · SSTI · Tabnabbing · Type Juggling · Upload Insecure Files ·
Virtual Hosts · Web Cache Deception · Web Sockets · XPATH Injection · XS-Leak ·
XSLT Injection · XSS · XXE · Zip Slip.

**How each capability is delivered (same recipe per category):**
1. **Payloads** — from the auto-synced PATT catalog (§6). All categories already ingested; PATT updates flow in for free.
2. **Trigger** — SurfaceClassifier (§2) decides the category is applicable from observed signals (surface present), not from a guessed path.
3. **Inject** — unified context-aware engine (§0) places payloads into the REAL injection points.
4. **Confirm** — a per-category oracle validates the response (this is the LOGIC that stays as code / LLM, §6).
5. **Adapt/chain** — feedback + HypothesisEngine + ChainReasoner (§5).

**Honest status:**
- Payloads: ALL categories ingested (catalog). ✅
- Oracles/detection: only a subset exist (~SQLi/XSS/SSRF/XXE/SSTI/RCE/LFI/IDOR/JWT/
  CORS/redirect/upload/etc.); many categories (CSS injection, XSLT, LDAP, XPATH,
  SAML, Type Juggling, GWT, Zip Slip, ORM leak, Client-Side Path Traversal,
  Dependency Confusion, DOM Clobbering, XS-Leak, Reverse Proxy, Insecure Mgmt
  Interface, Insecure Randomness, ReDoS, Java RMI, Virtual Hosts, Prompt Injection…)
  have NO oracle yet → must add one per category.
- Executors: fragmented/half today → replaced by the unified engine (§0).

**To fully deliver:** add a per-category oracle for every category above + let the
classifier trigger each when its surface is present. Then "capability for X" =
payloads (PATT) + classifier trigger + inject + oracle + adapt — uniformly.

---
Honest split: structural parts (classifier, param derivation, workflow structure, batteries, loop wiring) buildable now, deterministic. Creative parts (semantic step-labeling, novel payload generation, "this looks abusable" leaps) need the LLM — blocked on Bedrock auth; switch on when authorized.

---
## BUILD STATUS (deterministic layers)
- **§0 unified injection engine** — BUILT: `UniversalProbeEngine.probe_point` injects at real points (query/json/form/header/cookie/path/multipart) with context detection; catalog breadth + WAF mutation. Wired via Dispatcher.
- **§2 SurfaceClassifier + Dispatcher** — BUILT: `core/recon/surface_classifier.py` (shape/signal-based, name-agnostic points + applicable classes), `core/orchestration/dispatcher.py` (surface×point×class battery; delegates depth classes). Wired in exploitation block.
- **§1 workflow** — BUILT: `core/workflow/{recorder,learner,violation_tester}.py` (value-tamper / replay / step-skip). Wired after business-logic probe.
- **§3 comprehension-first** — `ExecutionPhase.UNDERSTAND` + planner transition added.
- **§4 attacker-depth per surface** — delivered by classifier + dispatcher + per-class batteries + delegated depth probes.
- **§5 adaptive loop** — feedback via `catalog.record_outcome`; hypothesis/planner already wired. LLM layer Bedrock-gated (dormant).
- **§6 auto-sync** — `PayloadUpdater.maybe_update()` interval-guarded on scan start; git submodule/EFS checkout is infra. request_replayer/email/upload catalog-migrated (inline = cold-start fallback); other specialized probes keep logic-coupled vectors, breadth comes via the catalog+dispatcher.
- **§7 category coverage** — oracles added for LDAP/XPATH/XSLT/SSI/CSS/CSV/LaTeX/CRLF/HPP/TypeJuggling/ORM-leak/CS-path-traversal/ReDoS/PromptInjection/DOM-clobber/XS-Leak/SAML/ZipSlip/ReverseProxy/MgmtInterface/InsecureRandom/Tabnabbing/DNS-rebind + aliases (93 oracle keys). Catalog maps every category to a distinct class with fallback until bundle rebuild.

Contributor map + "add a category" recipe: `.agent/decisions.md`.

Remaining (LLM/infra): Bedrock enhancement layer (novel payloads, semantic step labels), PATT git submodule + scheduled pull in AWS, bundle rebuild with distinct §7 classes, browser-driven WorkflowRecorder (current recorder replays captured traffic).
