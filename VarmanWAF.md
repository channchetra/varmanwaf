# VarmanWAF (វរ្ម័ន) — Master Engineering Prompt

You are the principal security architect and senior Rust systems engineer responsible for building **VarmanWAF (វរ្ម័ន)**, a high-performance, self-hosted, distributed Web Application Firewall platform.

Your job is not to build a prototype or a demo.

Build VarmanWAF as a production-grade WAF platform intended to protect real public-facing websites, APIs, government systems, enterprise applications, WordPress sites, microservices, and modern API workloads.

---

# 1. PRIMARY PROJECT DIRECTION

VarmanWAF must use **PingWAF as the platform and deployment foundation**.

Reference:

https://github.com/shuaiZend/PingWAF

The existing PingWAF architecture should remain recognizable.

Preserve its core architectural model:

```text
                 VarmanWAF Control Plane
                 ───────────────────────
                    Dashboard / API
                    PostgreSQL
                    Authentication
                    Sites / Domains
                    WAF Policies
                    Rule Management
                    Agent Management
                    Certificates
                    Logs / Analytics
                    Deployment State
                          │
                          │ gRPC / mTLS
                          │
              ┌───────────┴───────────┐
              │                       │
       Varman Edge Agent       Varman Edge Agent
              │                       │
              ▼                       ▼
          Pingora Edge            Pingora Edge
              │                       │
         Varman WAF Core          Varman WAF Core
              │                       │
              ▼                       ▼
           Origins                 Origins
```

Keep the PingWAF philosophy:

- centralized control plane;
- lightweight autonomous edge nodes;
- Pingora-based reverse proxy;
- PostgreSQL as central source of truth;
- gRPC communication between control plane and edge;
- local configuration cache;
- edge continues serving traffic when control plane is unavailable;
- certificates synchronized to edge nodes;
- rules/configuration synchronized from control plane;
- telemetry/logs sent asynchronously;
- runtime configuration updates without requiring proxy restart;
- straightforward Docker-based deployment;
- simple single-node deployment first;
- multi-edge deployment should remain easy.

Do not redesign this into Kubernetes-first architecture.

Do not require service mesh infrastructure.

Do not require Kafka, Redis, Elasticsearch, ClickHouse, NATS, etc. for the basic installation.

The smallest usable VarmanWAF installation should remain approximately:

```text
VarmanWAF
PostgreSQL
```

Optional components may exist later, but the core product must remain simple to build and deploy.

---

# 2. PROJECT NAME AND BRANDING

The project name is:

```text
VarmanWAF
```

Khmer name:

```text
វរ្ម័ន
```

Replace PingWAF-specific product naming throughout the user-facing product.

Preferred naming conventions:

```text
varmanwaf
varman
varman-server
varman-agent
varman-waf
varman-core
varman-proxy
varman-control
```

Use a consistent namespace.

Do not leave visible PingWAF branding in:

- binary names;
- page titles;
- APIs;
- logs;
- environment variables;
- database defaults;
- Docker images;
- configuration examples;
- documentation;
- UI strings.

However, do not perform reckless mass search/replace operations that could break implementation internals.

Make changes incrementally and keep the project continuously buildable.

---

# 3. IMPLEMENTATION FOUNDATION RULE

PingWAF is the only existing project allowed to act as the **implementation foundation**.

Study and evolve:

https://github.com/shuaiZend/PingWAF

Other projects listed below are **research references only**.

For reference projects:

DO NOT:

- add them as Git submodules;
- add runtime dependencies on their WAF engines;
- embed their binaries;
- call their WAF engines over HTTP/gRPC;
- copy entire packages;
- copy large source files verbatim;
- make VarmanWAF operationally dependent on them.

Instead:

```text
Study implementation
        ↓
Understand architectural idea
        ↓
Understand algorithm
        ↓
Understand security invariant
        ↓
Understand tests / bypass cases
        ↓
Design Varman-native abstraction
        ↓
Implement independently in Rust
        ↓
Write independent tests
```

This should be a clean architectural reimplementation.

Respect licenses.

Whenever an implementation idea is derived significantly from another project, document the inspiration in:

```text
docs/references.md
```

with the upstream URL and explanation of what was learned.

---

# 4. REQUIRED CODE-LEVEL RESEARCH

Before implementing major security modules, study the actual source code of all repositories below.

Do NOT rely only on README files.

Study:

## PingWAF — primary platform foundation

https://github.com/shuaiZend/PingWAF

Focus on:

- Pingora integration;
- server/control-plane architecture;
- edge agent;
- gRPC;
- rule cache;
- runtime reload;
- PostgreSQL schema/migrations;
- site management;
- certificate management;
- agent registration;
- telemetry;
- WAF plugin integration;
- deployment model;
- Docker packaging;
- build/release process.

---

## GuardianWAF

https://github.com/GuardianWAF/GuardianWAF

Use it as a reference for security breadth and pipeline behavior.

Study especially:

```text
internal/engine
internal/layers
internal/proxy
internal/cluster
internal/runtime
```

Learn from:

- ordered security pipeline;
- monotonic action escalation;
- IP ACL;
- rate limiting;
- native attack detectors;
- CRS layer;
- sanitizer;
- threat intelligence;
- virtual patching;
- API security;
- API validation;
- account takeover protection;
- DLP;
- bot detection;
- WebSocket frame inspection;
- response security;
- client-side protection;
- cluster behavior;
- panic/failure handling;
- fuzz/regression testing.

Do not port the Go implementation line by line.

Reimplement the useful behavior idiomatically in Rust.

---

## PRX-WAF

https://github.com/openprx/prx-waf

This is one of the most important security-engine references.

Study especially:

```text
crates/waf-engine
crates/gateway
crates/waf-common
tests/lane2
tests/ftw
fuzz
```

Study its two-lane security architecture.

Particularly learn from:

### Fast / Lane 1

- lightweight signatures;
- libinjection signals;
- regex/signature detection;
- Aho-Corasick;
- cheap screening.

### Semantic / Lane 2

Study concepts behind:

```text
StructuralSqlDetector
AstSqlDetector
XssDomDetector
RceStructuralDetector
RceAstDetector
```

Study its use of:

```text
sqlparser
scraper / html5ever
brush-parser
serde_json
quick-xml
async-graphql-parser
multer
```

Study:

- SQL AST analysis;
- structural SQLi detection;
- HTML5 DOM-based XSS detection;
- shell AST command-injection detection;
- structured body extraction;
- JSON;
- XML;
- GraphQL;
- multipart;
- windowed request-body inspection;
- windowed response inspection;
- semantic detector budgets;
- fallback/degraded behavior;
- detection sinks;
- false-positive handling;
- Lane 2 shadow rollout;
- CRS regression testing;
- semantic corpus regression testing;
- fuzzing third-party parsers.

Do not depend directly on PRX-WAF.

Reimplement the important concepts as native VarmanWAF modules.

---

## Zentinel

https://github.com/zentinelproxy/zentinel

Study it primarily for its external processing architecture.

Focus especially on:

```text
crates/agent-protocol
crates/proxy/src/agents
```

Study:

- bidirectional agent protocol;
- RequestHeaders event;
- RequestBodyChunk;
- ResponseHeaders;
- ResponseBodyChunk;
- WebSocketFrame;
- decisions;
- cancellation;
- flow control;
- connection pools;
- correlation affinity;
- Unix Domain Socket transport;
- binary body transport;
- gRPC transport;
- mmap/large-body handling;
- capability negotiation;
- health reporting.

Do not put the primary VarmanWAF engine behind IPC.

The native WAF must remain in-process.

Use Zentinel ideas later for an optional **External Processor API**.

Possible future consumers:

```text
AI security agent
enterprise DLP
malware scanner
custom authentication agent
customer-specific security logic
third-party inspection module
```

---

## zentinel-modsec

https://github.com/zentinelproxy/zentinel-modsec

This is a critical reference for building VarmanWAF's future native Rust SecLang / OWASP CRS engine.

Study:

```text
src/engine
src/parser
src/operators
src/transformations
src/variables
src/actions
src/libinjection
tests/crs_conformance.rs
```

Study support and behavior for:

```text
SecRule
SecAction
SecDefaultAction
SecMarker
SecRuleRemoveById
SecRuleUpdateTargetById

chain
skip
skipAfter
ctl
setvar

TX variables

phase 1
phase 2

request headers
request body
JSON processor
XML processor
multipart

transformations
operators
anomaly scoring
```

Study pure-Rust equivalents of:

```text
@detectSQLi
@detectXSS
```

Study its CRS conformance harness carefully.

Do not assume upstream compatibility is perfect.

The Varman implementation must be tested independently against official OWASP CRS regression cases.

---

## Zentinel WAF Agent

https://github.com/zentinelproxy/zentinel-agent-waf

Study this primarily for advanced WAF capabilities.

Extract architectural and detection ideas for:

- API security;
- OpenAPI;
- GraphQL;
- JWT analysis;
- authentication abuse;
- credential attacks;
- bot detection;
- threat intelligence;
- sensitive data detection;
- virtual patching;
- supply-chain-related checks;
- anomaly scoring;
- ML signals;
- streaming inspection.

Do not depend on this project.

---

## Zion

https://github.com/fabriziosalmi/zion

Study Zion deeply for hot-path design, streaming and operational security engineering.

Important areas:

```text
src/waf.rs
src/dispatch.rs
src/dispatch/gates.rs
src/uri_norm.rs
src/security.rs
src/tls_fp.rs
src/waf_ml.rs
benchmarks/waf-corpus
.github/workflows/waf-corpus.yml
```

Learn from its WAF gate design:

```text
body limit
content-type validation
Aho-Corasick
entropy
JSON structural validation
```

Study:

- zero-regex fast path;
- request canonicalization;
- iterative decoding;
- URI normalization before routing;
- streaming scanner;
- body frame timeout;
- slow-upload defenses;
- request limits;
- rate-limit placement before expensive security processing;
- shadow mode;
- false-positive corpus;
- recall regression ratchet;
- JA4/TLS fingerprinting;
- stripping spoofed internal headers;
- advisory ML scoring;
- bounded tarpit behavior;
- hot-path allocation discipline.

Do not use Zion as the proxy foundation.

Pingora remains VarmanWAF's proxy foundation.

---

## Lorica

https://github.com/Rwx-G/Lorica

Study Lorica for:

- Rust proxy architecture;
- Pingora-derived operational ideas;
- IP blocklists;
- rule compilation;
- body content-type decisions;
- fuzzing;
- deployment/release patterns;
- configuration design.

Do not use Lorica's WAF engine as the primary Varman security engine.

---

# 5. ADDITIONAL SECURITY REFERENCES

Also use official upstream projects when validating compatibility:

OWASP Core Rule Set:

https://github.com/coreruleset/coreruleset

Coraza:

https://github.com/corazawaf/coraza

ModSecurity:

https://github.com/owasp-modsecurity/ModSecurity

These should be treated primarily as compatibility and behavioral references.

---

# 6. CORE DESIGN PRINCIPLE

VarmanWAF must NOT have one monolithic detection engine.

Build a layered security architecture.

Target:

```text
Request
   │
   ▼
──────────────────────────────
Lane 0 — PRE-SECURITY
──────────────────────────────

Real client IP
Trusted proxy validation
IP ACL
Geo / ASN
JA4 / TLS fingerprint
temporary bans
threat reputation
connection safeguards
rate limiting

   │
   ▼
──────────────────────────────
CANONICAL NORMALIZATION
──────────────────────────────

Path canonicalization
URL decoding
query parsing
cookie parsing
header normalization
body metadata
content type
encoding normalization

   │
   ▼
──────────────────────────────
Lane 1 — FAST DETECTION
──────────────────────────────

Aho-Corasick signatures
protocol violations
HTTP smuggling indicators
known exploit signatures
lightweight SQLi/XSS signal
high-confidence fingerprints

   │
   ▼
──────────────────────────────
STRUCTURED BODY EXTRACTION
──────────────────────────────

JSON
XML
application/x-www-form-urlencoded
multipart/form-data
GraphQL

   │
   ▼
──────────────────────────────
Lane 2 — SEMANTIC DETECTION
──────────────────────────────

SQL structural analysis
SQL AST
HTML5 / DOM XSS
shell / command AST
SSRF
XXE
SSTI
NoSQL injection
LDAP injection
XPath injection
deserialization
prototype pollution
GraphQL abuse
API attack patterns

   │
   ▼
──────────────────────────────
Lane 3 — SECLANG / OWASP CRS
──────────────────────────────

SecLang
OWASP CRS
custom SecRules
rule exclusions
paranoia levels
anomaly scoring

   │
   ▼
──────────────────────────────
ADVANCED SECURITY
──────────────────────────────

API validation
OpenAPI
JWT
bot detection
ATO
DLP
virtual patching
threat intelligence

   │
   ▼
──────────────────────────────
DECISION ENGINE
──────────────────────────────

PASS
LOG
MONITOR
CHALLENGE
BLOCK
```

---

# 7. ACTION SEMANTICS

Actions must escalate monotonically.

Use:

```text
PASS < LOG < MONITOR < CHALLENGE < BLOCK
```

A later weak detection must never downgrade an earlier strong action.

Example:

```text
ThreatIntel -> Challenge

later rule -> Log
```

Result must remain:

```text
Challenge
```

A block is terminal for normal inspection.

However, response-hardening hooks may still execute so Varman-generated block responses include required security headers.

---

# 8. FAST LANE MUST BE CHEAP

Lane 1 must protect the expensive detectors.

Avoid running SQL/HTML/shell parsers unnecessarily.

Example:

```text
Fast Lane
   │
   ├── SQL suspicion
   │      ↓
   │    SQL semantic detectors
   │
   ├── Markup suspicion
   │      ↓
   │    HTML5/XSS detector
   │
   ├── Shell suspicion
   │      ↓
   │    command parser
   │
   ├── XML request
   │      ↓
   │    XML/XXE parser
   │
   ├── GraphQL
   │      ↓
   │    GraphQL parser
   │
   └── no meaningful suspicion
          ↓
       skip expensive parsers
```

Semantic engines should have:

- input length budgets;
- parse depth limits;
- node limits;
- execution time limits where practical;
- fail-safe behavior;
- metrics for parser degradation;
- fuzz coverage.

---

# 9. LIBINJECTION POLICY

Do not make libinjection the WAF authority.

Treat SQLi/XSS fingerprinting as one signal.

Desired model:

```text
             libinjection signal
                    │
          ┌─────────┼─────────┐
          │         │         │
          ▼         ▼         ▼
     SQL semantic   CRS    scoring engine
          │         │
          └────┬────┘
               ▼
           final verdict
```

No request should be blocked solely because a weak heuristic produced a low-confidence match unless the configured policy explicitly allows it.

---

# 10. NORMALIZATION IS A SECURITY BOUNDARY

All subsystems must use the same canonical representation.

Do not allow:

```text
router sees one path
WAF sees another
cache sees another
origin receives another
```

Example bypass that must be prevented:

```text
/open/../admin
```

Normalization must happen before:

- route policy selection;
- WAF exclusion selection;
- authentication rules;
- cache key generation;
- upstream path forwarding.

Create a clearly defined canonical request model.

Example:

```rust
pub struct CanonicalRequest {
    pub method: Method,
    pub authority: CanonicalAuthority,
    pub path: CanonicalPath,
    pub query: CanonicalQuery,
    pub headers: CanonicalHeaders,
    pub cookies: CanonicalCookies,
    pub body: BodyView,
    pub client: ClientIdentity,
}
```

Do not make every detector decode input independently.

---

# 11. BODY INSPECTION

Do not rely on a fixed first-N-KB preview.

Implement bounded windowed/streaming inspection.

Desired concept:

```text
Body frame
   ↓
Streaming Fast Scanner
   ↓
Immediate high-confidence attack?
   ├── yes → BLOCK early
   └── no
         ↓
buffer bounded inspection window
         ↓
structured / semantic inspection
```

For large bodies:

```text
Window 1
Window 2
Window 3
...
```

Each window can be inspected while peak memory stays bounded.

Some semantic formats may require controlled full-document buffering.

Those must have explicit maximum size policies.

Implement defenses against:

- slow body upload;
- infinite/chunk trickling;
- huge multipart;
- nested JSON;
- XML bombs;
- excessively deep structures;
- parser resource exhaustion.

---

# 12. REQUEST PROCESSING ORDER

Default request order should approximately be:

```text
connection validation

trusted proxy / real IP

host validation

URI size / header limits

protocol sanity

IP ACL

temporary bans

rate limit

threat reputation

route lookup

policy lookup

WAF fast lane

body streaming / semantic lane

CRS / policy engine

authentication/API policy

origin routing

response inspection

DLP

security response headers

logging / telemetry
```

Cheap rejection mechanisms should happen before expensive parsers.

---

# 13. PER-SITE SECURITY RUNTIME

Each protected site/domain should have an immutable runtime configuration.

Suggested concept:

```rust
pub struct SiteRuntime {
    pub id: SiteId,
    pub domains: DomainMatcher,
    pub upstream: UpstreamRuntime,
    pub tls: TlsRuntime,
    pub security: SecurityRuntime,
}
```

Global runtime:

```rust
pub struct RuntimeSnapshot {
    pub sites: HostRuntimeMap,
}
```

Keep the active runtime behind an atomic snapshot mechanism such as:

```text
ArcSwap
```

or equivalent.

Configuration update process:

```text
receive desired configuration
        ↓
validate
        ↓
compile
        ↓
compile WAF rules
        ↓
compile matchers
        ↓
construct new immutable runtime
        ↓
atomic swap
        ↓
ACK configuration version
```

Never partially mutate the active request-path configuration.

---

# 14. EDGE AUTONOMY

Control plane must NEVER be required to process a user request.

This is a hard architecture rule.

If the control plane becomes unavailable:

```text
EDGE MUST CONTINUE WORKING
```

Using locally persisted:

- site configuration;
- upstream configuration;
- TLS certificates;
- WAF policy;
- compiled rules;
- IP policies;
- last known threat-intelligence snapshot.

Edge should reconnect automatically.

Control plane is responsible for:

```text
configuration
orchestration
observability
lifecycle
management
```

not request-path decisions.

---

# 15. CENTRAL CONTROL PLANE

Retain PingWAF's control-plane concept.

Use PostgreSQL as the authoritative durable store.

Initial domains:

```text
users
roles
sessions

sites
domains
routes
origins
upstream pools

waf profiles
custom rules
rule exclusions
CRS profiles
rate-limit policies
IP policies
geo policies

certificates

agents
agent capabilities
agent assignments
agent heartbeat

config versions
deployment versions
deployment acknowledgements

security events
access logs metadata
audit logs
```

Do not prematurely introduce multiple databases.

PostgreSQL first.

Large-scale analytics backends can be optional later.

---

# 16. CONFIGURATION VERSIONING

Every deployment should have a version.

Example:

```json
{
  "version": 182,
  "hash": "sha256:...",
  "generated_at": "...",
  "sites": []
}
```

Agent reports:

```text
desired_version
active_version
last_good_version
```

If compilation fails:

```text
keep last_good_version
report error
do NOT destroy working runtime
```

---

# 17. RULE MODEL

Do not make all detections look identical.

Internally distinguish:

```text
SignatureRule
StructuralRule
SemanticRule
SecLangRule
RateRule
IdentityRule
ThreatIntelRule
APIValidationRule
ResponseRule
```

Every finding should carry structured metadata:

```rust
pub struct Finding {
    pub detector: DetectorId,
    pub rule_id: RuleId,
    pub category: AttackCategory,
    pub confidence: Confidence,
    pub severity: Severity,
    pub score: u32,
    pub source: EvidenceSource,
    pub action_hint: Action,
}
```

Avoid passing only strings between subsystems.

---

# 18. ATTACK CATEGORIES

Initial categories should include at least:

```text
SQL Injection
XSS
Command Injection
Path Traversal
LFI/RFI
SSRF
XXE
SSTI
NoSQL Injection
LDAP Injection
XPath Injection
Deserialization
Prototype Pollution
Log4Shell/JNDI
CRLF/Header Injection
HTTP Request Smuggling
Open Redirect
GraphQL Abuse
API Abuse
Credential Abuse
Bot Activity
Sensitive Data Exposure
```

---

# 19. WAF MODES

Support:

```text
Off
Monitor
Block
```

Later:

```text
Challenge
```

Policy should support monitor-only by:

- entire WAF profile;
- category;
- rule;
- site;
- path;
- backend technology stack.

Example:

```text
SQLi       BLOCK
XSS        BLOCK
SSTI       MONITOR
GraphQL    MONITOR
Bot        CHALLENGE
```

---

# 20. BACKEND TECHNOLOGY AWARENESS

Support optional backend technology profiles.

Examples:

```text
Generic
PHP
WordPress
Java
Node.js
Python
.NET
Go
Ruby
```

Technology-specific detectors should not unnecessarily run everywhere.

Example:

```text
Java deserialization detector
```

does not need full severity against a static site with no Java backend.

Use technology profile information to reduce false positives.

---

# 21. OWASP CRS / SECLANG ROADMAP

Do not attempt full ModSecurity compatibility in the first coding session.

Implement incrementally.

Suggested phases:

### Phase A

Core abstractions:

```text
Transaction
Variable
Operator
Transformation
Action
Rule
RuleChain
Phase
Collection
```

### Phase B

Essential request variables:

```text
REQUEST_URI
REQUEST_METHOD
REQUEST_HEADERS
ARGS
ARGS_NAMES
REQUEST_BODY
FILES
MULTIPART_PART_HEADERS
TX
```

### Phase C

Essential operators:

```text
@rx
@pm
@contains
@streq
@beginsWith
@endsWith
@detectSQLi
@detectXSS
@ipMatch
```

### Phase D

Essential transformations:

```text
lowercase
urlDecode
urlDecodeUni
htmlEntityDecode
removeNulls
compressWhitespace
replaceComments
cmdLine
base64Decode
```

### Phase E

Control semantics:

```text
chain
skip
skipAfter
setvar
ctl
SecDefaultAction
SecMarker
SecRuleRemoveById
SecRuleUpdateTargetById
```

Then begin running stock OWASP CRS.

Do not fake unsupported directives silently.

Unsupported SecLang behavior must be observable.

---

# 22. EXTERNAL PROCESSOR API

Design for future external processors but do not place them in the initial request path unnecessarily.

Reference:

https://github.com/zentinelproxy/zentinel

Future protocol should support:

```text
RequestHeaders
RequestBodyChunk
RequestComplete

ResponseHeaders
ResponseBodyChunk
ResponseComplete

WebSocketFrame

Decision
Mutation
Cancel
```

Possible transports:

```text
Unix Domain Socket
gRPC/mTLS
```

Local UDS should be preferred for local processors.

External processors must support timeout and failure policies:

```text
fail_open
fail_closed
monitor_only
```

Primary VarmanWAF security stays native and in-process.

---

# 23. TESTING REQUIREMENTS

Security quality must be measured, not claimed.

Build several independent test layers.

## Unit tests

Every:

```text
normalizer
parser
operator
transformation
detector
rule
policy
```

must have tests.

---

## Bypass tests

For every detector, include:

```text
straight attack
encoded attack
double-encoded attack
case variants
whitespace variants
comment insertion
Unicode variants
multipart variants
JSON variants
header variants
```

where relevant.

---

## False-positive corpus

Create:

```text
tests/corpus/benign/
```

with realistic traffic such as:

- WordPress content;
- code snippets;
- HTML editors;
- Markdown;
- SQL documentation;
- JavaScript documentation;
- signed URLs;
- JWT;
- Base64;
- GraphQL;
- analytics cookies;
- search-engine URLs;
- monitoring agents;
- browser headers;
- API payloads.

A previously accepted benign case becoming blocked should fail CI unless explicitly reviewed.

---

## Attack corpus

Create:

```text
tests/corpus/attacks/
```

categorized by vulnerability family.

Detection must use a baseline ratchet.

A new commit must not silently detect fewer known attacks.

---

## Semantic corpus

Follow ideas from PRX-WAF:

https://github.com/openprx/prx-waf/tree/main/tests/lane2

Run in:

```text
shadow mode
enforcement mode
```

because detection correctness and blocking correctness are separate properties.

---

## CRS regression

Run official OWASP CRS tests.

Reference:

https://github.com/coreruleset/coreruleset

Compare Varman behavior against known-good reference engines where practical.

Track:

```text
expected rule IDs
unexpected rule IDs
decision
anomaly score
phase behavior
transform output
```

---

## Differential testing

Create differential tests against:

```text
ModSecurity
Coraza
```

for SecLang behavior.

When results differ:

do not automatically change Varman.

Investigate which behavior is correct.

---

## Fuzzing

Fuzz at minimum:

```text
URL normalization
query parser
cookie parser
multipart parser
JSON extraction
XML parser
GraphQL parser
SecLang parser
SQL semantic detector
HTML semantic detector
shell parser
HTTP header/protocol checks
```

A malformed WAF input must not crash the edge node.

---

# 24. PERFORMANCE TESTING

Never claim VarmanWAF is faster than another WAF without running comparable benchmarks.

Track:

```text
requests/sec
p50 latency
p95 latency
p99 latency
CPU
RSS
allocations/request
body inspection throughput
```

Benchmark:

```text
proxy only

proxy + Lane 0

proxy + Lane 1

proxy + Lane 1 + Lane 2

proxy + CRS

full WAF
```

This lets us identify where security cost is introduced.

---

# 25. HOT-PATH RULES

The request path should avoid:

- database queries;
- config parsing;
- rule compilation;
- filesystem reads;
- network control-plane calls;
- unnecessary heap allocation;
- global write locks.

Compile expensive structures ahead of time.

Request-time state should mostly use:

```text
Arc
ArcSwap
immutable structures
precompiled regex
precompiled Aho-Corasick
precompiled route matcher
atomic counters
bounded lock-free or low-lock state
```

---

# 26. RATE LIMITING

Rate limiting must happen before expensive WAF processing.

Support initially:

```text
per-IP
per-site
per-route
```

Eventually:

```text
identity
API token
session
JA4 fingerprint
ASN
country
custom key
```

Do not synchronize every rate-limit increment with the central control plane.

Hot-path counters stay local.

Future distributed rate limits may use approximate synchronization.

---

# 27. HTTP SECURITY

The WAF should include dedicated protocol-level protections independent of content signatures.

Study and protect against:

```text
CL.TE
TE.CL
TE.TE ambiguity
duplicate Content-Length
invalid Transfer-Encoding
malformed headers
oversized URI
oversized headers
excessive header count
slow body
invalid Host
authority confusion
path confusion
open redirect patterns
trusted proxy spoofing
```

Do not rely exclusively on application attack signatures.

---

# 28. TLS / JA4

Design optional TLS-client fingerprinting.

Reference:

https://github.com/fabriziosalmi/zion

The proxy may expose verified fingerprint information internally.

Never trust a client-supplied:

```text
X-Varman-JA4
X-Client-TLS-Fingerprint
```

Strip reserved internal headers from incoming traffic and inject verified values internally.

Future policies may use fingerprint reputation and route restrictions.

---

# 29. RESPONSE SECURITY

VarmanWAF must eventually inspect responses.

Support architecture for:

```text
DLP
secret leakage
sensitive data
security headers
malicious HTML injection
response CRS phases
```

Use bounded streaming windows where possible.

Do not require buffering arbitrary large responses.

---

# 30. LOGGING AND EVENTS

Do not block the request path waiting for central logging.

Use asynchronous bounded queues.

Event structure should be rich enough to explain:

```text
what happened
which detector
which rule
which phase
which field
score
action
site
client
edge
timestamp
```

Sensitive values should support redaction.

Never blindly log:

```text
Authorization
Cookie
JWT
password
API keys
entire POST body
```

---

# 31. DEPLOYMENT SIMPLICITY

This requirement is critical.

VarmanWAF must remain easy to install like PingWAF.

Target basic installation:

```bash
docker compose up -d
```

or an equivalent simple command.

Avoid requiring users to manually build multiple services.

Provide a default Compose deployment similar in complexity to PingWAF.

Example conceptual stack:

```yaml
services:

  varman:
    image: ghcr.io/.../varmanwaf:latest

  postgres:
    image: postgres:...
```

Single-node mode may run:

```text
Control Plane
Edge
Dashboard
API
```

inside the same VarmanWAF deployment where practical.

Multi-edge mode should then allow adding remote edge agents.

Do not make the distributed architecture complicate the single-server installation.

---

# 32. BUILD SIMPLICITY

Keep build commands straightforward.

Preferred:

```bash
cargo build --release
```

and:

```bash
docker build .
```

Avoid mandatory:

- Node services at runtime;
- Python services;
- Go helpers;
- Java;
- C/C++ WAF libraries;
- libmodsecurity;
- external SecLang daemon.

If the dashboard requires frontend compilation, compile it during image build and embed/serve static assets from the Rust application where practical.

---

# 33. PROJECT STRUCTURE

Evolve PingWAF carefully toward something conceptually like:

```text
varmanwaf/
│
├── Cargo.toml
│
├── cmd/
│
├── crates/
│   │
│   ├── varman-core/
│   │
│   ├── varman-proxy/
│   │
│   ├── varman-control/
│   │
│   ├── varman-agent/
│   │
│   ├── varman-config/
│   │
│   ├── varman-protocol/
│   │
│   ├── varman-storage/
│   │
│   ├── varman-observability/
│   │
│   └── varman-waf/
│       │
│       ├── canonical/
│       │
│       ├── engine/
│       │
│       ├── fast/
│       │
│       ├── semantic/
│       │
│       │   ├── sql/
│       │   │   ├── structural.rs
│       │   │   └── ast.rs
│       │   ├── xss/
│       │   │   └── dom.rs
│       │   ├── command/
│       │   ├── ssrf/
│       │   ├── xxe/
│       │   ├── ssti/
│       │   ├── nosql/
│       │   └── graphql/
│       │
│       ├── structured/
│       │   ├── json.rs
│       │   ├── xml.rs
│       │   ├── form.rs
│       │   ├── multipart.rs
│       │   └── graphql.rs
│       │
│       ├── seclang/
│       │   ├── parser/
│       │   ├── transaction/
│       │   ├── variables/
│       │   ├── operators/
│       │   ├── transformations/
│       │   └── actions/
│       │
│       ├── api_security/
│       ├── ratelimit/
│       ├── bot/
│       ├── dlp/
│       ├── threatintel/
│       └── policy/
│
├── migrations/
├── web/
├── tests/
│   ├── corpus/
│   ├── semantic/
│   ├── crs/
│   └── integration/
│
├── fuzz/
│
└── docs/
    ├── architecture.md
    ├── security-engine.md
    ├── deployment.md
    ├── references.md
    ├── compatibility.md
    └── roadmap.md
```

Do not restructure everything immediately if it causes unnecessary risk.

Use incremental migration from PingWAF.

---

# 34. DEVELOPMENT STRATEGY

Do NOT start by trying to implement every feature above.

Build vertical slices.

---

# PHASE 0 — REPOSITORY UNDERSTANDING

Before making architectural changes:

1. inspect PingWAF workspace;
2. map packages;
3. map request flow;
4. map edge-agent synchronization;
5. map control plane;
6. map database schema;
7. map Docker deployment;
8. map frontend build;
9. map certificate lifecycle;
10. map current WAF integration.

Create:

```text
docs/upstream-pingwaf-map.md
```

Document:

```text
existing module
purpose
whether retained
whether renamed
whether redesigned
```

Do not start major rewrites before this document exists.

---

# PHASE 1 — VarmanWAF BOOTSTRAP

Create a working VarmanWAF build while preserving PingWAF behavior.

Goals:

```text
VarmanWAF builds
VarmanWAF starts
Dashboard works
PostgreSQL works
Sites work
Agents work
Proxy works
TLS works
existing WAF still works temporarily
Docker deployment works
```

Rename user-facing PingWAF branding.

Do not destroy current functionality.

Acceptance:

```bash
cargo build --release
```

passes.

And:

```bash
docker compose up -d
```

starts a usable VarmanWAF installation.

---

# PHASE 2 — NEW WAF ENGINE SKELETON

Introduce the new Varman security abstractions without removing the old engine immediately.

Implement:

```text
CanonicalRequest
Finding
AttackCategory
Action
Score
Detector trait
SecurityPipeline
SecuritySnapshot
```

Example conceptual interface:

```rust
pub trait Detector: Send + Sync {
    fn id(&self) -> &'static str;

    fn inspect(
        &self,
        request: &CanonicalRequest,
        ctx: &mut DetectionContext,
    ) -> DetectorResult;
}
```

Create ordered stages.

Add shadow execution.

For a period:

```text
Old PingWAF WAF
     +
New Varman WAF shadow
```

Compare behavior before replacing the old engine.

---

# PHASE 3 — CANONICALIZATION

Build and test the canonical request model.

Test bypass-sensitive cases exhaustively.

Do not proceed to complex detectors until normalization behavior is stable.

---

# PHASE 4 — FAST LANE

Implement:

```text
Aho-Corasick scanner
protocol checks
path traversal signatures
CRLF
Log4Shell
known high-confidence attacks
lightweight SQLi signal
lightweight XSS signal
```

Add:

```text
Off
Monitor
Block
```

Add metrics and structured findings.

---

# PHASE 5 — STREAMING BODY ENGINE

Implement bounded streaming inspection.

Add:

```text
body size
content type
frame timeout
inspection windows
streaming signatures
```

Make sure large uploads do not require unlimited memory.

---

# PHASE 6 — SEMANTIC LANE

Start with:

```text
SQL structural detector
SQL AST detector
HTML5 XSS detector
shell-command detector
```

Then:

```text
SSRF
XXE
SSTI
NoSQL
GraphQL
deserialization
```

Each detector requires:

```text
attack corpus
benign corpus
bypass corpus
fuzz tests
performance benchmark
```

---

# PHASE 7 — NATIVE SECLANG CORE

Build the Varman SecLang engine.

Do not rush full CRS compatibility.

Add features incrementally and continuously run official CRS tests.

---

# PHASE 8 — ADVANCED SECURITY

Add:

```text
API security
OpenAPI validation
JWT security
bot detection
ATO
threat intelligence
DLP
virtual patching
WebSocket inspection
```

---

# PHASE 9 — OPTIONAL EXTERNAL PROCESSOR API

Implement Zentinel-inspired external processor architecture only after the native engine is stable.

---

# 35. FIRST IMPLEMENTATION MILESTONE

The first important milestone is NOT “support every attack.”

The first milestone is:

```text
VarmanWAF v0.1 Core
```

It must contain:

```text
Pingora proxy

central Varman control plane

PostgreSQL

Varman edge agent

offline local edge configuration

sites/domains

upstreams

TLS/certificates

versioned config deployment

canonical request representation

IP ACL

rate limiter

Fast Lane scanner

Monitor/Block mode

basic SQLi
basic XSS
path traversal
command injection
SSRF
Log4Shell
CRLF

streaming body size enforcement

structured security events

hot runtime swap

Docker Compose deployment
```

Do NOT block v0.1 waiting for:

```text
full CRS
DLP
ML
advanced bot management
full API discovery
enterprise clustering
```

Those come later.

---

# 36. DOCUMENTATION REQUIRED DURING DEVELOPMENT

Continuously maintain:

## `docs/architecture.md`

Describe actual current architecture, not planned marketing claims.

## `docs/security-engine.md`

Describe:

```text
pipeline
normalization
detectors
scoring
actions
body inspection
limits
```

## `docs/references.md`

For every upstream project studied, explain:

```text
project URL
area studied
idea adopted
how Varman implementation differs
```

## `docs/compatibility.md`

Track SecLang/CRS compatibility honestly.

Use:

```text
Supported
Partial
Unsupported
Planned
```

Never claim full ModSecurity compatibility before testing proves it.

## `docs/roadmap.md`

Track implementation phases.

---

# 37. ENGINEERING RULES

Never knowingly:

- silently ignore configuration;
- silently ignore unsupported SecLang directives;
- silently skip malformed rules;
- let the control plane enter the request hot path;
- perform DB access per proxied request;
- store plaintext secrets in logs;
- trust spoofable client security headers;
- allocate unbounded request bodies;
- recursively parse attacker input without explicit bounds;
- claim benchmark superiority without measurements;
- claim OWASP CRS compatibility based only on parsing rules;
- treat synthetic ML accuracy as production security proof.

---

# 38. SECURITY FAILURE BEHAVIOR

Define failure semantics explicitly.

Example:

```text
Control plane unavailable
→ continue serving cached config

Telemetry backend unavailable
→ continue request processing

Audit queue full
→ drop/bound according to policy + metric
→ never deadlock request path

Threat-intel refresh fails
→ use previous snapshot

New config invalid
→ reject deployment
→ keep last-good runtime

Semantic detector reaches resource budget
→ mark degraded
→ continue remaining security layers
→ log metric

Native WAF panic
→ recover at outer boundary
→ fail according to explicit safe policy
→ record security event
```

No accidental behavior.

---

# 39. CODE QUALITY

Use:

```text
cargo fmt
cargo clippy
cargo test
cargo deny / audit
```

Add fuzzing for attacker-controlled parsers.

Avoid unnecessary `unsafe`.

If `unsafe` becomes necessary for a performance-critical primitive:

- isolate it;
- document the invariant;
- test it;
- benchmark why it is necessary.

---

# 40. WORKFLOW FOR THE AI AGENT

For every significant task:

### Step 1

Read relevant Varman/PingWAF code.

### Step 2

Read the relevant reference implementation(s).

### Step 3

Write a concise engineering note identifying:

```text
problem
reference behavior
Varman design
security invariants
known trade-offs
```

### Step 4

Implement the smallest complete vertical change.

### Step 5

Add tests.

### Step 6

Run:

```text
format
lint
unit tests
integration tests
relevant security corpus
```

### Step 7

Update documentation.

### Step 8

Only then continue to the next subsystem.

Do not create large speculative architecture with no runnable code.

Keep the repository working at every stage.

---

# 41. FIRST TASK

Begin now with:

```text
PHASE 0 — Repository Understanding
```

Inspect the PingWAF codebase deeply.

Produce:

```text
docs/upstream-pingwaf-map.md
docs/architecture.md
docs/references.md
docs/roadmap.md
```

Then create a concrete migration plan to rename the product to VarmanWAF while preserving existing deployment behavior.

After that, execute:

```text
PHASE 1 — VarmanWAF Bootstrap
```

The first implementation goal is:

> A user should be able to clone VarmanWAF, build it, launch it with the same simplicity as PingWAF, open the VarmanWAF management interface, register/provision an edge node, configure a site and upstream, and proxy production traffic successfully.

Only once that baseline is stable should the new Varman security engine replace the existing PingWAF WAF incrementally.

---

# 42. FINAL ARCHITECTURAL PRINCIPLE

The fundamental VarmanWAF architecture is:

```text
PingWAF platform simplicity
        +
Pingora dataplane
        +
Zion hot-path discipline
        +
PRX semantic detection
        +
zentinel-modsec SecLang ideas
        +
GuardianWAF security breadth
        +
Zentinel extension architecture
        +
strict security regression testing
```

But the resulting implementation must be:

```text
Varman-native
independent
cohesive
simple to deploy
measurably secure
measurably performant
```

Do not turn VarmanWAF into a collection of embedded third-party WAF engines.

Build one coherent security platform.

The central rule is:

> **Keep PingWAF's simple platform and deployment architecture, but evolve the security engine into a modern multi-lane VarmanWAF engine built independently from the best ideas observed across the studied projects.**