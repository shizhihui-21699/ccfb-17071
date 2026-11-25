# credwatch

Detects temporary cloud credentials being used **outside the workload they were
issued to**, and contains them before the attacker finishes tiering the bucket.

It consumes provider audit logs continuously, resolves each call's source
address through a live inventory of the account's network, compares that
attribution against the issuance record for the credential, and — when the
evidence holds — revokes the session or narrows the principal automatically.

```
audit log ──▶ decode ──▶ attribute ──▶ bind to issuance scope ──▶ score ──▶ decide ──▶ revoke / alert
             (trusted   (IP is a        (is this origin            (hard +    (conclusive
              vs        representation,  legitimate for            soft)      & above
              untrusted) not identity)    this credential?)                   threshold)
```

## The problem this actually solves

A leaked instance credential is not detectable by "strange IP" rules, because
legitimate calls also come from strange IPs: NAT gateways, forward proxies, VPC
endpoints, and the cloud provider's own services calling on the workload's
behalf. An audit address is a *representation*, never an *identity*. The whole
design follows from that one sentence:

- The same instance can surface as its private IP, the subnet's NAT EIP, a VPC
  endpoint ENI, or a provider-owned range. Each is legitimate for some
  workloads and wrong for others.
- Containers share credentials per *fleet*, not per node. Serverless functions
  either share a VPC NAT or leave from provider ranges that identify nothing.
- Audit logs are minutes late. Detection is always retrospective, so **how late**
  is part of the verdict, not an implementation detail.

So the detector never asks *"is this address good?"*. It asks *"which workload
could have produced traffic from this address, how strong is that inference, and
does it agree with what this credential was issued for?"*

## What it decides, and how

Evidence is split into two classes that are **not** interchangeable:

**Hard evidence** — does not depend on client-supplied fields:
- network binding mismatch: the origin resolves to a different instance, fleet,
  or outside every known path;
- the credential is a canary (no legitimate holder exists);
- the source is blocklisted;
- the credential was expired when used;
- the same session key used from two *exact* origins inside a window.

**Soft evidence** — adds urgency, never carries a verdict alone, because an
attacker can forge it and normal workloads produce it:
- action outside the workload's learned baseline;
- a new user agent for the key (capped, and explicitly `trusted: false`).

Verdicts: `allow` < `watch` < `alert` < `revoke`. `revoke` requires both a score
threshold **and** conclusive evidence (`AutoRevokeRequiresConclusive`), so a
stale or missing inventory can never break production by auto-revoking.

### Binding classes

`attrib.Bind` is the heart of it. Each origin kind maps to a binding:

| origin | binding | meaning |
|---|---|---|
| the scope's own instance / pod / function ENI | `bound_direct` | exactly who it should be |
| the scope's NAT gateway | `bound_shared_egress` | inside the scope, but a whole subnet shares it — ambiguous |
| a registered proxy the scope trusts | `bound_via_proxy` | ambiguous but expected |
| VPC endpoint ENI | `bound_shared_egress` | proves "inside the VPC", not "this instance" |
| provider range + `invokedBy` | `bound_service` | the cloud called the cloud; no client exists |
| provider-owned range (serverless, no VPC) | `bound_provider_egress` | tolerated and explicitly unattributable |
| another known instance in the account | `foreign_principal` | lateral movement |
| outside every known path | `external` | the attack shape |
| scope has no network expectation (role/user) | `bound_unanchored` | cannot condemn or clear |

## The hard cases

**Shared egress and serverless ambiguity.** When the address is a NAT or a
provider range, the network cannot answer. The independent fix is
`internal/attest`: a small agent on the workload HMAC-signs "I used key K at
time T", and the engine treats a matching claim as *corroboration only*. A
missing claim never proves theft (agents deploy late, get blocked). Critically,
a matching claim clears the *network* doubt and nothing else — an SSRF that
makes the instance call the API from itself produces a perfect claim, so the
behavioural evidence must survive it. A claim naming a *different* workload is
strong evidence and flips the binding to `foreign_principal`.

**Container and serverless models.** Credential records carry a `Scope` with a
kind (`instance`, `fleet`, `function`, `role`, `user`) and a key precision
(`exact_session` vs `principal`). An EKS pod's key is scoped to the fleet and
its pod CIDR; concurrent use across pods is normal, concurrency evidence is
suppressed. A GCP service account or Azure managed identity has no per-session
key at all — every instance sharing it looks identical in the logs, so the
binding is principal-scoped and the engine subtracts a confidence penalty
rather than pretending it has session precision. Revocation also differs:
there is no session to kill for a bearer token, so the response generates a
source-address-conditioned deny policy instead.

**Audit lag.** `LagSeconds` is recorded on every incident. Lag ≥ `lag_warn` and
`lag_crit` adds urgency, and `recommend()` tells the operator to review the
whole lifetime of the key, not just the alerting call — because by the time we
see an event, revocation may be containment rather than prevention.

**Late and out-of-order delivery.** The processor treats event time as
authoritative for windowing, dedupes by event ID (late logs replay heavily), and
suppresses repeat pages per credential while still actioning containment —
the credential is compromised even if we do not page twice.

## Layout

```
cmd/credwatch/          serve | simulate
internal/model/         canonical types: Event, Credential, Scope, Origin, Incident
internal/audit/         CloudTrail / Azure / GCP decoders; decides trusted vs untrusted fields
internal/inventory/     address → workload; snapshot store with explicit staleness
internal/attrib/        origin resolution + scope binding (the core inference)
internal/credstore/     issuance records, key/session resolution, actioned set
internal/attest/        HMAC workload corroboration channel
internal/engine/        evidence scoring, verdicts, lag handling, walk-up windows
internal/response/      session revoke / principal deny / quarantine, dry-run + circuit breaker
internal/pipeline/      decode → detect → alert → act; dedupe, per-key serialization
internal/server/        HTTP ingest, inventory, attest, health, metrics, simulate
internal/scenario/      the 14 evaluation cases (also the CLI's self-test)
configs/                example config, inventory, credential, event
```

## Run

```sh
go run ./cmd/credwatch simulate -v        # run all 14 cases, print every decision
go build -o credwatch ./cmd/credwatch
./credwatch serve -config configs/example.json -inventory configs/inventory.example.json
```

Then feed a credential and a call:

```sh
curl -XPOST localhost:8080/v1/credentials -d @configs/credential.example.json
curl -XPOST 'localhost:8080/v1/audit?provider=aws' -d @configs/event.example.json
curl localhost:8080/v1/incidents
```

`/v1/simulate` runs records through a fresh detector sharing inventory and
credentials, with an optional `now`, so you can replay a historical attack and
measure exactly what would have fired and when.

## Endpoints

| path | method | purpose |
|---|---|---|
| `/v1/audit?provider=aws\|azure\|gcp` | POST | raw audit record(s): object, array, envelope or NDJSON |
| `/v1/credentials` | POST | issuance records from your STS/identity poller |
| `/v1/attest` | POST | signed workload claims |
| `/v1/inventory` | POST/GET | refresh / inspect the network snapshot |
| `/v1/incidents` | GET | recent incidents, newest first |
| `/v1/simulate` | POST | what-if evaluation |
| `/healthz` | GET | liveness + inventory staleness (503 when unsafe) |
| `/metrics` | GET | counters incl. `max_lag_seconds` |

## Defaults that matter

- **`response.dry_run: true`.** Containment is logged, including the exact
  deny-policy document, but nothing is mutated until you turn it off. Verify
  against your environment before enabling.
- **`auto_revoke_requires_conclusive: true`.** A stale/missing inventory caps
  verdicts at `alert`.
- **Inventory staleness is explicit.** `/healthz` returns 503 when the snapshot
  is older than `inventory.max_age`; a detector with no inventory cannot tell
  "external" from "unmodelled", and says so in every reason string.

## What is deliberately *not* here

- No provider SDK calls. `response.Revoker` and the inventory refresh are
  interfaces; the bundled `MemoryRevoker` and snapshot file are for evaluation.
  Wiring real `sts:RevokeSession` / IAM deny / Azure / GCP requires credentials
  and account-specific policy that should be reviewed, not defaulted.
- No baseline *learning* pipeline. `baseline_actions` is supplied by the
  issuance feed; an empty baseline means "no baseline", not "everything is
  normal".
- No claim that shared-NAT attribution is exact. It is `ambiguous` in the type
  system and needs attestation to become `direct`.

## Tests

```sh
go test ./...          # incl. the false positives that shaped the design
go test -race ./...
```

The engine tests lock in behaviour found the hard way during development:
concurrency evidence must ignore unresolved origins (one stolen call must not
make every later legitimate call look concurrent), expired-but-known credentials
must resolve rather than vanish, and service-forwarded calls must not be scored
on client behaviour.
