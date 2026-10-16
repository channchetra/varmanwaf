# Server Sizing & Capacity

What to provision, what the numbers actually mean, and how to measure your own
hardware. All figures come from the published 1.0.0 benchmark
([`benchmarks/v1.0.0.md`](./benchmarks/v1.0.0.md)) plus live database
measurements; the methodology and caveats are stated, not implied.

## 1. What was measured, and on what

| | |
| --- | --- |
| Machine | Intel i7-12700 (12 cores / 20 threads), 31.7 GB RAM, Windows + Docker Desktop |
| Container | `varman` all-in-one (control plane + edge + Pingora), **no CPU or memory limits** |
| Origin | `nginx:alpine` on the same Docker network |
| Load generator | Node.js 24, keep-alive, single process |

Headline results (pass-through `GET /`, full WAF + proxy):

| Concurrency | Throughput | p50 | p95 | p99 |
| --- | --- | --- | --- | --- |
| 1 | 1,450 req/s | 0.62 ms | 0.91 ms | 1.49 ms |
| 25 | 5,835 req/s | 4.10 ms | 6.20 ms | 8.53 ms |
| 100 | 5,485 req/s | 16.96 ms | 22.56 ms | 71.28 ms |

WAF block verdicts cost **~1 ms** on top of the allow path (p50 0.85-1.17 ms)
and skip the upstream entirely; the auto-block refusal lane serves
**~9.8k req/s** because it never runs the engine.

**Honest reading**: these are relative numbers from a shared desktop with an
untuned Docker network and a single-process generator. A tuned Linux server
with a real network path typically does better per core; the *shape* (engine
cost ≈ 1 ms, refusal ≈ free, throughput plateaus when the generator or the
network becomes the bottleneck) is what carries over.

## 2. What consumes resources

| Resource | Driver | Lever |
| --- | --- | --- |
| CPU | requests/s × engine work; body inspection is the expensive part | paranoia level, advanced mode, body inspection budgets, per-rule modes |
| Memory | per-site runtime snapshots, connection state, caches | number of sites, upstream connection pools, cache quota |
| Edge disk | cache objects + agent state | per-site cache quota, cache TTLs |
| PostgreSQL disk | access logs + security events + config history | retention, sampling, Elasticsearch offload |
| PostgreSQL CPU | control-plane API traffic, event ingest, analytics queries | retention, ES offload, bigger instance |

### Real storage growth (measured on the live deployment)

| Data | Rows | Size | Per row |
| --- | --- | --- | --- |
| Access logs | 45,084 | 88 MB | **~2.0 KB** |
| Security events | 1,495 | 736 KB | ~0.5 KB |
| Config history | ~420 versions | 600 KB | ~1.4 KB |
| Whole database (incl. indexes) | - | 133 MB | - |

Planning numbers:

- **1 million access log rows ≈ 2 GB** (with indexes).
- **1 million security events ≈ 0.5 GB**.
- Config history grows ~1.5 KB per recorded change - negligible; keep it all.
- A busy site doing 100 req/s produces ~8.6 M access rows/day → ~17 GB/day.
  Set retention accordingly (Settings → Log retention) or ship to
  Elasticsearch.

## 3. Recommended sizing

| Profile | Traffic | vCPU | RAM | Disk | Notes |
| --- | --- | --- | --- | --- | --- |
| Lab / evaluation | < 10 req/s | 2 | 2 GB | 20 GB | all-in-one Compose is fine |
| Small production | up to ~500 req/s | 2-4 | 4 GB | 60 GB | all-in-one or 1 control + 1 edge |
| Medium | ~500-5,000 req/s | 4-8 per edge node | 8 GB | 200 GB SSD | split control plane from edge(s); PostgreSQL on its own host |
| Large | > 5,000 req/s | scale edge nodes horizontally | 8-16 GB per edge | 500 GB+ | N edge nodes behind an LB/anycast; managed PostgreSQL with replicas |

Rules of thumb from the measurements:

- Assume **~1,000-1,500 req/s per allocated vCPU** for pass-through traffic on
  a tuned Linux host (the desktop container did ~5.8k req/s while sharing
  ~20 threads with Docker Desktop and the generator).
- Blocked traffic is *cheaper* than allowed traffic (no upstream trip); a
  DDoS-blocking deployment is bounded by the refusal lane, not the engine.
- Memory is dominated by **connection state**: size for peak concurrent
  connections (keep-alive), not for average RPS.
- Give PostgreSQL **its own instance** beyond the small profile; the control
  plane degrades gracefully when it is slow, but event ingest and analytics
  queries compete with each other.

## 4. Scaling levers (in order of effect)

1. **Horizontal edge nodes.** Add agents; each holds the same bundles and
   serves independently. Traffic spreads via DNS round-robin, an L4/LB, or
   anycast. See [`ha.md`](./ha.md).
2. **Log retention & sampling.** The cheapest capacity win is not storing
   every access row forever.
3. **Body inspection budgets.** Keep advanced mode/body inspection for the
   endpoints that need it; strict inspection of large uploads is the single
   most expensive configuration.
4. **Paranoia level.** PL2 is a sensible production default; PL3-4 raise
   false positives and CPU in equal measure.
5. **Cache.** A high cache-hit ratio removes both engine cost and origin cost
   for static traffic.
6. **Elasticsearch offload.** Move log search/analytics off PostgreSQL when
   the control plane becomes the constraint.

## 5. Measure your own hardware

```powershell
cd build-artifacts
pwsh -NoProfile -File .\run-benchmark.ps1          # add -KeepOrigin to keep the origin container
```

The script starts its own origin, switches the measured site to block posture
for the block phases and restores it, cleans up, and writes
`build-artifacts/bench-results.json`. Run it on the machine you plan to
deploy on, with your real sites and policies, before sizing anything.
