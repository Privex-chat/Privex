# Privex on Kubernetes (PVX-03)

Immutable, tagged images; rolling deploys that never route to an unready pod;
migrations run once as a pre-deploy Job; rollback is `kubectl rollout undo`.

## Files

| File | Purpose |
|---|---|
| `namespace.yaml` | `privex` namespace, `restricted` pod-security. |
| `configmap.yaml` | Non-secret config. Sets `PRIVEX_SKIP_MIGRATIONS=1` (PVX-05). |
| `secret.example.yaml` | **Template only.** Real `privex-secrets` comes from SOPS/Vault. Not in kustomization. |
| `migration-job.yaml` | `privex-server migrate` — apply migrations + exit (PVX-05). |
| `deployment.yaml` | API Deployment: probes (PVX-02), limits, `maxUnavailable:0`, read-only rootfs. |
| `service.yaml` | ClusterIP (public exposure via ingress, not this Service). |
| `pdb.yaml` | PodDisruptionBudget `minAvailable: 2`. |
| `hpa.yaml` | CPU autoscaler 3→10. |

## Image discipline

CI builds `ghcr.io/privex-chat/privex-server:<immutable-tag>` (git SHA or semver —
never `:latest`) and pins it:

```
cd infra/k8s
kustomize edit set image ghcr.io/privex-chat/privex-server=ghcr.io/privex-chat/privex-server:<TAG>
```

The Deployment **and** the migration Job share the pinned tag, so migrations
always match the code being rolled.

## Deploy order (migrations before serving pods)

```
# 1. Secret exists (out-of-band, once):     kubectl apply -f <sops-decrypted-secret>
# 2. Validate against the live API server:  kubectl apply -k . --dry-run=server
# 3. Run migrations to completion FIRST:
kubectl delete job/privex-migrate -n privex --ignore-not-found
kubectl apply -k .                          # creates/updates all incl. the Job
kubectl wait --for=condition=complete job/privex-migrate -n privex --timeout=300s
# 4. The Deployment rolls with maxUnavailable:0 — readiness keeps traffic off any
#    pod whose deps aren't up (PVX-02). Watch it:
kubectl rollout status deploy/privex-server -n privex
```

CI/CD (Argo/Flux/Helm) should gate the Deployment rollout on the Job's
completion (a Helm pre-install/pre-upgrade hook, or an Argo sync-wave with the
Job in an earlier wave than the Deployment).

## Monitoring & keeping /metrics private (PVX-02/04)

- `monitoring/servicemonitor.yaml` scrapes the label-free `/metrics` **in-cluster**
  via the ClusterIP Service (Prometheus Operator). No operator? Use pod
  annotations instead: `prometheus.io/scrape: "true"`, `prometheus.io/path:
  "/metrics"`, `prometheus.io/port: "8080"`.
- `monitoring/networkpolicy.yaml` default-denies namespace ingress, then allows
  only the ingress controller and the `monitoring` namespace to reach port 8080.
- `monitoring/grafana-dashboard.yaml` is a sidecar-loaded board (request rate,
  status classes, 5xx ratio, avg latency, cleanup-failure counter, DB pool).
- **/metrics must not be reachable from the public edge.** It shares port 8080
  with the API, so an L3/L4 NetworkPolicy can't hide it by path — block it at the
  Ingress. Example (ingress-nginx):
  ```
  nginx.ingress.kubernetes.io/server-snippet: |
    location = /metrics { return 404; }
  ```
  (This mirrors the edge behaviour already in `infra/caddy/Caddyfile` and
  `infra/nginx/privex.conf`.) The label-free counters carry no user/IP/path
  series, so a scrape leaks no identifiers even in-cluster.

## Rollback

```
kubectl rollout undo deploy/privex-server -n privex          # to the previous ReplicaSet
kubectl rollout undo deploy/privex-server -n privex --to-revision=<N>
```

`revisionHistoryLimit: 5` retains prior ReplicaSets. Forward-only migrations mean
a code rollback must be compatible with the current schema — keep each migration
additive, and follow the per-migration rollback notes in the migration files
before rolling back across a schema change.

## Validation status

- Offline (this repo): `kubectl kustomize .` builds all resources; every file
  parses; probe paths, `maxUnavailable:0`, read-only rootfs, `PRIVEX_SKIP_MIGRATIONS`,
  and the Job's `migrate` arg are asserted.
- **Not yet done (needs a cluster):** `kubectl apply --dry-run=server` schema
  validation, a real rollout, a deliberately-crashing image to confirm readiness
  keeps traffic off it, `rollout undo`, and confirming a Prometheus scrape of
  `/metrics` succeeds in-cluster while the public ingress returns 404 for it. The
  ServiceMonitor needs the Prometheus Operator CRDs installed. Do these on the
  target cluster.
