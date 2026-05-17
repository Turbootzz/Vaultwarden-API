# Vaultwarden Kubernetes Operator

A Kubernetes operator that automatically syncs secrets from your Vaultwarden vault into native Kubernetes `Secret` objects. Define a `VaultwardenSecret` custom resource and the operator keeps the corresponding K8s Secret up to date.

## How It Works

```
┌──────────────────────┐    watches     ┌──────────────────────┐
│  VaultwardenSecret   │ <────────────  │  vaultwarden-        │
│  (custom resource)   │                │  operator            │
└──────────────────────┘                │                      │
                                        │  • Fetches items     │
┌──────────────────────┐    creates/    │    from Vaultwarden  │
│  Kubernetes Secret   │ <── updates ── │  • Reconciles on     │
│  (same name/ns)      │                │    interval          │
└──────────────────────┘                └──────────────────────┘
```

1. You create a `VaultwardenSecret` CR listing the Vaultwarden items you want
2. The operator fetches all listed items from Vaultwarden (using the same crypto as the API server)
3. It creates or updates a `corev1.Secret` in the same namespace with the same name as the CR
4. It re-syncs on the configured interval, and immediately on any change to the CR or managed Secret
5. Deleting the CR cascade-deletes the managed Secret (via owner reference)

**Atomicity:** if any vault item is missing, the entire sync is aborted — no partial writes.

## Prerequisites

- Kubernetes 1.26+
- A running Vaultwarden instance reachable from the cluster
- A dedicated Vaultwarden user account with the relevant items in its vault (see the [main README](README.md#recommended-create-a-dedicated-user))

## Installation

### 1. Create the credentials Secret

The operator reads Vaultwarden credentials from a Secret in its namespace. Create it before deploying:

```bash
kubectl create namespace vaultwarden-operator-system

kubectl create secret generic vaultwarden-operator-credentials \
  --namespace vaultwarden-operator-system \
  --from-literal=VAULTWARDEN_URL=https://vault.example.com \
  --from-literal=VAULTWARDEN_EMAIL=operator@example.com \
  --from-literal=VAULTWARDEN_PASSWORD=your-master-password
```

If your account has 2FA enabled, also add the API key credentials (see [2FA / Two-Step Login](README.md#2fa--two-step-login) in the main README):

```bash
kubectl patch secret vaultwarden-operator-credentials \
  --namespace vaultwarden-operator-system \
  --type=merge \
  -p '{"stringData":{"VAULTWARDEN_CLIENT_ID":"your-client-id","VAULTWARDEN_CLIENT_SECRET":"your-client-secret"}}'
```

Then uncomment the `VAULTWARDEN_CLIENT_ID` / `VAULTWARDEN_CLIENT_SECRET` env blocks in `config/manager/deployment.yaml`.

### 2. Install the CRD and operator

```bash
make deploy-operator
```

This runs:
1. `kubectl apply -f config/crd/vaultwardensecret.yaml` — installs the `VaultwardenSecret` CRD
2. `kubectl apply -f config/rbac/` — creates the ServiceAccount, ClusterRole, and ClusterRoleBinding
3. `kubectl apply -f config/manager/deployment.yaml` — deploys the operator pod
4. `kubectl apply -f config/manager/network_policy.yaml` — applies the NetworkPolicy (see [Network Policy](#network-policy))

Verify the operator is running:

```bash
kubectl get pods -n vaultwarden-operator-system
kubectl logs -n vaultwarden-operator-system -l app.kubernetes.io/name=vaultwarden-operator
```

## Usage

Create a `VaultwardenSecret` in any namespace:

```yaml
apiVersion: secrets.vaultwarden.io/v1alpha1
kind: VaultwardenSecret
metadata:
  name: my-app-secrets
  namespace: my-app
spec:
  syncInterval: 5m       # optional, defaults to 5m
  data:
    - key: DATABASE_URL
      vaultwardenSecret: DATABASE_URL   # item name in Vaultwarden (case-insensitive)
    - key: API_TOKEN
      vaultwardenSecret: My API Token   # partial/natural names work too
    - key: REDIS_PASSWORD
      vaultwardenSecret: redis-prod
```

Apply it:

```bash
kubectl apply -f my-app-secrets.yaml
```

The operator creates a `Secret` named `my-app-secrets` in the `my-app` namespace:

```bash
kubectl get secret my-app-secrets -n my-app -o yaml
```

Check sync status:

```bash
kubectl get vaultwardensecrets -n my-app
# NAME              READY   LAST SYNC              AGE
# my-app-secrets    true    2024-01-15T10:30:00Z   5m
```

```bash
kubectl describe vaultwardensecret my-app-secrets -n my-app
```

### Using the managed Secret in a Pod

```yaml
envFrom:
  - secretRef:
      name: my-app-secrets
```

Or individual keys:

```yaml
env:
  - name: DATABASE_URL
    valueFrom:
      secretKeyRef:
        name: my-app-secrets
        key: DATABASE_URL
```

## Spec Reference

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `spec.syncInterval` | string | No | `5m` | Re-sync interval (Go duration, e.g. `30s`, `5m`, `1h`) |
| `spec.data` | array | **Yes** | — | List of vault item → Secret key mappings (min 1 item) |
| `spec.data[].key` | string | **Yes** | — | Key name in the resulting Kubernetes Secret |
| `spec.data[].vaultwardenSecret` | string | **Yes** | — | Vaultwarden item name to look up (case-insensitive, partial match supported) |

## Status Reference

| Field | Description |
|-------|-------------|
| `status.ready` | `true` when the last sync succeeded |
| `status.lastSyncTime` | Timestamp of the last successful sync |
| `status.lastSyncError` | Error message from the last failed sync |
| `status.conditions` | Standard K8s conditions: `Ready` and `SyncFailed` |

## Operator Configuration

The operator Deployment in `config/manager/deployment.yaml` supports these environment variables:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VAULTWARDEN_URL` | **Yes** | — | Vaultwarden instance URL |
| `VAULTWARDEN_EMAIL` | **Yes** | — | Vaultwarden account email |
| `VAULTWARDEN_PASSWORD` | **Yes** | — | Master password (used for decryption) |
| `VAULTWARDEN_CLIENT_ID` | No | — | API key client ID (bypasses 2FA) |
| `VAULTWARDEN_CLIENT_SECRET` | No | — | API key client secret (bypasses 2FA) |
| `CACHE_TTL` | No | `5m` | In-memory secret cache TTL |
| `SYNC_INTERVAL` | No | `5m` | Background vault sync interval |

## RBAC

The operator uses a `ClusterRole` with the following permissions:

| Resource | Verbs |
|----------|-------|
| `vaultwardensecrets` (all subresources) | get, list, watch, create, update, patch, delete |
| `secrets` (core) | get, list, watch, create, update, patch, delete |
| `events` (core) | create, patch |
| `coordination.k8s.io/leases` | get, list, watch, create, update, patch, delete |

The `secrets` permission is cluster-wide by necessity — the operator must be able to create and manage Secrets in any namespace where a `VaultwardenSecret` CR is deployed. The NetworkPolicy below limits the blast radius if the operator pod is compromised.

## Network Policy

`config/manager/network_policy.yaml` applies a `NetworkPolicy` to the operator pod that restricts traffic to only what is required:

**Ingress** (what can reach the operator pod):
- Kubelet health and readiness probes on port `8081` (`/healthz`, `/readyz`)
- All other inbound traffic is denied

**Egress** (what the operator pod can reach):
- DNS on port `53` (UDP + TCP) — for resolving the Vaultwarden hostname and the Kubernetes API server
- HTTPS on port `443` — Kubernetes API server (`kubernetes.default.svc`) and Vaultwarden
- Port `6443` — clusters that expose kube-apiserver on its default port

This prevents a compromised operator from making unexpected outbound connections (e.g., exfiltrating secrets to an external host) while allowing all legitimate traffic.

### Adjustments

**Vaultwarden on a non-standard port** — add the port to the egress rules in `config/manager/network_policy.yaml`:
```yaml
- ports:
    - port: 8443   # example
      protocol: TCP
```

**Vaultwarden running inside the cluster** — replace the broad port-based egress rule with a targeted one using `podSelector` and `namespaceSelector`:
```yaml
- to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: vaultwarden
      podSelector:
        matchLabels:
          app.kubernetes.io/name: vaultwarden
  ports:
    - port: 80
      protocol: TCP
```

**Prometheus metrics scraping** — uncomment the ingress block in `config/manager/network_policy.yaml` and set the label on your monitoring namespace to match.

## Running Locally

To run the operator against your local `~/.kube/config` cluster:

```bash
# Install the CRD first
make install-crd

# Run the operator with leader election disabled
make run-operator
```

This requires a `.env` file with `VAULTWARDEN_URL`, `VAULTWARDEN_EMAIL`, and `VAULTWARDEN_PASSWORD`.

## Building and Publishing

```bash
# Build the binary
make build-operator

# Build Docker image (AMD64)
make docker-build-operator

# Build and push multi-arch image (amd64, arm64, armv7)
make docker-push-operator
```

## Uninstalling

```bash
# Remove the operator Deployment and RBAC (does NOT remove the CRD or any managed Secrets)
make undeploy-operator

# To also remove the CRD (this will delete all VaultwardenSecret CRs in the cluster)
make uninstall-crd
```

> **Note:** Managed `Secret` objects are owned by their `VaultwardenSecret` CR. Deleting a CR deletes the Secret. Undeploying the operator without removing CRs leaves the Secrets in place.

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `status.ready: false` | Vault item not found or unreachable | Check `status.lastSyncError`; verify item names with `kubectl describe vws` |
| Operator pod crash-loops | Missing credentials Secret | Ensure `vaultwarden-operator-credentials` exists in `vaultwarden-operator-system` |
| Secret not created | Operator lacks RBAC | Confirm ClusterRole and ClusterRoleBinding are applied |
| Stale secret values | Sync interval too long | Lower `spec.syncInterval` on the CR or `SYNC_INTERVAL` on the Deployment |
| Operator can't reach Vaultwarden | NetworkPolicy too strict | Check that port 443 egress is allowed; add non-standard ports if needed (see [Network Policy](#network-policy)) |
| Operator can't reach Kubernetes API | NetworkPolicy too strict | Ensure port 443 and/or 6443 egress is allowed and DNS (53) egress is open |

Check operator logs for details:

```bash
kubectl logs -n vaultwarden-operator-system \
  -l app.kubernetes.io/name=vaultwarden-operator --tail=100
```
