#!/usr/bin/env bash
# §10 image pipeline (M0.x): binary build from this laptop into the in-cluster registry.
#   cargo build --release -p sync-agent --target x86_64-unknown-linux-musl
#   ./scripts/m0-buildconfig.sh
# After the M0 gate: promote to quay.io/eformat (owner makes public) — chart values flip.
#
# GOTCHA (code-sandbox memory + hit live): the docker strategy looks for `Dockerfile` by
# default — our context ships `Containerfile`, so --dockerfile=Containerfile is REQUIRED.
set -euo pipefail

: "${KUBECONFIG:?export KUBECONFIG=~/.kube/config.ocp5-1 first}"
NS="${NS:-openshell}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$REPO_ROOT/target/x86_64-unknown-linux-musl/release/sync-agent"

[ -x "$BIN" ] || { echo "binary missing: $BIN (build it first)"; exit 1; }

CTX="$REPO_ROOT/target/bc-context"
rm -rf "$CTX" && mkdir -p "$CTX"
cp "$REPO_ROOT/deploy/images/Containerfile.agent" "$CTX/Containerfile"
cp "$BIN" "$CTX/sync-agent"

# (Re)create BuildConfig, then patch dockerfilePath to Containerfile — the proven
# code-sandbox pattern (the --dockerfile CLI flag doesn't accept a context path for
# binary builds, and inline content trips the same "binary + source repo" validation).
oc -n "$NS" get bc/sync-agent >/dev/null 2>&1 && oc -n "$NS" delete bc/sync-agent
oc -n "$NS" new-build --binary --name=sync-agent --strategy=docker \
  --to=sync-agent:latest 2>&1 | tail -1
oc -n "$NS" patch bc/sync-agent --type merge \
  -p '{"spec":{"strategy":{"dockerStrategy":{"dockerfilePath":"Containerfile"}}}}' >/dev/null

oc -n "$NS" start-build sync-agent --from-dir="$CTX" --follow 2>&1 | tail -3
oc -n "$NS" get imagestream sync-agent
echo "Image: image-registry.openshift-image-registry.svc:5000/$NS/sync-agent:latest"
