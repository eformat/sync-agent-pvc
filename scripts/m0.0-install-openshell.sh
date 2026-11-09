#!/usr/bin/env bash
# M0.0 — install OpenShell on ocp5-1 following ~/git/agent-ops/guides/getting-started-openshell-openshift.md
#
# Prerequisites:
#   - KUBECONFIG exported (test cluster: ~/.kube/config.ocp5-1), cluster-admin
#   - helm 3 CLI
#   - Red Hat build of Agent Sandbox operator v0.9.0 in openshift-operators (step 0 verifies)
#   - chart dependency vendored: helm dependency update deploy/chart/ (once)
#
# Order is load-bearing (guide): ns → SCC binding BEFORE helm install → chart → verify.
set -euo pipefail

: "${KUBECONFIG:?export KUBECONFIG=~/.kube/config.ocp5-1 first}"

NS="${NS:-openshell}"
ODH_IMAGE_TAG="${ODH_IMAGE_TAG:-v0.0.116-rhaiv.0}"
CHART_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../deploy/chart" && pwd)"

echo "== 0. preflight: Agent Sandbox CRD present (Red Hat build of Agent Sandbox v0.9.0)?"
if ! oc get crd sandboxes.agents.x-k8s.io >/dev/null 2>&1; then
  echo "MISSING: sandboxes.agents.x-k8s.io CRD."
  echo "Install the Red Hat build of Agent Sandbox (v0.9.0) in openshift-operators first"
  echo "(Software Catalog, or the Subscription YAML in docs/m0.0-runbook.md step 0)."
  exit 1
fi

echo "== 1. namespace + privileged SCC binding (BEFORE chart install)"
oc get ns "$NS" >/dev/null 2>&1 || oc create ns "$NS"
oc adm policy add-scc-to-user privileged -z openshell-sandbox -n "$NS"

echo "== 2. helm upgrade --install (chart brings ns/SCC/Route templates too — idempotent)"
# NOTE: image tags come from deploy/chart/values.yaml (gateway = eformat patched build,
# supervisor = chart-family 0.1.2). The guide's --set image.tag/supervisor.image.tag
# pattern injects Red Hat quay tags onto the ghcr repo → manifest unknown. Don't do that.
helm upgrade --install sync-agent-pvc "$CHART_DIR" -n "$NS" \
  --set "routeHost=openshell-openshell.$(oc get ingresses.config.openshift.io cluster -o jsonpath='{.spec.domain}')" \
  --set "openshell.pkiInitJob.serverDnsNames[0]=openshell-openshell.$(oc get ingresses.config.openshift.io cluster -o jsonpath='{.spec.domain}')"

echo "== 3. wait for the gateway pod"
oc -n "$NS" wait --for=condition=Ready pod -l app.kubernetes.io/instance=sync-agent-pvc --timeout=180s 2>/dev/null \
  || oc get pods -n "$NS"

echo "== 4. verify"
oc get pods -n "$NS"
ROUTE_HOST="openshell-openshell.$(oc get ingresses.config.openshift.io cluster -o jsonpath='{.spec.domain}')"
echo
echo "Gateway Route: https://${ROUTE_HOST}"
echo
echo "NEXT (laptop-side, see docs/m0.0-runbook.md steps 5-7):"
echo "  - extract mTLS bundle from secret openshell-client-tls"
echo "  - openshell gateway add \"https://${ROUTE_HOST}\" --local --name openshift"
echo "  - openshell status   # expect Connected"
