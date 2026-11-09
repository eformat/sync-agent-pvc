#!/usr/bin/env bash
# M0 spikes (a)(d)(f) driver — run AFTER the sync-test sandbox is Running.
#
# (a) binary-safe exec stdio: push bytes through `oc exec` and compare hashes end-to-end
#     (detects banner noise, \r\n mangling, any tty-driven corruption).
# (d) AgentSandbox CR -> workload pod mapping via label selector.
# (f) sandbox UID/umask + PVC write test as the pod UID (config-anchoring preconditions, §7/§8).
#
# Usage: KUBECONFIG=~/.kube/config.ocp5-1 ./scripts/m0-spikes.sh [sandbox-name]
set -euo pipefail

: "${KUBECONFIG:?export KUBECONFIG=~/.kube/config.ocp5-1 first}"
SANDBOX="${1:-default--sync-test}"
NS="${NS:-openshell}"

PASS=0; FAIL=0
check() { # check <name> <cmd...>
  local name="$1"; shift
  if "$@" >/dev/null 2>&1; then echo "PASS  $name"; PASS=$((PASS+1));
  else echo "FAIL  $name"; FAIL=$((FAIL+1)); fi
}

echo "== (d) resolve sandbox CR -> workload pod =="
CR_NAME="$SANDBOX"
POD="$(oc -n "$NS" get pod -l openshell.io/sandbox="$CR_NAME" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
if [ -z "$POD" ]; then
  # label selector fallback: list pods and match the CR name by naming convention
  POD="$(oc -n "$NS" get pods -o name | grep -F "$CR_NAME" | head -1 | cut -d/ -f2 || true)"
fi
[ -n "$POD" ] || { echo "FAIL  no pod found for sandbox $CR_NAME — inspect: oc -n $NS get sandboxes"; exit 1; }
echo "      sandbox CR: $CR_NAME -> pod: $POD"

echo "== (a) exec binary-safety: 4MiB random payload round-trip through exec stdio =="
TMPDIR_LOCAL="$(mktemp -d /tmp/opencode/exec-spike.XXXXXX)"
head -c 4194304 /dev/urandom > "$TMPDIR_LOCAL/payload.bin"
LOCAL_SHA=$(sha256sum < "$TMPDIR_LOCAL/payload.bin" | cut -d' ' -f1)
# Remote-side hashing when sha256sum exists (ubi-minimal usually has coreutils-single);
# otherwise byte-identity via round-trip (push payload, cat it back, hash locally).
if oc -n "$NS" exec "$POD" -- sh -c 'command -v sha256sum' >/dev/null 2>&1; then
  REMOTE_SHA=$(oc -n "$NS" exec -i "$POD" -- sh -c 'cat > /tmp/.spike-payload && sha256sum /tmp/.spike-payload' \
    < "$TMPDIR_LOCAL/payload.bin" | cut -d' ' -f1)
  echo "      method: remote sha256sum"
else
  oc -n "$NS" exec -i "$POD" -- sh -c 'cat > /tmp/.spike-payload' < "$TMPDIR_LOCAL/payload.bin"
  REMOTE_SHA=$(oc -n "$NS" exec "$POD" -- cat /tmp/.spike-payload | sha256sum | cut -d' ' -f1)
  echo "      method: stream round-trip (no sha256sum in image)"
fi
echo "      local  sha256: $LOCAL_SHA"
echo "      remote sha256: $REMOTE_SHA"
check "(a) 4MiB payload survives exec stdin byte-identical" test "$LOCAL_SHA" = "$REMOTE_SHA"

# Banner-noise resilience: prefix garbage on stdout of the REMOTE command must still let the
# client-side framing recover (this is why the MAGIC handshake exists).
if oc -n "$NS" exec "$POD" -- sh -c 'command -v sha256sum' >/dev/null 2>&1; then
  NOISE_SHA=$(oc -n "$NS" exec -i "$POD" -- sh -c 'echo "banner noise: motd-ish line"; cat > /tmp/.spike-payload2 && sha256sum /tmp/.spike-payload2' \
    < "$TMPDIR_LOCAL/payload.bin" | tail -1 | cut -d' ' -f1)
  check "(a) payload intact despite stdout banner noise (stdin/stdout are independent)" \
    test "$LOCAL_SHA" = "$NOISE_SHA"
fi

echo "== (f) pod UID / umask / PVC write as pod UID =="
oc -n "$NS" exec "$POD" -- sh -c 'echo "      uid=$(id -u) gid=$(id -g) umask=$(umask)"'
WORKDIR="$(oc -n "$NS" exec "$POD" -- sh -c 'echo "${HOME:-/sandbox}"')"
echo "      HOME in sandbox: $WORKDIR"
check "(f) can write to sync root as pod UID" \
  oc -n "$NS" exec "$POD" -- sh -c "touch '$WORKDIR/.spike-write-test' && rm -f '$WORKDIR/.spike-write-test'"
check "(f) XDG config dir visible/creatable" \
  oc -n "$NS" exec "$POD" -- sh -c "mkdir -p '$WORKDIR/.config/opencode'"

echo
echo "RESULT: $PASS passed, $FAIL failed"
rm -rf "$TMPDIR_LOCAL"
[ "$FAIL" -eq 0 ]
