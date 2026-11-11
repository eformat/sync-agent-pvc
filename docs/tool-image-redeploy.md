# Tool-gap sandbox image — build & redeploy runbook (2026-11-07; 2.2.6-tools 2026-11-08)

Closes the gaps audited by the slides agent in
`~/git/memory-bandwidth-wall-slides/sandbox-tool-gaps.md`: poppler-utils,
ImageMagick, jq, unzip, diff, wget/curl, python3 — baked into the OpenCode
sandbox image (the sandbox has NO network egress, so nothing can be installed
at runtime).

**STATUS: DEPLOYED + LIVE-VERIFIED 2026-11-07.** In-sandbox: `opencode run`
inference via RHOAI MaaS ✓, memory-tunnel e2e (`memory_search` → laptop store,
10 results) ✓.

**2.2.6-tools (2026-11-08)** adds the cluster/ops toolbox, version pins mirroring
`~/git/web-terminal/Containerfile`: `oc` + `kubectl` (4.22.22), helm 4.3.1,
argocd 3.6.1, vault 2.2.1, kustomize 5.8.3, yq 4.54.2, uv, plus gh/zip/
bind-utils/httpd-tools — so the agent can script and control OpenShift.
Requires the `openshift-api` policy endpoint (authored) + a kubeconfig upload
(`make kubeconfig-upload`).

**CHROME REMOVED (2026-11-08, owner's call).** The OpenShell boundary's
child-hardening seccomp filter (unconditional, no policy knob) makes headless
Chrome unusable **as the agent** — it can only run boundary-free (`oc exec`),
which is not a path the agent itself can take. Not worth ~450MB + the X/GTK
stack in the image, so 2.2.6-tools drops it; slides Verify/Export run on the
LAPTOP (`references/export.md`). The policy's `/opt` grant and the chrome
`localhost-http` binaries went with it. Re-add recipe in the Containerfile's
CHROME note. Full analysis: sandbox-tool-gaps.md Audit 2.

## What changed in the repo

| File | Change |
|---|---|
| `deploy/images/Containerfile.opencode-aipcc` | 3-stage build: sandbox (unchanged chmod fix) → UBI9 installer (`dnf --installroot` into the Hummingbird rootfs) → final overlay. **2.2.6-tools**: + static toolbox layer (oc/kubectl/helm/argocd/vault/kustomize/yq/uv, `set -euo pipefail` so a 404 page can't masquerade as a binary) + gh/zip/iputils/bind-utils/httpd-tools dnf packages; **− google-chrome-stable** (see CHROME REMOVED above) |
| `deploy/images/fedora-tools.repo` | NEW — Fedora 43 os+updates (ImageMagick; wget) |
| `deploy/policy/sandbox-opencode.yaml` | + `/dev/shm` read-write, + `localhost-http` (python3 http.server, port 8000). **2.2.6-tools**: + `openshift-api` endpoint (api.ocp5-m6wl4-4lf4h…:6443, binaries /usr/local/bin/{oc,kubectl}) so `oc` works in-boundary; **− `/opt` grant and chrome `localhost-http` binaries** (chrome removed). The MaaS endpoint is NOT authored here — see below |
| `Makefile` | toolbox lifecycle: `kubeconfig-upload`, `verify-oc`, `verify-oc-cluster`, `verify-tools`; image tag bumped to `2.2.6-tools`; **`verify-chrome` removed** (export is laptop-side) |
| `~/git/memory-bandwidth-wall-slides/.agents/skills/slides-deck/references/export.md` | Pod-flag documentation (`--no-sandbox` REQUIRED in pods — chrome's SUID sandbox fails under the boundary). **2026-11-08**: sandbox-image references removed — Chrome is not in the sandbox image anymore; export runs on the laptop |

Deliberately OMITTED from the toolbox vs web-terminal (see the Containerfile
comment): nodejs/npm (base node 26 is newer — an older fedora RPM would
clobber it), python3-pip/ansible (pip can never fetch in-pod — no egress — and
fedora python RPMs risk clobbering the hummingbird python 3.14 rootfs).

**NOT** `Containerfile.agent` — that is the sync-agent sidecar image
(ubi-minimal + one binary, used by `scripts/m0-buildconfig.sh`). The tool gaps
live in the sandbox image the OpenCode agent runs.

## Build

```sh
cd ~/git/sync-agent-pvc/deploy/images
podman build -f Containerfile.opencode-aipcc -t quay.io/eformat/openshell-opencode:2.2.6-tools .
podman push quay.io/eformat/openshell-opencode:2.2.6-tools
skopeo inspect docker://quay.io/eformat/openshell-opencode:2.2.6-tools | jq -r .Digest
# → update IMAGE_DIGEST in the Makefile with the printed digest (2.2.5-tools was
#   sha256:f235e99247664aec24ebf84a6d684c932b883d95efe443d1510deb163a384308)
```

Build gotchas (also encoded as Containerfile comments): the Hummingbird base
has **no package manager** (no dnf/microdnf/rpm binaries) and its rpmdb is
sqlite at `/usr/lib/sysimage/rpm` — el9 dnf must find it at
`<installroot>/var/lib/rpm` (COPY it there, don't symlink). Core packages are
excluded (glibc 2.43 never clobbered); `gpgme2*` excluded (fedora/hum1 file
conflict — hum1 poppler needs hum1's gpgmepp); fedora GPG key =
`https://fedoraproject.org/fedora.gpg`. UBI9 installer-stage trap: installing
`curl` conflicts with the preinstalled `curl-minimal` (depsolve failure) —
curl-minimal already provides /usr/bin/curl; only `unzip` needs installing.
`set -euo pipefail` on the static-binary layer so a curl'd 404 page piped into
tar fails the RUN instead of baking an HTML error page as a binary. Also:
ubi9-minimal ships **none of tar/gzip/unzip** (only curl via curl-minimal —
installing the full curl RPM conflicts with it) — `microdnf install dnf unzip
tar gzip` covers the installer stage; `net-tools` hard-requires the full
systemd RPM (conflicts with the exclude — and is redundant, the base ships
iproute2 `ss`/`ip`).

**Built + locally validated 2026-11-08:** `2.2.6-tools` = **2.49 GB** (vs
3.43 GB with Chrome). In-image checks: oc 4.22.22 + kubectl v1.35.2, helm
v4.3.1, argocd v3.6.1, vault 2.2.1, kustomize v5.8.3, yq v4.54.2, uv 0.13.7,
gh 2.87.3, zip, dig 9.20.30, ab 2.3, htpasswd all execute; base intact
(node v26.13.0, python 3.14.10, jq 1.8.2, poppler 26.08.0, ImageMagick
7.1.2); google-chrome absent; `/opt` holds only `opencode/`.

## Recreate the sandbox (the full, correct sequence)

**The workspace PVC does NOT survive a sandbox delete** — the OpenShift driver
deletes `workspace-default--sync-oc` itself (an ownerRef strip does not help).
Everything synced from the laptop (slides repo, plan, `~/.config/opencode`
except the top-level opencode.json — that file is excluded from the sync set)
comes back on the next sync pass; `.sync-agent/agents` and the master key do
NOT and must be re-bootstrapped (steps 5-6).

Prerequisite: the CLI must be OIDC-authenticated (mTLS `--local` registrations
get `role 'user' required` on EVERY workspace mutation):
`openshell gateway login -g openshift` (browser → Keycloak realm
`<realm>`, user `<your-username>`).

```sh
# 1. Delete + create — main process must NOT be `sleep 1800` (expires in 30 min,
#    phase → Completed). sleep infinity + on-failure.
openshell sandbox delete sync-oc -g openshift
openshell sandbox create -g openshift --name sync-oc --detach \
  --from quay.io/eformat/openshell-opencode@sha256:f235e99247664aec24ebf84a6d684c932b883d95efe443d1510deb163a384308 \
  --policy ~/git/sync-agent-pvc/deploy/policy/sandbox-opencode.yaml \
  --restart-policy on-failure \
  -- /bin/bash -c 'exec sleep infinity'

# 2. Attach the provider — this is what delivers inference. It derives the
#    `_provider_openai` policy entry (maas:443, enforce, binaries) and injects
#    OPENAI_API_KEY. NEVER hand-author a maas endpoint in the policy file:
#    policy-owned + provider-derived endpoints for the same host:port =
#    ambiguity → AttachSandboxProvider FAILED_PRECONDITION → receipt revoked.
openshell sandbox provider attach sync-oc openai -g openshift --wait --timeout 60
openshell sandbox provider status sync-oc openai -g openshift   # expect: ready

# 3. Restore the sync-plane state the PVC lost:
#    the agent binary (fresh musl build) + the master key.
cargo build --release -p sync-agent --target x86_64-unknown-linux-musl
openshell sandbox upload sync-oc target/x86_64-unknown-linux-musl/release/sync-agent /tmp/sync-agent --no-git-ignore
oc -n openshell exec default--sync-oc -- /tmp/sync-agent install /tmp/sync-agent
openshell sandbox upload sync-oc ~/.config/sync-agent-pvc/master.key /sandbox/.sync-agent/master.key --no-git-ignore
oc -n openshell exec default--sync-oc -- chmod 0600 /sandbox/.sync-agent/master.key

# 3b. REGISTER THE NEW AGENT PATH IN THE POLICY — REQUIRED when step 3
#     installed a NEW agents/<ver> version (learned 2026-11-11): the
#     0.1.8-pre.33 supervisor matches the policy binaries list against the
#     RESOLVED path, and agents/<ver> rolls every deploy — the relay entry's
#     old binary paths stop matching → transparent_tcp_policy_denied even for
#     mediated dials. Register the new version's paths (both layouts):
openshell policy update sync-oc -g openshift --add-endpoint 52.64.89.26:4001 \
  --binary /sandbox/.opencode/.sync-agent/agents/<ver>/sync-agent \
  --binary /sandbox/.sync-agent/agents/<ver>/sync-agent

# 4. Write opencode.json + AGENTS.md — both are versioned repo files
#    (deploy/bootstrap/). The provider attach delivers the KEY but NOT
#    OPENAI_BASE_URL (config keys are not injected as env), so baseURL must be
#    explicit in opencode.json. The mcp block (sync-agent via agents/current +
#    the memory tunnel) — the daemon only CHECKS the convention (mcp_config),
#    it does not merge. AGENTS.md gives the sandbox agent the same global
#    rules the laptop agent runs under (memory-first, git-master, secrets —
#    the sync does NOT deliver ~/.config/opencode/**, bootstrap is the only
#    path that populates it). Refresh the snapshots after editing the laptop
#    copies: make bootstrap-sync (AGENTS.md only — the laptop's opencode.json
#    shape is deliberately different from the sandbox's).
make config-bootstrap

# 5. The daemon's per-root agents then spawn (drift → re-provision), and the
#    first sync runs as a HELD dry-run — confirm it:
curl -s -X POST http://127.0.0.1:7391/api/targets/memory-bandwidth-wall-slides/sync-now
curl -s -X POST http://127.0.0.1:7391/api/targets/plan/sync-now

# 5b. RESET THE PAIR STATE — REQUIRED after a recreate (learned 2026-11-08 the
#     hard way): the pair state in ~/.local/state/sync-agent-pvc/pairs/ holds
#     the OLD sandbox's archive; keyed by (sandbox name, root_remote), a
#     recreated sandbox with the same name INHERITS it. Every pass then
#     reconciles the fresh empty root against the stale full base → mass
#     DeleteA → apply::check_safety halts with OneSideRootEmptied → zero
#     mutations, zero state writes, forever — and the content NEVER re-pushes
#     (the daemon even logs it as "pass ok ... archive held"). Resolution
#     clicks get eaten the same way. Reset (reversible) and let the next pass
#     re-push in no-base mode:
for d in ~/.local/state/sync-agent-pvc/pairs/*/; do
  case "$d" in *.halted-*) continue;; esac
  mv "$d" "${d%/}.halted-$(date +%Y%m%d)" 2>/dev/null || true
done
# → expect "applied N ... archive advanced" within ~2 passes, conflicts 0.
# (Design option for later: key the archive on the sandbox UUID so a recreated
#  sandbox auto-resets — no manual step, no halt deadlock.)

# 5c. THE AGENT SPAWN MUST BE MEDIATED — REQUIRED on 0.1.8-pre.33+: the
#     sandbox runtime's network_broker egress-denies every oc-exec-spawned
#     process (DNS AND TCP), so an agent spawned by hand via `oc exec` comes
#     up unable to dial the relay or resolve anything. The daemon spawns it
#     through the mediated `openshell sandbox exec` path since 0.1.8
#     (agent_spawn_script; oc-exec fallback) — let it, don't hand-spawn.

# 6. OPTIONAL — give the agent the oc toolbox its kubeconfig (2.2.6-tools image
#    only). DECIDE THE TOKEN SCOPE FIRST: the kubeconfig token carries
#    your cluster roles; for agent use prefer a bounded ServiceAccount token.
#    /sandbox/.kube is NOT a sync root, so the token never round-trips.
#    The openshift-api policy endpoint is already authored in the policy file
#    (no live policy surgery needed when creating with this policy).
make kubeconfig-upload
make verify-oc            # client present
make verify-oc-cluster    # live read against api.ocp5-m6wl4-4lf4h…:6443
```

The uploaded `deploy/bootstrap/opencode.json` (the daemon's `mcp_config`
check greps for `agents/current/sync-agent`):

```json
{
  "$schema": "https://opencode.ai/config.json",
  "model": "openai/publishers/prelude-maas/models/glm-53-flash",
  "provider": {
    "openai": {
      "npm": "@ai-sdk/openai-compatible",
      "options": { "baseURL": "https://maas.apps.ocp.cloud.rhai-tmm.dev/v1" },
      "models": { "publishers/prelude-maas/models/glm-53-flash": { "name": "GLM 5.3 Flash (RHOAI MaaS)" } }
    }
  },
  "mcp": {
    "sync-agent": { "type": "local", "command": ["/sandbox/.sync-agent/agents/current/sync-agent", "mcp", "--root", "/sandbox/.opencode/plan"], "enabled": true },
    "memory": { "type": "remote", "url": "http://127.0.0.1:7402/mcp", "enabled": true }
  }
}
```

## Gateway auth (why login is needed)

Every workspace-scoped gateway RPC (create/delete/stop/start/list/provider
attach) requires `workspace_role: "user"` via a **bearer** token from the
Keycloak realm `ocp5-m6wl4-4lf4h` (issuer on the hub cluster). The CLI's old
`--local` mTLS registration only CONNECTS (`allow_unauthenticated_users=true`)
— every mutation returns `role 'user' required`. The fix (2026-11-07):
re-register the gateway in OIDC mode and log in:

```sh
openshell gateway remove openshift
openshell gateway add https://openshell-openshell.apps.<cluster-domain> \
  --name openshift \
  --oidc-issuer https://keycloak-keycloak.apps.<keycloak-domain>/realms/<realm> \
  --oidc-client-id openshell-cli \
  --oidc-audience openshell-dashboard
openshell gateway login -g openshift
```

Realm prerequisites (fixed 2026-11-07): the `openshell-cli` client's Valid
Redirect URIs must include `http://127.0.0.1:*` (the CLI sends
`http://127.0.0.1:<ephemeral>/callback`; the chart-provisioned client only had
`http://localhost:*` — the mismatch surfaces as Keycloak "Invalid parameter:
redirect_uri"). The realm-job (`rhoai-cluster-pool/applications/spoke-realms`)
already carries the correct four-URI list — re-run it to reconcile a drifted
realm. Your user needs the realm roles `user` + `admin`.

## Live-verified policy facts (2026-11-07; chrome facts historical)

- `localhost-http` (127.0.0.1:8000, rest, enforce) worked 2026-11-07: python3
  binds, chrome printed — no `transparent_tcp_policy_denied`. (Chrome is gone
  from the image 2026-11-08; the endpoint stays for python3-serve smoke tests.)
- The provider-derived `_provider_openai` endpoint carries the profile's
  binaries (`/usr/bin/node`, `/usr/bin/node-26`, `/usr/local/{sbin,bin}/opencode`)
  — node's fetch through the L7 path works (placeholder resolved broker-side,
  MITM cert = `OpenShell Sandbox CA`, trusted via the injected
  `NODE_EXTRA_CA_CERTS`/`SSL_CERT_FILE`).
- Boundary DNS: all boundary processes resolve via the policy-DNS stub at
  `127.0.0.53`; oc-exec'd processes are OUTSIDE the regime (their DNS is
  dropped — `dropping DNS datagram from unregistered socket`), so never use
  `oc exec` to test network reachability — use `openshell sandbox exec`.
- `UpdateSandbox` (proto) can swap image/command on a stopped sandbox
  storage-preserving, but has NO CLI and is gated by
  `enable_sandbox_updates=false` — not viable on the 0.1.2 stack.

## Verify after recreate

1. `openshell sandbox get sync-oc -g openshift` → Phase: Ready.
2. `openshell sandbox provider status sync-oc openai -g openshift` → ready.
3. Wait ~2 daemon passes; `curl -s localhost:7391/api/targets | jq` — both
   targets `syncing`, `agent_version` present, `mcp_binary`+`mcp_config` true.
4. First sync is a HELD dry-run → confirm with the two sync-now POSTs above;
   content then lands on the PVC.
5. Inference: `openshell sandbox exec sync-oc -g openshift -- opencode run "Reply with exactly: OK"`.
6. Memory tunnel: `opencode run` with a `memory_search` tool call → real laptop-store results.
7. Toolbox: `make verify-tools` (oc/helm/argocd/... inventory) — and, once the
   kubeconfig is uploaded, `make verify-oc-cluster`.
