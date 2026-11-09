# M4 study — OpenShell sandbox workload templates & the sync-agent injection

Date: 2026-11-06 (M4 chart work; retires the M3 deferral "chart sidecar template —
needs SandboxWorkloadTemplate API study"). Evidence sources, all read-only:

- **Live cluster** ocp5-1 (`KUBECONFIG=~/.kube/config.ocp5-1`): CRD list, the
  `default--sync-oc` Sandbox CR, the `os-supervisor-*` pod spec, CRD schemas.
- **OpenShell source** `~/git/OpenShell` (0.1.2-family): `proto/openshell.proto`,
  `crates/openshell-driver-kubernetes/src/{driver,config}.rs`,
  `crates/openshell-sandbox/src/main.rs`, `crates/openshell-cli/src/{main,run}.rs`.
- **This repo**: `crates/agent/src/{p2p,main}.rs`, vendored chart
  `deploy/chart/charts/openshell/`, `docs/m0.0-runbook.md` (M0/M3.5 lessons).

## TL;DR — the decision

**The injection form is the MAIN-PROCESS SPEC** (the sandbox's canonical command),
**not a sidecar container**. The sync-agent `p2p` mode replaces the M0 probe
(`bash -c '…; exec sleep 1800'`) as the workload's main process:

```
/usr/local/bin/sync-agent p2p --relay <multiaddr> --sandbox-id sync-oc --root /sandbox
```

- It is a **foreground, long-lived process** — exactly what a main process is; its
  lifetime = sandbox lifetime. No `nohup` (the M3 gate's workaround dies here).
- It keeps the sandbox phase **Ready indefinitely** — killing the M3.5-gate
  problem where the probe's `sleep 1800` expired after 30 min and dropped the
  sandbox to `Completed` (`docs/m0.0-runbook.md`, M3.5 section).
- The master key arrives as an **env var** (`SYNC_AGENT_MASTER_KEY`), not a file:
  the k8s driver's per-sandbox schema accepts **PVC-only volumes**
  (`deny_unknown_fields`), so a Secret volume mount into the sandbox pod is
  impossible in-schema — and unnecessary, the agent has an env fallback.
- The `opencode.json` mcp block lands via the **image-baked workspace seed** (the
  platform's own first-boot copy of image `/sandbox` contents into the PVC), with
  the chart ConfigMap as the rendered source of truth.

There is **no helm-renderable sandbox workload template on this cluster**: the
OpenShell `SandboxWorkloadTemplate` is gateway (SQLite) state, and its schema
(image + env + resources) cannot carry a main-process command anyway. The chart
therefore renders the *wiring* — master-key Secret, opencode.json +
create-command ConfigMap — and the create command (one-time, CLI) applies the
injection. Details below.

## 1. What actually exists (inventory)

| Name | Where it lives | Notes |
|---|---|---|
| `Sandbox` CRD | `sandboxes.agents.x-k8s.io/v1beta1` (k8s) | Created by the **gateway**, not by users; carries OpenShell internal annotations |
| `SandboxTemplate` CRD (upstream agent-sandbox) | `sandboxtemplates.extensions.agents.x-k8s.io` | Present on ocp5-1, **zero instances** — OpenShell does not use the upstream template/claim flow |
| `SandboxWorkloadTemplate` | **Gateway state (SQLite)**, via `CreateSandboxTemplateRequest` | NOT a k8s object → helm cannot render it |
| Main-process spec | Annotation `openshell.ai/sandbox-runtime-main-process-spec` on the Sandbox CR + env `OPENSHELL_MAIN_PROCESS_SPEC` on the supervisor pod | Written by the gateway from `SandboxSpec.command` at create time |
| Sidecar injection | **Nowhere** | k8s-driver per-sandbox config rejects extra containers (`deny_unknown_fields`); the upstream flat sidecar fields were *removed* |

Verified on the live CR (`oc get sandbox default--sync-oc -o yaml`): the pod is
gateway-built — one `agent` container (the runtime bootstrap
`openshell-sandbox --bootstrap boundary.json`) plus OpenShell init containers
(`openshell-sandbox-bootstrap`, `workspace-init`); volumes are the workspace PVC
(`volumeClaimTemplates`, 2Gi gp3) plus OpenShell-internal runtime/state/bootstrap
volumes. A user-defined extra container has no path into this pod.

## 2. The gateway `SandboxWorkloadTemplate` (why it can't be the vehicle)

From `~/git/OpenShell/proto/openshell.proto` (line refs from the 0.1.2-family tree):

```proto
message SandboxWorkloadTemplate {            // line 1169
  ObjectMeta metadata = 1;
  SandboxWorkloadTemplateSpec spec = 2;
}
message SandboxWorkloadTemplateSpec {        // line 1176
  SandboxWorkloadConfig workload = 1;        // the whole portable shape
  google.protobuf.Struct driver_config = 2;
  SandboxServiceLevel desired_service_level = 3;
}
message SandboxWorkloadConfig {              // line 1186
  string image = 1;
  map<string, string> environment = 2;
  SandboxResources resources = 3;            // cpu/memory/gpu — that's all
}
```

Three fatal gaps for our purpose:

1. **No command field.** The main-process spec (`SandboxSpec.command`, proto
   line ~1097: *"Canonical command launched once by the sandbox supervisor. No
   shell parsing is performed."*) is **not part of the template** — a
   template-created sandbox still needs the command supplied per-create
   (`CreateSandboxRequest.spec.command`) or via `UpdateSandboxRequest.command`
   on a stopped sandbox.
2. **Not a k8s object.** Templates are workspace-scoped gateway records
   (`CreateSandboxTemplateRequest`, CLI `openshell sandbox template create`).
   Helm/GitOps cannot manage them; they don't survive gateway-data loss.
3. `CreateSandboxRequest.workload_template` (field 6) **conflicts** with the
   inline workload flags (`--template` vs `--from/--env/--driver-config-json` —
   enforced in the CLI), so a template can't be layered onto a bespoke create.

**Verdict:** the template is optional sugar for pinning image+env+resources; it
cannot be the injection vehicle and cannot be chart-rendered. Documented here so
the M3 deferral is retired with evidence, not vibes.

## 3. The chosen form: main-process spec (evidence chain)

Flow, with receipts:

1. **API**: `CreateSandboxRequest.spec.command` (repeated string, no shell) —
   CLI surface: trailing args after `--` on `openshell sandbox create`
   (`crates/openshell-cli/src/main.rs`, `Create` variant), plus
   `--restart-policy {never|on-failure|always}`, `--env KEY=VALUE`,
   `--env-from KEY[=ENVVAR]` (value read from the CLI *process* env — keeps
   secrets out of argv), `--detach` (don't attach; sets
   `await_main_process_attachment=false`).
2. **Gateway → Sandbox CR**: the command is persisted as the annotation
   `openshell.ai/sandbox-runtime-main-process-spec`
   (`{"version":1,"command":[...],"tty":false,"await_main_process_attachment":false}`
   — exactly what the live CR shows for the probe).
3. **Driver → supervisor pod**: the k8s driver renders that annotation into
   env `OPENSHELL_MAIN_PROCESS_SPEC` on `os-supervisor-<sandbox-id>`
   (`openshell-driver-kubernetes/src/sandbox_runtime.rs`; live pod confirms).
   The supervisor spawns the main process **inside the workload container's
   boundary**, so it inherits the pod's env and the provider launch environment.
4. **Pod env**: `SandboxSpec.environment` → the workload pod's container env
   (`spec_pod_env` → `podTemplate` in `driver.rs:7866`; the runtime generation
   install merges `template.environment` + `spec.environment`, stripping
   `OPENSHELL_*`, `driver.rs:3409`). This is the **schema-sanctioned env path**.

Why this beats a sidecar — and why a sidecar is not even available:

- The per-sandbox k8s `driver_config` schema is
  `KubernetesSandboxDriverConfig` (`driver.rs:700`, `#[serde(deny_unknown_fields)]`):
  `pod.{node_selector,runtime_class_name,tolerations,priority_class_name}`,
  `containers.agent.{resources,volume_mounts}`, and `volumes[]` which are
  **`persistent_volume_claim` only** (`driver.rs:770-800`). No `containers[]`
  list, no images, no commands.
- The older flat sidecar fields were **removed upstream** —
  `config.rs` tests `serde_rejects_sidecar_binary_identity_field` and
  `serde_rejects_removed_flat_sidecar_fields` assert they now error as
  `unknown field`.
- The "sidecar topology" strings in `openshell-core/src/sandbox_env.rs`
  (`OPENSHELL_SUPERVISOR_TOPOLOGY = "sidecar"`, `SIDECAR_RUN_ROOT`,
  `SIDECAR_CONTROL_SOCKET`) are OpenShell's **internal** network/policy sidecar
  machinery — a deployment topology the platform may use itself, not a
  user-injection point.
- Plan §1's placement tree option ② (Kyverno sidecar injection) would fight the
  gateway-built pod (scheduling gate + bootstrap secret + admission records)
  and inject OUTSIDE the OpenShell identity regime; option ③ (second process in
  one container) is what the main-process spec already does natively.

**Bonus:** the p2p agent as main process means `openshell sandbox exec` keeps
working indefinitely (phase stays Ready — M3.5 runbook lesson), and the daemon
can treat "pod Running + agent on the relay" as one lifecycle.

## 4. Master key delivery: Secret → env (no file, no mount)

Requirement (§ plan / M3): the sandbox needs the same 64-hex master as the
laptop (`~/.config/sync-agent-pvc/master.key`); identity =
`blake3::derive_key("sync-agent-pvc/v1/sandbox/<id>", master)` → ed25519 →
PeerId. The daemon computes the same PeerId (no DHT/rendezvous).

Schema reality (why the file-at-0600 approach from the M3 gate is not
declaratively reachable):

- driver_config volumes are **PVC-only** → no `secret:` volume, no projected
  volume, no ConfigMap mount into the workload pod. (Also gated: driver_config
  itself requires gateway `allow_driver_config=true`, default **false** —
  `driver.rs` config — and we don't need it at all: the workspace PVC is
  injected by default.)
- Init containers are gateway-built; no user init step exists to write a file.
- Therefore: **env is the only in-schema path**, and the agent already supports
  it — `crates/agent/src/p2p.rs::load_master_key(None)` falls back to
  `SYNC_AGENT_MASTER_KEY` (64-hex). Same file exists as the M3
  exec-fallback bootstrap shape (unchanged, daemon-owned).

Delivery chain (all pieces chart-rendered or one-time CLI):

```
--set sandboxTemplate.masterKey=<64-hex>            (deploy time, never in git)
  → Secret sync-agent-master-key (chart template)
    → operator shell: oc -n openshell get secret … | base64 -d
      → export SYNC_AGENT_MASTER_KEY=…
        → openshell sandbox create --env-from SYNC_AGENT_MASTER_KEY
          → SandboxSpec.environment                 (pod container env)
            → supervisor-spawned main process       (agent env fallback)
```

`--env-from` reads the CLI process env, so the key never appears in argv/`ps`
output. Accepted v1 exposure: the key lands in `SandboxSpec.environment` and is
readable from `oc get sandbox -o yaml` by anyone who can read the CR — the §9
k8s-Secrets+env exception on a single-user test cluster; upgrade path = vault/ESO.

## 5. `opencode.json` mcp injection (ConfigMap + image seed)

The mcp block (M3.5 gate shape — the key is **`mcp`, NOT `mcpServers`**):

```json
{
  "mcp": {
    "sync-agent": {
      "type": "local",
      "command": ["/usr/local/bin/sync-agent", "mcp", "--root", "/sandbox"],
      "enabled": true
    }
  }
}
```

- The command references the **image copy** of the binary
  (`/usr/local/bin/sync-agent`), not the exec-uploaded self-install path
  (`.sync-agent/agents/<ver>/…`) — that path belongs to the oc-exec fallback
  transport and stays out of the in-sandbox config.
- **How it gets into `/sandbox/.config/opencode/`**: mounting is impossible
  (`/sandbox` IS the workspace PVC). The platform-native mechanism is the
  **workspace seed**: the `workspace-init` init container (same image) copies
  the image's original `/sandbox` contents into a fresh PVC on first use —
  sentinel `.openshell-initialized` guard, `create_new` semantics, dirs 0700 /
  files 0600|exec (`driver.rs` `apply_workspace_persistence`,
  `openshell-sandbox/src/main.rs::copy_workspace_tree`). Bake the file into the
  derived image at `/sandbox/.config/opencode/opencode.json` → it seeds every
  fresh sandbox PVC.
- The chart ConfigMap (`sync-agent-sandbox-config`, key `opencode.json`) renders
  the same block from values — the source of truth for image builds and for
  manual/daemon copies onto existing sandboxes. Drift risk (image copy vs
  ConfigMap) is documented; regenerate the image after any values change.
- **Sync interplay (owner decides)**: `~/.config/opencode/**` is an anchored
  sync include (plan §7), so the seeded file lives INSIDE the synced set. If the
  laptop has its own `opencode.json`, the first sync pass will surface a
  no-base conflict on that file (both sides modified) — resolve once, or
  exclude the top-level `opencode.json` from the sync set so the sandbox-side
  file stays injection-owned. This is a daemon/plan-policy decision, flagged
  here because the injection makes it load-bearing.

## 6. Chart deliverables (what renders)

Gate: `sandboxTemplate.enabled` (default **false** → default render/lint clean;
flip in the deploy values file, never commit values in it).

| Object | Template | Purpose |
|---|---|---|
| Secret `sync-agent-master-key` | `templates/sync-agent-master-key-secret.yaml` | 64-hex master, `required` → empty `--set` fails the render loudly |
| ConfigMap `sync-agent-sandbox-config` | `templates/sync-agent-sandbox-config.yaml` | key `opencode.json` (mcp block) + key `create-sandbox.sh` (the values-rendered create command) |

Exact `create-sandbox.sh` shape (rendered; digest/key are deploy-time values):

```sh
export SYNC_AGENT_MASTER_KEY="$(oc -n openshell get secret sync-agent-master-key \
  -o jsonpath='{.data.master-key}' | base64 -d)"
exec openshell sandbox create -g openshift --name sync-oc --detach \
  --from quay.io/eformat/openshell-opencode-sync@sha256:<digest> \
  --policy deploy/policy/sandbox-opencode.yaml \
  --env-from SYNC_AGENT_MASTER_KEY \
  --restart-policy on-failure \
  -- /usr/local/bin/sync-agent p2p \
      --relay /ip4/203.0.113.42/tcp/4001/p2p/12D3KooWQqWcYxCifgqAsynZL2uJUd132gbG3XhZbCQZMs6Dq9Qc \
      --sandbox-id sync-oc --root /sandbox
```

Render/lint commands (helm 3.x; the M0.0 rule holds — **always `-n <namespace>`**
because subchart templates call `lookup` against the live cluster
(`credential-secrets-namespace`, `credential-storage-key-encryption-key-secret`);
with KUBECONFIG exported those lookups hit ocp5-1 read-only, with it unset they
return nil/defaults — both render, but be deliberate):

```bash
# full render with the M4 wiring enabled (values file is /tmp-only, NEVER committed)
helm template sync-agent-pvc deploy/chart -n openshell -f /tmp/opencode/m4-values.yaml

# plain render (M4 section gated off) + lint — both must be clean
helm template sync-agent-pvc deploy/chart -n openshell
helm lint deploy/chart
```

Status at delivery: template exit 0 (23 objects), `helm lint` 0 failures **with
and without** the M4 values, rendered `create-sandbox.sh` passes `sh -n`,
rendered `opencode.json` parses as JSON, fail-loud verified (enabled + no key →
render exits 1 with the `required` message). One pre-existing lint failure was
fixed in passing: `Chart.yaml` now declares the vendored subchart
(`dependencies: [name: openshell, version: 0.1.2]`) — helm lint rejects a
charts/ subchart that Chart.yaml doesn't declare.

## 7. The derived image (recipe for `deploy/images/` — see that dir)

Extends the proven `Containerfile.opencode-aipcc` (base + `chmod -R a+rX
/sandbox`). The sync-agent binary is the musl static build of this repo
(`cargo build --release -p sync-agent --target x86_64-unknown-linux-musl`),
plus the seeded mcp config generated from the rendered ConfigMap:

```dockerfile
FROM quay.io/eformat/openshell-opencode@sha256:1e85d936bb40720de9deeef450d5a3629c6b7be91c492e948ccecbcaf985239f
# sync-agent (musl static) at the PATH-stable image location
COPY target/x86_64-unknown-linux-musl/release/sync-agent /usr/local/bin/sync-agent
RUN chmod 0755 /usr/local/bin/sync-agent
# Seed the FRESH-PVC opencode config (mcp block) — copied by workspace-init
# into the PVC on first use (sentinel-guarded, create_new).
COPY opencode.json /sandbox/.config/opencode/opencode.json
RUN chmod 0600 /sandbox/.config/opencode/opencode.json
```

Build/push with the established flow (`podman build` → `quay.io/eformat`,
BuildConfig path per plan §10 also works), then **pin by registry manifest
digest** (podman's local `.Digest` is a different hash and 404s remotely — M0
lesson). Values: `sandboxTemplate.image.{registry,repository,digest}`.

## 8. Egress (reference, don't duplicate)

- **k8s layer**: already covered — `templates/sandbox-egress-vps.yaml` opens
  workload-pod → VPS:4001 (M0 spike (g) PASS; `openshell policy update` never
  touches k8s NetworkPolicies).
- **OPA/Landlock layer — NEW exposure**: the M3 gate ran the agent from `oc
  exec` + `nohup` (OUTSIDE the supervisor identity regime). As the **main
  process** it is supervisor-spawned → inside the regime → the transparent-TCP
  policy now applies to its relay connection. If the relay dial gets refused
  (`transparent_tcp_policy_denied` in the supervisor log — the authoritative
  record, runbook M3.5), add the endpoint + binary to the policy, e.g. a
  `network_policies` entry in `deploy/policy/sandbox-opencode.yaml`
  (endpoints: VPS:4001 read-write; binaries: the executed path
  `/usr/local/bin/sync-agent` — the opencode hardlink lesson: OPA reports the
  **executed** path) or the runbook's `openshell policy update …
  --add-endpoint <VPS>:4001:read-write:rest:enforce --binary
  /usr/local/bin/sync-agent` shape.

## 9. Schema gaps found (recorded for upstream/future)

1. **No user sidecar/init containers** — `KubernetesSandboxDriverConfig` is
   `deny_unknown_fields` with containers.agent-only shape; upstream removed the
   flat sidecar fields. (If a true sidecar ever becomes the shape, this is the
   upstream gap to file.)
2. **No secret/configMap volumes in driver_config** (PVC-only) → secret
   delivery must ride `SandboxSpec.environment` (literal map — the value is
   visible in the Sandbox CR to CR readers).
3. **`SandboxWorkloadTemplate` cannot carry the main-process command** —
   template reuse can't pin the injection; the command is per-create (or
   `UpdateSandboxRequest.command` on a stopped sandbox — note: that is also the
   *repair path* to swap the probe on an existing sandbox without recreate).
4. `driver_config` is dead-letter by default (`allow_driver_config: false`) —
   irrelevant for this design (we use none), noted so nobody reaches for it.
5. The driver strips `OPENSHELL_*` from user env (`driver.rs:3415`) — our env
   names (`SYNC_AGENT_*`) are outside that namespace by design.

## 10. What the owner must verify manually (I cannot apply anything)

1. **Build/push the derived image** (§7 recipe into `deploy/images/`), pin the
   real manifest digest into the deploy values
   (`sandboxTemplate.image.digest`).
2. **Apply the release** via rhoai-cluster-pool GitOps with a deploy values
   file: `sandboxTemplate.enabled=true`, `--set sandboxTemplate.masterKey=<64-hex>`
   (same master as `~/.config/sync-agent-pvc/master.key`), real digest.
3. **Run the create command** from the rendered ConfigMap; then verify:
   - `oc get sandbox default--sync-oc -o yaml` → annotation
     `openshell.ai/sandbox-runtime-main-process-spec` shows the p2p command
     (probe gone), env map carries `SYNC_AGENT_MASTER_KEY`.
   - Supervisor pod env `OPENSHELL_MAIN_PROCESS_SPEC` matches; phase goes Ready
     and STAYS Ready (>30 min — probe expiry retired).
   - The agent reached the relay: reservation in its logs (where main-process
     stderr lands — check `oc logs os-supervisor-<id>` vs the workload pod;
     confirm and note for the runbook).
4. **OPA egress for the main process** (§8): if the relay dial is refused, add
   the VPS endpoint + `/usr/local/bin/sync-agent` to
   `deploy/policy/sandbox-opencode.yaml` (that file is yours) and re-attach.
5. **`openshell sandbox exec`** still works against the agent-as-main-process
   sandbox (phase Ready gate) and OpenCode in-sandbox sees the `sync-agent` MCP
   tools (image-path binary).
6. **Restart policy** `on-failure`: kill the main process once, confirm the
   gateway restarts it and the sandbox recovers (no `Completed`).
7. **opencode.json sync interplay** (§5): decide exclude-vs-anchor for the
   top-level `opencode.json` before the first real `$HOME` sync.
8. **Sandbox id consistency**: the create command uses `--sandbox-id sync-oc`
   (= `sandboxTemplate.name`); the daemon's per-target sandbox id in M4
   `config.toml` must be the same string or the derived PeerIds won't match.
