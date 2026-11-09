# sync-agent-pvc — laptop <-> OpenShell sandbox sync
#
# Conventions borrowed from ~/git/queryflux (Rust workspace targets, WHY
# comments, guard clauses) and ~/git/rhoai-nightly (thin targets that delegate
# to scripts, phase-organized help, status/diagnose targets).
#
# Default workflow: run targets individually and verify each step.
# The sandbox lifecycle targets encode the recreate flow from
# docs/tool-image-redeploy.md — read it before running sandbox-recreate cold.

CARGO      := $(HOME)/.cargo/bin/cargo

# Every oc/openshell call in this Makefile targets the hub cluster (alias
# ocp5-1). FORCED (not ?=): your shell may carry a KUBECONFIG for a different
# cluster, and an env var would silently win over `?=` (the old verify-chrome
# once ran `oc exec` against the wrong cluster and got NotFound). Override
# per-invocation: make verify-oc-cluster KUBECONFIG=...
export KUBECONFIG = $(HOME)/.kube/config.ocp5-1

# Optional LOCAL overrides (untracked — never commit real cluster values):
#   echo 'GATEWAY_GUARD_DOMAIN = apps.my-cluster.example.com' >> Makefile.local
-include Makefile.local

NAMESPACE  ?= openshell
SANDBOX    ?= sync-oc
# GATEWAY NAME, not namespace: `openshift` = the ocp5-1 gateway. There is also
# a gateway named `openshell` (the COCO cluster) — defaulting to the wrong one
# once aimed a `sandbox delete` at it (caught by the endpoint guard below).
GATEWAY    ?= openshift
# The endpoint guard substring: destructive targets refuse to run against any
# gateway whose endpoint does not contain this domain. Set YOUR cluster's apps
# domain in the untracked Makefile.local (or per-invocation) — never commit a
# real cluster hostname here.
GATEWAY_GUARD_DOMAIN ?= gateway.invalid.example.com

# The sandbox image. IMAGE_REF pins BY REGISTRY DIGEST — a mutable tag plus
# IfNotPresent served a stale layer once (M0 lesson). After `make image-push`,
# run `make image-digest` and update IMAGE_DIGEST here (or pass
# IMAGE_REF=...@sha256:... on the command line). IMAGE_DIGEST = the 2.2.6-tools
# build (toolbox, no Chrome — 2.49GB) — bump to the 2.2.7 digest after push.
IMAGE      ?= quay.io/eformat/openshell-opencode:2.2.7-tools
# NOTE: the digest to pin is the REGISTRY one (from the push log or the quay
# API Docker-Content-Digest header) — podman's LOCAL digest differs (push
# converts OCI→schema2). Never use `podman images --digests` for this.
IMAGE_DIGEST ?= sha256:a628d722be5aeed378b9096d0edef021ec5d68724dc0a0cce7eae475c2f7363f
IMAGE_REF  ?= quay.io/eformat/openshell-opencode@$(IMAGE_DIGEST)

MUSL_BIN   := target/x86_64-unknown-linux-musl/release/sync-agent
DAEMON_BIN := $(HOME)/.local/bin/sync-agent
MASTER_KEY := $(HOME)/.config/sync-agent-pvc/master.key

.DEFAULT_GOAL := help
.PHONY: help build build-musl install test clippy lint fmt check clean \
        image image-push image-digest image-sidecar relay-deploy \
        login sandbox-status sandbox-create sandbox-delete provider-attach \
        agent-upload master-key-upload config-bootstrap bootstrap-sync \
        kubeconfig-upload sandbox-recreate \
        policy-add-endpoint policy-remove-endpoint \
        status sync-now daemon-restart daemon-logs \
        verify verify-inference verify-memory verify-oc verify-tools

help:
	@awk 'BEGIN { printf "\nsync-agent-pvc — laptop <-> OpenShell sandbox sync\n" } \
	  /^# --- / { hdr = $$0; sub(/^# --- /, "", hdr); sub(/ -+$$/, "", hdr); printf "\n%s\n", hdr; next } \
	  /^##/ { line = $$0; sub(/^## ?/, "", line); pending = pending line "\n"; next } \
	  /^[a-zA-Z_][a-zA-Z0-9_-]*:/ { \
	    if (pending != "") { \
	      name = $$1; sub(/:.*/, "", name); \
	      n = split(pending, L, "\n"); \
	      printf "  \033[36m%-20s\033[0m %s\n", name, L[1]; \
	      for (i = 2; i <= n; i++) if (L[i] != "") printf "  %-20s %s\n", "", L[i]; \
	      pending = ""; \
	    } \
	    next \
	  } \
	  END { if (pending != "") printf "%s", pending; printf "\n" }' $(MAKEFILE_LIST)

# --- Build & dev -------------------------------------------------------------

## Release build of the workspace (sync-agent, sync, sync-relay)
build:
	$(CARGO) build --release

## Musl-static sync-agent — the binary that gets uploaded into the sandbox
## (static: runs on any sandbox image regardless of its glibc; the gnu build
## of the SUPERVISOR once died on distroless for exactly this reason).
build-musl:
	$(CARGO) build --release -p sync-agent --target x86_64-unknown-linux-musl

## Install the DAEMON into ~/.local/bin/sync-agent (the unit file's ExecStart).
## The daemon is the `sync` CLI crate (crates/cli) copied under the sync-agent
## name — the sandbox agent crate (crates/agent) is a DIFFERENT binary with no
## `daemon` subcommand: cargo install --path crates/agent put it here once and
## the service crash-looped on "unknown subcommand: daemon" (2026-11-08).
## --force: a same-version reinstall must not silently no-op.
install: build
	$(CARGO) install --path crates/cli --locked --force --root $(HOME)/.local
	cp $(HOME)/.local/bin/sync $(DAEMON_BIN)
	$(MAKE) daemon-restart
	@$(DAEMON_BIN) --version

## Workspace tests (M4 gate: all green, 0 clippy warnings)
test:
	$(CARGO) test --workspace

## Clippy with warnings as errors
clippy:
	$(CARGO) clippy --workspace --all-targets -- -D warnings

## clippy alias (queryflux convention)
lint: clippy

## rustfmt across the workspace
fmt:
	$(CARGO) fmt --all

## cargo check without codegen — fast feedback
check:
	$(CARGO) check --workspace

clean:
	$(CARGO) clean

# --- Images ------------------------------------------------------------------

## Build the OpenCode sandbox image locally (toolbox: oc/helm/argocd/... + poppler/ImageMagick/python3 — NO Chrome, see the Containerfile's CHROME note)
image:
	podman build -f deploy/images/Containerfile.opencode-aipcc -t $(IMAGE) deploy/images

## Push to quay (your quay repo — the quay session must be logged in)
image-push:
	podman push $(IMAGE)

## Print the REGISTRY manifest digest (podman's local .Digest is a different
## hash and 404s remotely — M0 lesson). Update IMAGE_DIGEST with the output.
image-digest:
	@skopeo inspect docker://$(IMAGE) | jq -r .Digest

## Sidecar image via the in-cluster BuildConfig (M0 path — scripts/m0-buildconfig.sh)
image-sidecar:
	@KUBECONFIG=$(KUBECONFIG) ./scripts/m0-buildconfig.sh

## Deploy the VPS relay (M3 — musl build, stage, cutover, verify)
relay-deploy:
	@./scripts/m3-relay-deploy.sh

# --- Gateway auth ------------------------------------------------------------

## OIDC login for the CLI (mTLS --local registrations only CONNECT; every
## mutation needs a bearer: 'role user required'). Keycloak realm ocp5-m6wl4-4lf4h.
login:
	openshell gateway login -g $(GATEWAY)
	openshell whoami -g $(GATEWAY)

# --- Sandbox lifecycle -------------------------------------------------------
# The full recreate flow is `make sandbox-recreate`. The workspace PVC does NOT
# survive a sandbox delete (the driver removes it — an ownerRef strip does not
# help): synced roots restore from the laptop, but agents + master key must be
# re-bootstrapped. Details + prerequisites (OIDC login!) in
# docs/tool-image-redeploy.md.

## Get the sandbox (phase, restart policy, main process)
sandbox-status:
	openshell sandbox get $(SANDBOX) -g $(GATEWAY)

## DANGEROUS: deletes the sandbox AND its workspace PVC (slides repo, plan,
## agent binaries — everything PVC-local). Requires CONFIRM=yes. Refuses to run
## against any gateway whose endpoint is not ocp5-1 (the `openshell` gateway
## name belongs to the COCO cluster). The endpoint lookup matches the gateway
## name ANYWHERE in the row — the selected row is starred ("* openshift"), so
## a column-1 awk match silently returns '' and would fail-closed (2026-11-08).
sandbox-delete:
	@test "$(CONFIRM)" = "yes" || { echo "This deletes the workspace PVC (unsynced data is LOST)."; echo "Run: make sandbox-delete CONFIRM=yes"; exit 1; }
	@endpoint=$$(openshell gateway list 2>/dev/null | awk -v gw="$(GATEWAY)" '{ for (i = 1; i <= NF; i++) if ($$i == gw) { print $$(i+1); exit } }'); \
	  case "$$endpoint" in \
	    *$(GATEWAY_GUARD_DOMAIN)*) ;; \
	    *) echo "REFUSING: gateway '$(GATEWAY)' endpoint '$$endpoint' does not match GATEWAY_GUARD_DOMAIN '$(GATEWAY_GUARD_DOMAIN)' (set yours in untracked Makefile.local)"; exit 1 ;; \
	  esac
	openshell sandbox delete $(SANDBOX) -g $(GATEWAY)

## Create the sandbox from the pinned image. Main process = `exec sleep infinity`:
## the M0-era probe (`sleep 1800`) expired after exactly 30 minutes and took the
## sandbox to Completed. Never hand-author a maas endpoint in the policy — the
## provider attach derives it (ambiguity = FAILED_PRECONDITION, see policy file).
sandbox-create:
	@endpoint=$$(openshell gateway list 2>/dev/null | awk -v gw="$(GATEWAY)" '{ for (i = 1; i <= NF; i++) if ($$i == gw) { print $$(i+1); exit } }'); \
	  case "$$endpoint" in \
	    *$(GATEWAY_GUARD_DOMAIN)*) ;; \
	    *) echo "REFUSING: gateway '$(GATEWAY)' endpoint '$$endpoint' does not match GATEWAY_GUARD_DOMAIN '$(GATEWAY_GUARD_DOMAIN)' (set yours in untracked Makefile.local)"; exit 1 ;; \
	  esac
	openshell sandbox create -g $(GATEWAY) --name $(SANDBOX) --detach \
	  --from $(IMAGE_REF) \
	  --policy deploy/policy/sandbox-opencode.yaml \
	  --restart-policy on-failure \
	  -- /bin/bash -c 'exec sleep infinity'

## Attach the openai provider (RHOAI MaaS). Delivers OPENAI_API_KEY (as a
## broker-resolved placeholder) and derives the _provider_openai policy entry.
## Does NOT deliver OPENAI_BASE_URL — config keys are not injected as env, so
## opencode.json must carry options.baseURL explicitly (see config-bootstrap).
provider-attach:
	openshell sandbox provider attach $(SANDBOX) openai -g $(GATEWAY) --wait --timeout 60
	openshell sandbox provider status $(SANDBOX) openai -g $(GATEWAY)

## Build + upload the musl sync-agent and install it into the sandbox
## (agents/<ver> + current symlink — the daemon's per-root agents need it).
agent-upload: build-musl
	openshell sandbox upload $(SANDBOX) $(MUSL_BIN) /tmp/sync-agent --no-git-ignore
	@KUBECONFIG=$(KUBECONFIG) oc -n $(NAMESPACE) exec default--$(SANDBOX) -- bash -c \
	  'chmod 0755 /tmp/sync-agent && /tmp/sync-agent install /tmp/sync-agent' 2>&1 | grep -v "Defaulted container"

## Upload the shared master key (the provision script refuses to spawn agents
## without it — exit 4). 0600, owned by the pod UID.
master-key-upload:
	@test -f $(MASTER_KEY) || { echo "no master key at $(MASTER_KEY)"; exit 1; }
	openshell sandbox upload $(SANDBOX) $(MASTER_KEY) /sandbox/.sync-agent/master.key --no-git-ignore
	@KUBECONFIG=$(KUBECONFIG) oc -n $(NAMESPACE) exec default--$(SANDBOX) -- \
	  chmod 0600 /sandbox/.sync-agent/master.key 2>&1 | grep -v "Defaulted container" || true

## Upload the ocp5-1 kubeconfig for the baked-in oc (2.2.6-tools image). Lands
## at /sandbox/.kube/config — oc's default lookup path (HOME=/sandbox) — and
## /sandbox/.kube is NOT a sync root, so the token never round-trips to the
## laptop. THE FILE HOLDS A BEARER TOKEN: never commit it, never move it under
## a synced root, and decide the scope first (see the policy file's SECURITY
## NOTE — this token carries your cluster roles; prefer a bounded
## ServiceAccount token if the agent must not write cluster-wide).
kubeconfig-upload:
	@test -f $(HOME)/.kube/config.ocp5-1 || { echo "no kubeconfig at $(HOME)/.kube/config.ocp5-1"; exit 1; }
	openshell sandbox upload $(SANDBOX) $(HOME)/.kube/config.ocp5-1 /sandbox/.kube/config --no-git-ignore
	@KUBECONFIG=$(KUBECONFIG) oc -n $(NAMESPACE) exec default--$(SANDBOX) -- \
	  chmod 0600 /sandbox/.kube/config 2>&1 | grep -v "Defaulted container" || true

## Credential-free kubeconfig for the kubernetes-api provider (stage 1). The
## bearer token NEVER enters the sandbox: the provider delivers an opaque
## placeholder as $KUBE_TOKEN, the exec-plugin echoes it, and the supervisor's
## proxy swaps it for the real token only on kubernetes.default.svc:443.
## Prereqs: profile imported (deploy/provider-profiles/kubernetes-api.yaml) +
## provider created + attached (k8s-provider-attach). See
## ~/.opencode/plan/k8s-provider-stage1.md. SAFE on the PVC — no secret.
kubeconfig-provider-upload:
	@test -f deploy/bootstrap/kubeconfig-provider.yaml || { echo "missing deploy/bootstrap/kubeconfig-provider.yaml"; exit 1; }
	openshell sandbox upload $(SANDBOX) deploy/bootstrap/kubeconfig-provider.yaml /sandbox/.kube/config --no-git-ignore
	@KUBECONFIG=$(KUBECONFIG) oc -n $(NAMESPACE) exec default--$(SANDBOX) -- \
	  chmod 0600 /sandbox/.kube/config 2>&1 | grep -v "Defaulted container" || true

## Attach the kubernetes-api provider (k8s access via the in-cluster API service
## on 443 — port 6443 is hard-blocked upstream, SEC-005). Must be re-run after
## any sandbox recreate, alongside provider-attach. Rotation (stage 2):
##   KUBE_TOKEN="$$(KUBECONFIG=$$(KUBECONFIG) oc whoami -t)" \
##     openshell provider update kubernetes-api --credential KUBE_TOKEN
k8s-provider-attach:
	openshell sandbox provider attach $(SANDBOX) kubernetes-api -g $(GATEWAY) --wait --timeout 60
	openshell sandbox provider status $(SANDBOX) kubernetes-api -g $(GATEWAY) 2>&1 | grep -viE "token|secret"

## Rotate the kubernetes-api provider credential from the laptop kubeconfig
## (2a: `oc whoami -t` — mimics a normal KUBECONFIG workflow; override the
## source with `make k8s-provider-rotate KUBECONFIG=~/.kube/other`). Uses the
## Makefile-exported KUBECONFIG by default. The gateway pushes the new
## credential to every attached sandbox (—wait reports per-sandbox outcomes).
##
## ROTATION SEMANTICS (corrected live 2026-11-09): the gateway store KEEPS the
## credential's expiry metadata across updates — a rotate without
## --credential-expires-at inherits the previous expiry (the stage-1 credential
## was created from a 1h `oc create token`, so the store later judged the fresh
## token 'credential_expired' -> withheld -> fresh sandbox processes got NO
## KUBE_TOKEN at all). So every rotate MUST restate the expiry: we read the
## live token's real server-side expiry from the user's newest
## openshift-challenging-client OAuthAccessToken (the `oc login` flow; fallback:
## newest token of any client; fallback: 0 = clear). `oc whoami -t` tokens on
## this cluster DO expire (~24h) — the earlier "non-expiring" observation was
## wrong. Update never revokes OLD placeholders (only detach does): a running
## session's existing env keeps resolving the old value until THAT session's
## processes restart — restart the agent's session process tree, not the sync
## daemon.
k8s-provider-rotate:
	@test -f "$(KUBECONFIG)" || { echo "no kubeconfig at $(KUBECONFIG)"; exit 1; }
	@TOK=$$(KUBECONFIG=$(KUBECONFIG) oc whoami -t 2>/dev/null); \
	  test -n "$$TOK" || { echo "oc whoami -t returned nothing (expired session? run: KUBECONFIG=$(KUBECONFIG) oc login)"; exit 1; }; \
	  WHO=$$(KUBECONFIG=$(KUBECONFIG) oc whoami); \
	  COLS='CREATED:.metadata.creationTimestamp,USER:.userName,CLIENT:.clientName,EXPIRESIN:.expiresIn'; \
	  ROW=$$(KUBECONFIG=$(KUBECONFIG) oc get oauthaccesstokens -o custom-columns=$$COLS --no-headers 2>/dev/null | awk -v u="$$WHO" '$$2==u && $$3=="openshift-challenging-client"{print $$1, $$4}' | sort | tail -1); \
	  test -n "$$ROW" || ROW=$$(KUBECONFIG=$(KUBECONFIG) oc get oauthaccesstokens -o custom-columns=$$COLS --no-headers 2>/dev/null | awk -v u="$$WHO" '$$2==u{print $$1, $$4}' | sort | tail -1); \
	  EXP=$$(test -n "$$ROW" && date -u -d "$$(echo $$ROW | cut -d' ' -f1) + $$(echo $$ROW | cut -d' ' -f2) seconds" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null); \
	  test -n "$$EXP" || EXP=0; \
	  KUBE_TOKEN="$$TOK" openshell provider update kubernetes-api -g $(GATEWAY) --credential KUBE_TOKEN --credential-expires-at "KUBE_TOKEN=$$EXP" --wait 2>&1 | grep -viE "token value|^  Receipt|Persisted"
	@echo "rotated kubernetes-api credential from $(KUBECONFIG) — fresh sandbox processes resolve the new value; a running session keeps the old placeholder until its processes restart"
	@echo "rotated kubernetes-api credential from $(KUBECONFIG) — fresh sandbox processes resolve the new value; a running session keeps the old placeholder until its processes restart"

## Minimal opencode.json + the global AGENTS.md (memory-first, git-master,
## secrets rules — same instructions the laptop agent runs under). The attach
## delivers the API key but NOT OPENAI_BASE_URL — config keys are not injected
## as env, so opencode.json must carry options.baseURL explicitly. The mcp
## block: sync-agent via agents/current + the memory tunnel. The daemon only
## CHECKS this convention (mcp_config), it does not merge it. Both files are
## versioned under deploy/bootstrap/ (the sync does NOT deliver
## ~/.config/opencode/** today — bootstrap is the only path that populates it).
## Refresh the snapshots from the laptop after editing them there:
##   make bootstrap-sync
config-bootstrap:
	@test -f /sandbox/.config/opencode/opencode.json 2>/dev/null || true
	openshell sandbox upload $(SANDBOX) deploy/bootstrap/opencode.json /sandbox/.config/opencode/opencode.json --no-git-ignore
	openshell sandbox upload $(SANDBOX) deploy/bootstrap/AGENTS.md /sandbox/.config/opencode/AGENTS.md --no-git-ignore
	@KUBECONFIG=$(KUBECONFIG) oc -n $(NAMESPACE) exec default--$(SANDBOX) -- \
	  sh -c 'grep -c "agents/current/sync-agent" /sandbox/.config/opencode/opencode.json; head -1 /sandbox/.config/opencode/AGENTS.md' 2>&1 | grep -v "Defaulted container" || true

## Refresh deploy/bootstrap/AGENTS.md from the laptop's live copy (a
## deliberate, reviewable commit). opencode.json is DELIBERATELY NOT copied:
## the laptop shape (empty provider options, env-based URL, no mcp block) is
## the broken shape for the sandbox — the sandbox config needs explicit
## options.baseURL (the attach does not deliver OPENAI_BASE_URL) and the mcp
## block. Edit deploy/bootstrap/opencode.json by hand.
bootstrap-sync:
	@if [ -f $(HOME)/.config/opencode/AGENTS.md ]; then \
	  cp $(HOME)/.config/opencode/AGENTS.md deploy/bootstrap/AGENTS.md && echo "AGENTS.md refreshed"; \
	else echo "WARN: no laptop AGENTS.md — leaving the repo copy"; exit 1; fi
	@git diff --stat deploy/bootstrap/ | tail -3

## In-place image update: patch the sandbox CR's pod image (digest-pinned
## IMAGE_REF) and let the controller roll the pod. KEEPS the workspace PVC —
## synced content, agent state and master key all survive, no pair-state reset
## (that's the whole point vs sandbox-recreate). The per-root sync agents die
## with the pod; the daemon's drift re-provision respawns them on the next
## pass (watch `make status`). Run after image-push + IMAGE_DIGEST bump.
sandbox-image-update:
	@echo "patching sandbox image → $(IMAGE_REF)"
	export KUBECONFIG=$(KUBECONFIG); \
	oc -n $(NAMESPACE) patch sandbox default--$(SANDBOX) --type=merge \
	  -p '{"spec":{"podTemplate":{"spec":{"containers":[{"name":"agent","image":"$(IMAGE_REF)"}]}}}}'
	@echo "pod rolling — watch: KUBECONFIG=$(KUBECONFIG) oc -n $(NAMESPACE) get pod -w"

## Restart a sandbox whose pod was killed/deleted: the shutdownPolicy puts the
## CR into Suspended (PodTerminated) and the controller will NOT recreate the
## pod on its own — `openshell sandbox start` re-admits and recreates it. The
## workspace PVC SURVIVES pod deletion (content + agent state intact; the
## daemon re-provisions the per-root agents on the next pass). Start blocks
## until Ready — run it in the foreground and let it finish.
sandbox-start:
	openshell sandbox start $(SANDBOX) -g $(GATEWAY)

## Stop (preserve workspace) — the polite counterpart to sandbox-start. NOTE:
## `oc delete pod` does NOT stop a sandbox cleanly; it Suspends it (see
## sandbox-start) and skips the graceful shutdown path.
sandbox-stop:
	openshell sandbox stop $(SANDBOX) -g $(GATEWAY)

## Full recreate: delete (destroys the PVC!) → create → provider → agent binary
## → master key → config. Then confirm the held first-sync dry-run:
##   make sync-now   (and check `make status`)
sandbox-recreate:
	$(MAKE) sandbox-delete CONFIRM=yes
	$(MAKE) sandbox-create
	$(MAKE) provider-attach
	$(MAKE) agent-upload
	$(MAKE) master-key-upload
	$(MAKE) config-bootstrap

## Live policy endpoint surgery (the attach-ambiguity escape hatch):
##   make policy-remove-endpoint EP=maas.apps.ocp.cloud.rhai-tmm.dev:443
##   make policy-add-endpoint EP=host:443:read-write:rest:enforce BIN=/usr/local/sbin/opencode
policy-add-endpoint:
	@test -n "$(EP)" || { echo "EP=host:port:access:protocol:enforcement required"; exit 1; }
	openshell policy update $(SANDBOX) -g $(GATEWAY) --add-endpoint $(EP) $(if $(BIN),--binary $(BIN),)

policy-remove-endpoint:
	@test -n "$(EP)" || { echo "EP=host:port required"; exit 1; }
	openshell policy update $(SANDBOX) -g $(GATEWAY) --remove-endpoint $(EP)

# --- Sync & daemon -----------------------------------------------------------

## Show both sync targets (phase, agent version, tunnel, MCP checks)
status:
	@curl -s --max-time 5 http://127.0.0.1:7391/api/targets | jq -r '.[] | "\(.name)  \(.phase)  agent:\(.sandbox_status.agent_version // "none")  tunnel:\(.sandbox_status.tunnel // [])  mcp:\(.sandbox_status.mcp_binary // false)/\(.sandbox_status.mcp_config // false)  err:\(.last_error // "none")"'

## Confirm the held first-run dry-run(s) and force a pass on both targets
sync-now:
	@curl -s -X POST http://127.0.0.1:7391/api/targets/memory-bandwidth-wall-slides/sync-now | head -c 120; echo
	@curl -s -X POST http://127.0.0.1:7391/api/targets/plan/sync-now | head -c 120; echo

## Restart the user daemon (after `make install`, config changes, key rotation)
daemon-restart:
	systemctl --user restart sync-agent.service
	@systemctl --user is-active sync-agent.service

## Follow the daemon's logs
daemon-logs:
	@journalctl --user -u sync-agent.service -f

# --- Verification (the three capability gates) --------------------------------

## Inference: a real model roundtrip through the provider + derived policy
verify-inference:
	@timeout 180 openshell sandbox exec $(SANDBOX) -g $(GATEWAY) -- \
	  opencode run "Reply with exactly: MAAS-EGRESS-OK" 2>&1 | tail -2

## Memory tunnel: opencode → 127.0.0.1:7402 → P2P → daemon allowlist → laptop store
verify-memory:
	@timeout 240 openshell sandbox exec $(SANDBOX) -g $(GATEWAY) -- \
	  opencode run "Use the memory tool memory_search to search for 'sync-agent-pvc'. Reply with exactly MEMORY-TUNNEL-OK plus the number of results." 2>&1 | tail -2

## oc: client exists in the image (works pre-recreate only if the sandbox was
## already recreated on 2.2.6-tools); cluster reachability is verify-oc-cluster
verify-oc:
	@timeout 60 openshell sandbox exec $(SANDBOX) -g $(GATEWAY) -- oc version --client

## oc against the LIVE cluster — requires: 2.2.6-tools image (oc binary), the
## openshift-api policy endpoint (authored in deploy/policy/sandbox-opencode.yaml
## or added live via policy-add-endpoint), and kubeconfig-upload. Read-only.
verify-oc-cluster:
	@timeout 120 openshell sandbox exec $(SANDBOX) -g $(GATEWAY) -- \
	  oc get namespaces --request-timeout=60s -o name 2>&1 | head -5

## The whole baked toolbox (version pins mirror ~/git/web-terminal/Containerfile)
verify-tools:
	@timeout 120 openshell sandbox exec $(SANDBOX) -g $(GATEWAY) -- bash -c '\
	  for t in oc kubectl helm argocd vault kustomize yq uv uvx gh zip dig ab htpasswd; do \
	    printf "%-10s %s\n" $$t "$$(command -v $$t >/dev/null && $$t --version 2>/dev/null | head -1 || echo MISSING)"; done'

## Run the two in-boundary gates. (Chrome export was the third — it runs
## LAPTOP-side now: the OpenShell boundary's child-hardening seccomp filter
## makes headless Chrome unusable as the agent, and Chrome was removed from
## the image 2026-11-08. See ~/git/memory-bandwidth-wall-slides/sandbox-tool-gaps.md
## Audit 2 + references/export.md.)
verify: verify-inference verify-memory
