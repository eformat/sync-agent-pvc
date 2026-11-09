#!/usr/bin/env bash
# M3 VPS relay deploy: build the musl-static relay on the laptop, stage + cut over
# on the VPS (ssh alias `wg`), retiring the borrowed Go p2p-claude-plans unit.
#
#   ./scripts/m3-relay-deploy.sh            # full: build → upload → cutover → verify
#   ./scripts/m3-relay-deploy.sh --build-only   # just the musl build
#
# Cutover is ROLLBACK-SAFE: the Go unit is disabled (not deleted) —
#   ssh wg 'sudo systemctl disable --now sync-relay && sudo systemctl enable --now p2p-claude-plans'
#
# VPS facts (surveyed 2026-11-06): CentOS Stream 9, x86_64, glibc 2.34 → musl static
# REQUIRED (laptop glibc is newer; a gnu-target binary would fail). Port 4001 free
# after the Go unit stops; AWS SG + sandbox egress NP already allow 4001.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VPS="${VPS:-wg}"
VPS_USER="${VPS_USER:-ec2-user}"
RELAY_BIN="$REPO_ROOT/target/x86_64-unknown-linux-musl/release/sync-relay"
STAGED="/home/$VPS_USER/sync-relay.staged"
UNIT_SRC="$REPO_ROOT/deploy/vps/sync-relay.service"
KEY_DIR="/home/$VPS_USER/.sync-agent-relay"

# --- build (musl static; the target must be installed: rustup target add x86_64-unknown-linux-musl)
if [[ "${1:-}" != "--build-only" && ! -x "$RELAY_BIN" && "${SKIP_BUILD:-0}" != "1" ]]; then
  echo "==> building sync-relay (musl static)"
  (cd "$REPO_ROOT" && cargo build --release -p sync-relay --target x86_64-unknown-linux-musl)
fi
if [[ "${1:-}" == "--build-only" ]]; then
  (cd "$REPO_ROOT" && cargo build --release -p sync-relay --target x86_64-unknown-linux-musl)
  exit 0
fi
[[ -x "$RELAY_BIN" ]] || { echo "relay binary missing: $RELAY_BIN"; exit 1; }

echo "==> upload"
scp -q "$RELAY_BIN" "$VPS:$STAGED"

echo "==> stage binary + unit on the VPS"
# SELinux (CentOS): mv from /home preserves user_home_t — systemd (init_t) exec
# fails 203/EXEC. restorecon relabels to bin_t (the old Go binary's context).
ssh "$VPS" "sudo mv $STAGED /usr/local/bin/sync-relay && sudo chmod 0755 /usr/local/bin/sync-relay && \
  sudo restorecon /usr/local/bin/sync-relay && \
  sudo tee /etc/systemd/system/sync-relay.service > /dev/null && \
  mkdir -p $KEY_DIR && chmod 0700 $KEY_DIR" < "$UNIT_SRC"

echo "==> cutover (Go relay disabled, NOT deleted — rollback hint at the end)"
ssh "$VPS" "sudo systemctl disable --now p2p-claude-plans 2>/dev/null; \
  sudo systemctl daemon-reload && sudo systemctl enable sync-relay && sudo systemctl restart sync-relay"
sleep 3

echo "==> verify"
ssh "$VPS" "systemctl is-active sync-relay; ss -tlnp | grep 4001 || { echo 'NOT LISTENING'; exit 1; }"
PEERID="$(ssh "$VPS" "journalctl -u sync-relay --no-pager -n 50 | grep -iE 'peer[_ ]?id' | tail -1" || true)"
echo "relay PeerId line: $PEERID"
echo "$PEERID" > "$REPO_ROOT/deploy/vps/relay-peerid.txt"
echo
echo "DONE. Relay on 4001; PeerId recorded in deploy/vps/relay-peerid.txt."
echo "Rollback: ssh $VPS 'sudo systemctl disable --now sync-relay && sudo systemctl enable --now p2p-claude-plans'"
