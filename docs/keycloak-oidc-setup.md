# Keycloak OIDC setup for the dashboard and gateway

The dashboard and the gateway both authenticate against an existing
Keycloak realm — the same realm the cluster's OpenShift OAuth server
delegates to, so the credentials are the pod-terminal ones.

- Realm: `<your-realm>` on the hub
  (`https://keycloak.apps.<hub-domain>`, hub
  kubeconfig: `~/.kube/config.<hub-cluster>`; realm admin: `<realm-admin>`)
- Realm roles: `admin` (<your-admin-user>), `user`

## What was created in the realm (Keycloak admin API)

1. Client `openshell-console` (confidential):
   - standard flow + direct access grants (the latter for scripted testing)
   - redirect URI `https://console.apps.<cluster-domain>/oauth2/callback`
   - web origin `https://console.apps.<cluster-domain>`
   - PKCE: `pkce.code.challenge.method = S256`
   - audience mapper `openshell-dashboard-audience`: adds
     `openshell-dashboard` to the access token `aud` (the gateway's
     `server.oidc.audience`)
   - secret stored in the `openshell-dashboard-oidc` Secret (key
     `client-secret`) on the hub — never in git
2. Client `openshell-cli` (public, direct access grants) — for CLI-side
   OIDC testing against this realm.

## What was set on the hub gateway

`sync-agent-pvc` release values (deploy/chart, subchart values):

```yaml
openshell:
  server:
    oidc:
      issuer: https://keycloak.apps.<hub-domain>/realms/<your-realm>
      audience: openshell-dashboard
      rolesClaim: realm_access.roles
      adminRole: admin
      userRole: user
```

mTLS clients (CLI, sync-agent daemon) keep working alongside: the gateway
grants the trusted local identity the roles `openshell-admin` /
`openshell-user` (verified with `openshell whoami`).

## What the dashboard values use

The dashboard's deploy values: `oidc.provider: keycloak-oidc`, the realm
issuer, `codeChallengeMethod: S256`, `allowedRoles: [admin]`,
`authDisabled: false` — per ADR 0002 the proxy owns sign-in/sessions, the
BFF relays the bearer, and the gateway validates and authorizes.

## Gotchas learned on the way

- The kube-apiserver does NOT proxy `/oauth/token` (403 system:anonymous) —
  never point a redeemer at it; use discovery or the public oauth route.
- cookie-secret must be a raw 16/24/32-byte string (`openssl rand -hex 16`;
  base64-32 output is 44 chars and is rejected).
- The proxy's v3-era fork (origin-oauth-proxy) has no keycloak-oidc provider
  and its `/oauth` prefix differs from oauth2-proxy's `/oauth2` — the
  keycloak-oidc flow uses upstream oauth2-proxy v7 (the chart default).
- The JWT must carry the gateway's audience: without the audience mapper the
  gateway rejects with "Missing required claim: aud".
- The gateway JWT signing key must be Ed25519 (RSA is rejected).
