# remotesession — wslvault deploy handoff

**Status:** BLOCKED on Docker Hub repo secrets. Everything else staged.
**Last updated:** 2026-07-09

## Decisions locked
- **Image build path:** native amd64 via GitHub CI. Local QEMU build is a **dead end** — `aws-lc-sys v0.38.0` crashes `cc1` with SIGSEGV on the s2n-bignum `.S` assembly under QEMU emulation on Apple Silicon.
- **Registry/naming:** Docker Hub, public, `bwalia/wslvault-<service>`. (The `wslvault` Docker Hub namespace does not exist; `bwalia` does.)

## Code changes already made (uncommitted, on `main`)
- `.github/workflows/ci.yml` — build-images job retagged to `bwalia/wslvault-${service}:{latest,0.1.0,<sha>}`.
- `deploy/helm/wslvault/values.yaml` — all 12 service `image.repository` lines retagged to `bwalia/wslvault-<service>` (gateway left as `openresty/openresty`). `global.imageTag=0.1.0` matches CI; no `imageRegistry` prefix; public images so no pull secret needed.

## BLOCKER (user action) — set repo secrets
`bwalia/wslvault` currently has **zero** secrets. Run in-session (`!` prefix):
```
! gh secret set DOCKERHUB_USERNAME --body bwalia
! gh secret set DOCKERHUB_TOKEN --body <dockerhub PAT, Read & Write scope>
```
Verify: `gh secret list` shows both names.

## Next steps (once secrets set)
1. Verify `gh secret list` shows `DOCKERHUB_USERNAME` + `DOCKERHUB_TOKEN`.
2. Commit: `ci.yml`, `values.yaml`, `.dockerignore`, `Chart.lock`.
   **Exclude** `deploy/docker/Dockerfile.build-all` and `Dockerfile.runtime` (abandoned QEMU approach). Leave `charts/*.tgz` local.
3. Push to `main` — CI `build-images` is gated on `refs/heads/main`, so must push to main to trigger (noted exception to branch-first). Builds+pushes 12 images to `bwalia/wslvault-*` on native amd64.
4. `gh run watch` — confirm all 12 images pushed to Docker Hub.
5. **Task 4 — helm install:**
   ```
   KUBECONFIG=~/.kube/k3s1.yaml helm install wslvault deploy/helm/wslvault -n wslvault \
     --set-string secrets.rootKey=... --set-string secrets.jwtSecret=... --set-string secrets.pkiRootKey=... \
     # ingress: Traefik, hosts wslvault.workstation.co.uk + vault.workstation.co.uk
   ```
   Keys stashed at `scratchpad/wslvault-secrets.env` (chmod 600) — NOTE: scratchpad is session-scoped and may be gone; regenerate with `openssl rand -base64 32/48` if missing.
6. **Before gateway ready:** fix `gateway/lua/health/readiness.lua` hardcoded compose hostnames (`secret-engine:8081`, `identity-service:8082`) — won't resolve in k3s1. Override via ConfigMap with k8s service names (`wslvault-secret-engine`, etc.) or FQDNs.
7. Verify rollout: `kubectl -n wslvault get pods,ingress`.

## Already done (Task 3)
- `wslvault` namespace exists.
- `nebulacr-login` pull secret copied (for int-spectoncr; not needed for public Docker Hub).
- `wslvault-gateway-tls` self-signed secret created (SANs: both ingress hosts).
- 3 encryption keys generated + stashed at `scratchpad/wslvault-secrets.env`.
- postgresql `16.4.3` subchart vendored (`helm dependency build`).

## Security flag (unresolved)
`origin` remote URL in `.git/config` has a GitHub PAT embedded in plaintext (`github_pat_11AAW7I2A0...`). Rotate the PAT and switch remote to a bare `https://github.com/bwalia/wslvault.git` + credential helper.
