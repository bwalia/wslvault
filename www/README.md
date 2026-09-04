# WSLVault marketing site

The public site at **https://www.wslvault.org** (apex `wslvault.org` redirects to it).

A Next.js static export published to GitHub Pages, mirroring the vantiq site's
setup. It is self-contained here in `www/` and shares nothing with the Rust
workspace or `ui/apps/vault-ui`.

## Local development

```bash
cd www
npm install
npm run dev              # http://localhost:3000
npm run build:static     # static export into www/out
npm run preview:static   # serve the exported site
```

## Deploy

Normal path: push to `www/` on `main` →
`.github/workflows/seed-www-ring-promoter.yml` seeds Ring Promoter app
`wslvault-www` → RP workflow-dispatches `.github/workflows/pages.yml` →
GitHub Pages updates **https://www.wslvault.org/**.

`pages.yml` also still runs on direct pushes to `www/**` as a safety net, and
accepts `workflow_dispatch` inputs (`ENV`, `DEPLOY_BRANCH`, `DEPLOY_MODE`) for
Ring Promoter. Pages source must be **GitHub Actions**.

See `deploy/ring-promoter/README.md` and
https://rp.workstation.co.uk/?app=wslvault-www.

## Domain

`www/CNAME` holds the custom domain (`www.wslvault.org`) and is copied into the
build artifact on every deploy. DNS (Cloudflare) is already configured:

- `wslvault.org` — A records to the GitHub Pages addresses (185.199.108–111.153)
- `www.wslvault.org` — CNAME to `bwalia.github.io`

GitHub Pages serves both and redirects the apex to `www`. Do not orange-cloud
(proxy) the records through Cloudflare, or the Pages TLS certificate cannot
issue.
