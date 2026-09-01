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

`.github/workflows/pages.yml` builds `www/` with `NEXT_STATIC_EXPORT=true` and
publishes `www/out` to GitHub Pages on any push to `main` that touches `www/`
(or via **Run workflow**). Pages must have its source set to **GitHub Actions**.

## Domain

`www/CNAME` holds the custom domain (`www.wslvault.org`) and is copied into the
build artifact on every deploy. DNS (Cloudflare) is already configured:

- `wslvault.org` — A records to the GitHub Pages addresses (185.199.108–111.153)
- `www.wslvault.org` — CNAME to `bwalia.github.io`

GitHub Pages serves both and redirects the apex to `www`. Do not orange-cloud
(proxy) the records through Cloudflare, or the Pages TLS certificate cannot
issue.
