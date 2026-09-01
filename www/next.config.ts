import type { NextConfig } from "next";

/**
 * Two build modes, mirroring the vantiq marketing site.
 *
 * Default: a normal Next dev/server build for local work.
 *
 * NEXT_STATIC_EXPORT=true: a static export for GitHub Pages, which serves files
 * rather than running a Node server. Deploy CI sets this.
 */
const isStaticExport = process.env.NEXT_STATIC_EXPORT === "true";

/** e.g. "/wslvault" for a GitHub project page. Empty for the custom domain. */
const basePath = process.env.NEXT_PUBLIC_BASE_PATH ?? "";

const nextConfig: NextConfig = {
  ...(isStaticExport
    ? {
        output: "export",
        // Pages has no image optimiser.
        images: { unoptimized: true },
        // Emits /path/index.html, so deep links resolve without rewrite rules.
        trailingSlash: true,
      }
    : {}),

  ...(basePath ? { basePath, assetPrefix: basePath } : {}),
};

export default nextConfig;
