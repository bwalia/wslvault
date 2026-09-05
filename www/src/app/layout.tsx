import type { Metadata, Viewport } from "next";
import { Lexend, Source_Sans_3, IBM_Plex_Mono } from "next/font/google";
import "./globals.css";

const lexend = Lexend({
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
  variable: "--font-display",
  display: "swap",
});

const sourceSans = Source_Sans_3({
  subsets: ["latin"],
  weight: ["400", "500", "600"],
  variable: "--font-sans",
  display: "swap",
});

const plexMono = IBM_Plex_Mono({
  subsets: ["latin"],
  weight: ["400", "500", "600"],
  variable: "--font-plex-mono",
  display: "swap",
});

const SITE_URL = "https://www.wslvault.org";
const DESCRIPTION =
  "WSLVault is an open-source, multi-region secrets manager: AES-256-GCM envelope encryption with a per-tenant key hierarchy, dynamic secrets and leases, transit encryption, PKI, self-service two-factor auth, and active/active cross-region replication — via CLI, SDKs, or a web console.";

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: {
    default: "WSLVault — Secrets, encrypted per tenant, across regions",
    template: "%s · WSLVault",
  },
  description: DESCRIPTION,
  keywords: [
    "secrets manager",
    "vault",
    "envelope encryption",
    "AES-256-GCM",
    "multi-region",
    "high availability",
    "PKI",
    "dynamic secrets",
    "transit encryption",
    "Kubernetes",
  ],
  alternates: { canonical: "/" },
  openGraph: {
    type: "website",
    url: SITE_URL,
    title: "WSLVault — Secrets, encrypted per tenant, across regions",
    description: DESCRIPTION,
    siteName: "WSLVault",
  },
  twitter: {
    card: "summary_large_image",
    title: "WSLVault — Secrets, encrypted per tenant, across regions",
    description: DESCRIPTION,
  },
  robots: { index: true, follow: true },
};

export const viewport: Viewport = {
  themeColor: "#11161d",
  colorScheme: "dark",
};

const structuredData = {
  "@context": "https://schema.org",
  "@type": "SoftwareApplication",
  name: "WSLVault",
  applicationCategory: "SecurityApplication",
  operatingSystem: "Linux, Kubernetes",
  description: DESCRIPTION,
  url: SITE_URL,
  offers: { "@type": "Offer", price: "0", priceCurrency: "USD" },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html
      lang="en"
      className={`${lexend.variable} ${sourceSans.variable} ${plexMono.variable}`}
    >
      <body>
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(structuredData) }}
        />
        {children}
      </body>
    </html>
  );
}
