const GITHUB = "https://github.com/bwalia/wslvault";
const DOCS = `${GITHUB}/tree/main/docs`;
/** Baked at Pages build time (git tag / describe / short SHA). Local default: dev. */
const SITE_VERSION = process.env.NEXT_PUBLIC_SITE_VERSION || "dev";
const SITE_SHA = process.env.NEXT_PUBLIC_SITE_SHA || "";


/* ── Inline icons (no icon library — keeps the static build dependency-free) ── */
type IconProps = { className?: string };
const I = (d: string) => ({ className }: IconProps) => (
  <svg className={className} width="20" height="20" viewBox="0 0 24 24" fill="none"
    stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    {d.split("|").map((p, i) => <path key={i} d={p} />)}
  </svg>
);
const LockIcon = I("M7 11V8a5 5 0 0 1 10 0v3|M5 11h14v9H5z");
const KeyIcon = I("M14 7a4 4 0 1 0-3.9 5H12l2 2 2-2 1.5 1.5|M20 7l-3 3");
const ShuffleIcon = I("M16 3h5v5|M4 20 21 3|M21 16v5h-5|M15 15l6 6|M4 4l5 5");
const CertIcon = I("M6 3h9l4 4v14H6z|M9 12h6|M9 16h4|M13 3v4h4");
const ClockIcon = I("M12 7v5l3 2|M12 21a9 9 0 1 1 0-18 9 9 0 0 1 0 18z");
const ShieldIcon = I("M12 3 5 6v6c0 4 3 7 7 9 4-2 7-5 7-9V6z|M9 12l2 2 4-4");
const GlobeIcon = I("M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z|M3 12h18|M12 3c3 3.5 3 14.5 0 18|M12 3c-3 3.5-3 14.5 0 18");
const BoltIcon = I("M13 2 4 14h7l-1 8 9-12h-7z");
const GitIcon = I("M6 3v12|M6 15a3 3 0 1 0 0 6 3 3 0 0 0 0-6z|M6 3a3 3 0 1 0 0 .001|M18 9a3 3 0 1 0 0 .001|M18 9v1a4 4 0 0 1-4 4H9");
const CheckIcon = I("M20 6 9 17l-5-5");

const features = [
  { icon: LockIcon, title: "Versioned KV secrets", body: "A Vault-compatible KV v2 engine: versioned reads and writes, check-and-set, soft-delete and destroy, per-path metadata — every value sealed before it touches disk." },
  { icon: KeyIcon, title: "Envelope encryption", body: "AES-256-GCM with a per-tenant key hierarchy. Data keys are wrapped under a tenant KEK, which is wrapped under a root key held only by the crypto service." },
  { icon: ShuffleIcon, title: "Transit engine", body: "Encryption as a service: encrypt, decrypt, sign and verify without the plaintext key ever leaving the vault. Keys rotate while old ciphertext stays readable." },
  { icon: CertIcon, title: "PKI & certificates", body: "Issue and manage a private CA, roles and short-lived certificates. CA private keys are envelope-encrypted under their own root, never stored in the clear." },
  { icon: ClockIcon, title: "Dynamic leases", body: "Every credential is a lease: issued, listed, renewed and revoked for real. Revoking a token stops it working immediately, not just flips a row." },
  { icon: ShieldIcon, title: "Two-factor auth & identity", body: "Self-service TOTP two-factor with recovery codes, over fine-grained policies on API keys and JWTs — plus SCIM, LDAP, OIDC, mTLS and cloud-workload auth. Identity comes from a signed, per-tenant token, never a header." },
];

const securityPoints = [
  { title: "Signed, tamper-evident audit", body: "Every operation joins a per-tenant hash chain signed with a dedicated key — a record cannot be altered or removed without breaking the chain." },
  { title: "Shamir-split custody", body: "The root key can be split into Shamir shares so no single operator can unseal the vault alone. It starts sealed and stays sealed until a quorum agrees." },
  { title: "Tenant isolation to the key layer", body: "A data key belongs to exactly one tenant; a cross-tenant request returns “not found” rather than another tenant’s data. Isolation holds even at the crypto service." },
  { title: "Zero plaintext at rest", body: "Secrets, transit keys and CA material are all encrypted before storage. A database dump yields ciphertext wrapped under keys the database never sees." },
];

const stack = ["Rust services", "gRPC + HTTP", "PostgreSQL", "Helm chart", "Kubernetes operator", "GitOps / Argo CD", "Prometheus metrics", "MCP server"];
const sdks = ["Go", "Python", "Rust", "TypeScript", "CLI"];

export default function Page() {
  return (
    <>
      {/* Nav */}
      <header className="nav">
        <div className="wrap nav-inner">
          <a className="brand" href="#top">
            <span className="brand-mark">
              <LockIcon className="" />
            </span>
            <span>WSL<span className="brand-accent">Vault</span></span>
          </a>
          <nav className="nav-links">
            <a className="hide-sm" href="#features">Features</a>
            <a className="hide-sm" href="#architecture">Architecture</a>
            <a className="hide-sm" href="#security">Security</a>
            <a className="hide-sm" href={DOCS}>Docs</a>
            <a className="nav-cta" href={GITHUB}>GitHub</a>
          </nav>
        </div>
      </header>

      {/* Hero */}
      <main id="top">
        <section className="hero">
          <div className="wrap">
            <span className="eyebrow"><span className="dot" /> Open-source · multi-region · self-hosted</span>
            <h1 className="hero-title">
              Secrets, encrypted per tenant.<br />
              <span className="grad">Replicated across regions.</span>
            </h1>
            <p className="hero-sub">
              WSLVault is a self-hosted secrets manager built on envelope encryption and a
              per-tenant key hierarchy — with dynamic leases, transit encryption, PKI, a
              signed audit trail, and active/active replication between regions. Driven from
              a CLI, four SDKs, or a web console with built-in two-factor auth.
            </p>
            <div className="hero-actions">
              <a className="btn btn-primary" href={GITHUB}><GitIcon className="" /> Get started on GitHub</a>
              <a className="btn btn-ghost" href="#architecture">See the architecture</a>
            </div>
            <div className="hero-meta">
              <span><CheckIcon className="check" /> Vault-compatible API</span>
              <span><CheckIcon className="check" /> Runs on Kubernetes</span>
              <span><CheckIcon className="check" /> No plaintext at rest</span>
            </div>

            {/* Terminal */}
            <div className="terminal" role="img" aria-label="Example WSLVault CLI session writing and reading a secret">
              <div className="terminal-bar">
                <span className="tdot r" /><span className="tdot y" /><span className="tdot g" />
                <span className="terminal-title">wslvault — kv</span>
              </div>
              <pre>
{`$ `}<span className="c-cmd">wslvault</span>{` login `}<span className="c-flag">--key</span>{` `}<span className="c-str">wslv_&hellip;</span>{`
`}<span className="c-ok">✓</span>{` authenticated as tenant `}<span className="c-str">acme</span>{`  region=`}<span className="c-str">manchester</span>{`

$ `}<span className="c-cmd">wslvault</span>{` kv put `}<span className="c-str">prod/db/creds</span>{` password=`}<span className="c-str">s3cr3t</span>{`
`}<span className="c-ok">✓</span>{` sealed with dek `}<span className="c-dim">01a0&hellip;93a7</span>{`  version=1

$ `}<span className="c-cmd">wslvault</span>{` kv get `}<span className="c-str">prod/db/creds</span>{`  `}<span className="c-flag">--region</span>{` london
`}<span className="c-dim"># same secret, decrypted in the peer region</span>{`
password = `}<span className="c-str">s3cr3t</span>{`   `}<span className="c-ok">replication_lag=14ms</span>
              </pre>
            </div>
          </div>
        </section>

        {/* Features — light canvas band mirrors the login form side */}
        <section id="features" className="band-canvas">
          <div className="wrap">
            <div className="section-head">
              <div className="kicker">One vault, every secret type</div>
              <h2>Everything a secret needs, behind one API</h2>
              <p className="section-sub">
                Static and dynamic secrets, encryption-as-a-service, a private CA, and the
                identity and policy layer to govern them — each engine sealed by the same
                per-tenant key hierarchy.
              </p>
            </div>
            <div className="grid cols-3">
              {features.map((f) => (
                <article className="card" key={f.title}>
                  <div className="card-icon"><f.icon className="" /></div>
                  <h3>{f.title}</h3>
                  <p>{f.body}</p>
                </article>
              ))}
            </div>
          </div>
        </section>

        {/* Architecture */}
        <section id="architecture">
          <div className="wrap">
            <div className="section-head">
              <div className="kicker">Active / active by design</div>
              <h2>Two regions, one mesh</h2>
              <p className="section-sub">
                Each region is a complete, independent stack — its own database, its own
                services, its own public hostname. They share nothing at runtime but key
                material, and each region&rsquo;s agent pulls the other&rsquo;s changes over the public edge.
              </p>
            </div>
            <div className="regions">
              <div className="region">
                <div className="region-name"><GlobeIcon className="" /> Region A</div>
                <div className="region-loc">manchester · active</div>
                <ul>
                  <li><CheckIcon className="check" /> Own PostgreSQL, node-local storage</li>
                  <li><CheckIcon className="check" /> Full service set, sealed at rest</li>
                  <li><CheckIcon className="check" /> Serves its own public endpoint</li>
                </ul>
              </div>
              <div className="sync">
                <span className="sync-badge"><BoltIcon className="" /><br />encrypted<br />replication</span>
              </div>
              <div className="region">
                <div className="region-name"><GlobeIcon className="" /> Region B</div>
                <div className="region-loc">london · active</div>
                <ul>
                  <li><CheckIcon className="check" /> Byte-identical key material</li>
                  <li><CheckIcon className="check" /> Reads secrets written anywhere</li>
                  <li><CheckIcon className="check" /> Fails over as a PoP-side change</li>
                </ul>
              </div>
            </div>
          </div>
        </section>

        <div className="wrap"><hr className="divider" /></div>

        {/* Security */}
        <section id="security">
          <div className="wrap">
            <div className="section-head">
              <div className="kicker">Security model</div>
              <h2>Encrypted where it matters, provable after the fact</h2>
              <p className="section-sub">
                The vault fails closed. Keys are wrapped, custody can be split, and every
                action is signed into a chain you can verify.
              </p>
            </div>
            <div className="sec-list">
              {securityPoints.map((s) => (
                <div className="sec-item" key={s.title}>
                  <span className="mk"><ShieldIcon className="" /></span>
                  <div>
                    <h4>{s.title}</h4>
                    <p>{s.body}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        <div className="wrap"><hr className="divider" /></div>

        {/* Ecosystem */}
        <section id="ecosystem">
          <div className="wrap">
            <div className="grid cols-2" style={{ alignItems: "center" }}>
              <div>
                <div className="kicker">Built for your stack</div>
                <h2>Cloud-native, and scriptable everywhere</h2>
                <p className="section-sub" style={{ marginBottom: 22 }}>
                  Ship it with the Helm chart and Kubernetes operator, drive it from GitOps,
                  scrape it with Prometheus, and reach it from your language of choice — or
                  from an AI agent over the built-in MCP server.
                </p>
                <div className="chips">
                  {stack.map((s) => <span className="chip" key={s}>{s}</span>)}
                </div>
              </div>
              <div className="card">
                <h3 style={{ marginBottom: 14 }}>Official SDKs &amp; CLI</h3>
                <div className="chips" style={{ marginBottom: 18 }}>
                  {sdks.map((s) => <span className="chip" key={s}>{s}</span>)}
                </div>
                <p style={{ color: "var(--ink-muted)", fontSize: 14.5, margin: 0 }}>
                  The same JSON contract across every client, generated from one set of
                  protobuf definitions — so a secret read in Go looks like a secret read in
                  TypeScript.
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* CTA */}
        <section>
          <div className="wrap">
            <div className="cta">
              <div className="kicker" style={{ marginBottom: 10 }}>Self-hosted &amp; open source</div>
              <h2>Stand up your own vault</h2>
              <p>
                Clone the repo, install the Helm chart, and unseal. The getting-started guide
                takes you from an empty cluster to your first sealed secret.
              </p>
              <div className="hero-actions">
                <a className="btn btn-primary" href={GITHUB}><GitIcon className="" /> View on GitHub</a>
                <a className="btn btn-ghost" href={DOCS}>Read the docs</a>
              </div>
            </div>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer>
        <div className="wrap foot-inner">
          <div className="brand" style={{ fontSize: 15 }}>
            <span className="brand-mark" style={{ width: 26, height: 26 }}><LockIcon className="" /></span>
            <span>WSL<span className="brand-accent">Vault</span></span>
          </div>
          <nav className="foot-links">
            <a href="#features">Features</a>
            <a href="#architecture">Architecture</a>
            <a href="#security">Security</a>
            <a href={DOCS}>Docs</a>
            <a href={GITHUB}>GitHub</a>
          </nav>
          <div className="foot-meta">
            <div className="foot-note">© {new Date().getFullYear()} WSLVault · Open source</div>
            <a
              className="foot-version"
              href={SITE_SHA ? `${GITHUB}/commit/${SITE_SHA}` : `${GITHUB}/tree/main`}
              title={SITE_SHA ? `Commit ${SITE_SHA}` : "Published site version"}
            >
              {SITE_VERSION}
            </a>
          </div>
        </div>
      </footer>
    </>
  );
}
