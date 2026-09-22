# WSLVault — YouTube intro (20 min)

Copy-paste pack for the first long-form introduction video.

## Suggested titles (pick one)

1. **Steal the Server — Not the Secrets | WSLVault Intro (20 Min)**
2. **WSLVault Explained: Multi-Tenant Secrets That Survive a Stolen Disk**
3. **Open-Source Secrets Manager Tour: Envelope Encryption, Tenants & HA Regions**

Primary recommendation: **#1** — curiosity + benefit in under 70 characters.

## Thumbnail

File: `wslvault-intro-thumbnail.jpg` (1280×720)

Hook text: **STEAL THE SERVER. / NOT THE SECRETS.**  
Brand: WSLVault · steel/brass · vault wheel · “20-MIN INTRO · OPEN SOURCE”

Upload this as the custom thumbnail before publishing.

---

## Description (paste into YouTube)

```
Steal the server. Not the secrets.

WSLVault is an open-source, self-hosted secrets manager built on AES-256-GCM envelope encryption and a per-tenant key hierarchy — so a stolen disk, database dump, or compromised host still leaves attackers with ciphertext they cannot open.

This 20-minute intro is for first-time users: what WSLVault is, why the security model matters, and how you drive it from the console, CLI, or SDKs.

What you’ll learn
• True multi-tenancy — Team A cannot decrypt Team B (cryptographic refusal, not “oops”)
• Envelope encryption — DEK → tenant KEK → root KEK (KMS / HSM / Shamir)
• KV secrets, transit encryption, PKI, dynamic leases, MFA
• Active/active multi-region replication
• Tamper-evident, hash-chained audit
• Why “steal the disk ≠ steal the secrets”

Links
🌐 Site: https://www.wslvault.org
💻 GitHub: https://github.com/bwalia/wslvault
📘 Docs: https://github.com/bwalia/wslvault/tree/main/docs
🚀 Getting started: https://github.com/bwalia/wslvault/blob/main/docs/GETTING-STARTED.md

Chapters
0:00 Why this matters (steal the server)
1:30 What WSLVault is
3:00 Envelope encryption & key hierarchy
5:30 Multi-tenancy that actually isolates
8:00 Console walkthrough (secrets, transit, PKI)
11:00 Identity, policies, leases & MFA
14:00 Regions, HA & audit
17:00 Deploy on Kubernetes
19:00 Where to go next

Built for operators who want Vault-compatible workflows without plaintext at rest — Rust services, Helm/GitOps, CLI + Go/Python/Rust/TypeScript SDKs, and a steel/brass web console.

If this helped, star the repo and share with someone who still stores secrets in env files.

#WSLVault #SecretsManagement #DevSecOps #OpenSource #Kubernetes #Encryption #HashiCorpVault #ZeroTrust #PKI #SelfHosted
```

---

## Short pinned comment (optional)

```
New here? Start at 0:00 for the “steal the server” security model, then jump to 8:00 for the console tour. Site → https://www.wslvault.org · GitHub → https://github.com/bwalia/wslvault
```

## Tags

```
WSLVault, secrets manager, envelope encryption, multi-tenant vault, open source vault, HashiCorp Vault alternative, Kubernetes secrets, DevSecOps, PKI, transit encryption, AES-256-GCM, self-hosted secrets, multi-region HA, tamper-evident audit, zero trust secrets
```

## End screen / cards (suggestions)

- Link to https://www.wslvault.org (#tour) for the 2-min silent product tour
- Link to Getting Started docs
- Subscribe CTA: “Next: deploy on your cluster”
