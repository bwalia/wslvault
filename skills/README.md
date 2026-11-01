# wslvault agent skills

Skills that let an AI coding agent (Claude Code, OpenAI Codex, Cursor, Gemini
CLI, and others) carry out wslvault operations for a human operator. They use
the open [Agent Skills](https://agentskills.io) format: a folder holding a
`SKILL.md`, plus any bundled scripts.

| Skill | What it does |
|---|---|
| [`wslvault-secrets`](wslvault-secrets/SKILL.md) | Adds secrets for a tenant's apps, services and DTAP environments (INT/TEST/ACC/PROD). Creates the tenant, or attaches to an existing tenant with the same name. Every change needs MFA and a typed approval, and every run can be rolled back. |

## Install

A skill is a folder. Installing it means copying the folder to a place where
your agent looks for skills. Copy the **whole folder**, not only `SKILL.md`,
because the skill runs its bundled `scripts/wsv.py`.

```bash
# Pick the directory for your agent:
#   Claude Code          ~/.claude/skills            (project: .claude/skills)
#   Codex CLI, Cursor    ~/.agents/skills            (project: .agents/skills)
#   Cursor only          ~/.cursor/skills            (project: .cursor/skills)
#   Gemini CLI, others   ~/.agents/skills
D=~/.agents/skills/wslvault-secrets

base=https://raw.githubusercontent.com/bwalia/wslvault/main/skills/wslvault-secrets
mkdir -p "$D/scripts" "$D/examples"
curl -fsSL "$base/SKILL.md"                       -o "$D/SKILL.md"
curl -fsSL "$base/scripts/wsv.py"                 -o "$D/scripts/wsv.py"
curl -fsSL "$base/examples/manifest.example.json" -o "$D/examples/manifest.example.json"
shasum -a 256 "$D/scripts/wsv.py"     # compare with the copy in the repo before first use
```

Cursor also reads `~/.claude/skills`, so one copy there covers both Claude
Code and Cursor. If you use several agents, keep one real copy and symlink it
into the other directories.

**No install at all:** give any agent the link
`https://github.com/bwalia/wslvault/blob/main/skills/wslvault-secrets/SKILL.md`
and ask it to follow the skill. It fetches the helper script itself and shows
you the script's checksum before running it.

If the repository is private, raw URLs need a token. Clone the repository, or
use `gh api`, instead of `curl`.

## Use

Ask in plain words, for example:

> Add secrets for tenant `acme`: app `billing` with services `api` and
> `worker`, all four environments. The values are in `./envs/*.env`.

The agent will:

1. ask for anything missing, including the vault API endpoint if you have
   none configured;
2. write a manifest that **references** where each value comes from (files,
   `.env` files, env vars, or "generate"). Values never go into the chat;
3. log in with your superuser key (from a `0600` file you create) and your
   **authenticator code**;
4. show you a full plan: tenants to create or reuse, and secrets to create or
   update, by key name;
5. wait for you to type `APPLY <run> <hash>`, then ask for a **new**
   authenticator code;
6. apply the plan, journalling each change, and stop at the first error;
7. on request, roll the run back with `ROLLBACK <run>` and another
   authenticator code.

## Security model, briefly

- **The agent never sees secret values, API keys or the root token.** The
  helper reads them from files inside its own process. Only the 6-digit MFA
  code goes through the chat: it is single-use and expires within seconds.
- **The agent cannot approve on its own.** Applying needs a session minted with
  a TOTP code *after* the typed approval, and the code must differ from the
  one used for planning. An agent cannot produce a TOTP code.
- **The harness is a second gate.** Every mutating step is a separate shell
  command, so the agent harness's permission prompt shows each one to the
  operator.
- **Least surprise on existing data.** Keys are merged into existing secrets,
  never replaced wholesale. Writes use check-and-set. `generate:` never
  rotates an existing value.
- **Rollback** restores updated secrets to their earlier content,
  soft-deletes created secrets (or destroys them with `--destroy`), and
  soft-deletes tenants the run created.

## Roadmap: wslvault as a service (note only)

We may later offer wslvault as a hosted, multi-tenant **Vault as a Service**,
so people can try it and keep secrets in it without running their own
deployment. It does not exist yet. When it does, the skill's "no vault
endpoint" path will point to a sign-up that provisions a tenant and an
MFA-enrolled key.
