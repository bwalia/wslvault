# WSLVault UI design system — "Vault steel"

The subject is a **secrets vault**: security hardware, cryptography, operator
tooling. The UI should feel like a precision instrument — calm, engineered,
legible — not a generic SaaS dashboard.

## Tokens (defined in `src/app/globals.css` — USE THESE, never raw slate-*)

| Token | Use |
|---|---|
| `bg-canvas` | app background |
| `bg-surface` | cards, modals, tables |
| `bg-surface-2` | table headers, wells, hover fills |
| `bg-surface-3` | pressed/selected fills |
| `border-line` | default hairlines |
| `border-line-strong` | emphasized borders |
| `text-ink` | primary text |
| `text-ink-muted` | secondary text (≥4.5:1 verified) |
| `text-ink-faint` | tertiary/meta text (≥4.5:1 verified) |
| `bg-steel`, `text-steel-ink`, `text-steel-ink-dim`, `border-steel-line`, `bg-steel-raised` | sidebar ONLY |
| `primary-*` | deep teal — actions, active nav, focus rings |
| `success-* / warn-* / danger-*` | status ONLY, never decoration; always paired with icon or label |

All tokens flip automatically with `.dark` — a component written with semantic
tokens needs **zero** `dark:` variants for color. (`dark:` is still fine for
non-token cases, but prefer tokens.)

## Typography

- Sans: IBM Plex Sans (`font-sans`, default). Weights 400/500/600/700.
- Mono: IBM Plex Mono (`font-mono`). **Every** secret path, tenant ID, key ID,
  UUID, token, fingerprint, duration, and count wears `font-mono`.
- Numbers in tables get `tabular` (utility class → tabular-nums).
- Page title: `text-2xl font-semibold tracking-tight text-ink`.
- Section heading: `text-sm font-semibold text-ink`.
- Table headers: `text-xs font-medium uppercase tracking-wide text-ink-faint`.
- Meta/labels: `text-xs text-ink-muted`.

## Voice (copy)

- Name what the user controls: "Create tenant", not "New".
- Empty states direct: "No secrets under this prefix yet. Write your first
  secret to see it here." + action button when the user can act.
- Errors say what happened and what to do next.

## Spacing & shape

- Page content: `max-w-7xl` (readability on wide monitors), `space-y-6`.
- Cards: `rounded-xl border border-line bg-surface` — NO drop shadows in the
  data plane; elevation is for overlays (modals/menus) only.
- Density: tables `px-4 py-2.5`; cards `px-5 py-4`.
- One accent per view: the primary button. Everything else is quiet.

## Components (already redesigned — import from `@/components/ui/*`)

Card, Button, Badge, StatusBadge (dot + label, color never alone), Input,
Modal, ConfirmModal, DataTable, EmptyState, PageHeader, Skeleton, StatCard,
CodeChip (new — inline mono identifier), Toolbar (new — filter row).

## Rules

1. No raw `slate-*` classes in pages. Use tokens.
2. No decorative icons in colored squircles — page headers are typographic.
3. Status = StatusBadge (dot + label) or icon + label. Never color alone.
4. Motion: `transition-colors` only; no entrance animations, no pulse except
   Skeleton.
5. Focus: every interactive element gets `focus-ring`.
6. Tables: header `bg-surface-2`, uppercase xs headers, `tabular` numerics,
   row hover `bg-surface-2`, identifiers in `font-mono text-[13px]`.
7. Dark mode comes free from tokens — do not write `dark:bg-slate-900` ever.
