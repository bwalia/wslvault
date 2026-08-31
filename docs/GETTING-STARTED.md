# Getting started with WSLVault

A step-by-step guide for setting up WSLVault and signing in — written to be
followed by anyone, whether or not you write software.

You will copy and paste some commands into a terminal. You do not need to
understand them. Each one is explained in plain English first, and after each
step there is a **You should see** so you can tell it worked.

**Time needed:** about 20 minutes for the one-time setup, 2 minutes for each
person you add afterwards.

---

## Contents

1. [What WSLVault is](#1-what-wslvault-is)
2. [Who does what](#2-who-does-what)
3. [One-time setup: creating the master keys](#3-one-time-setup-creating-the-master-keys)
4. [Creating your first team and first user](#4-creating-your-first-team-and-first-user)
5. [Setting up the authenticator app on your phone](#5-setting-up-the-authenticator-app-on-your-phone)
6. [Signing in, day to day](#6-signing-in-day-to-day)
7. [Adding more people](#7-adding-more-people)
8. [Giving someone admin access](#8-giving-someone-admin-access)
9. [If something goes wrong](#9-if-something-goes-wrong)
10. [If you lose your phone](#10-if-you-lose-your-phone)
11. [Words explained](#11-words-explained)

---

## 1. What WSLVault is

Every company has passwords that its *software* needs — the password to the
customer database, the key to the payment provider, the login for the email
service. These are called **secrets**.

They usually end up somewhere they should not be: a spreadsheet, a chat
message, a configuration file on someone's laptop. Anyone who finds that file
has them all, and nobody can tell who looked.

WSLVault is a locked cabinet for those secrets. Software asks the cabinet for
what it needs, the cabinet checks whether it is allowed, hands it over, and
writes down that it did.

Three things follow from that, and they shape everything below:

- **The cabinet is locked with a master key.** You create that key in step 3.
  Lose it and the cabinet cannot be opened — not by you, not by anyone.
- **Each team gets its own compartment.** Team A cannot see Team B's secrets,
  even by accident.
- **People need two things to get in** — something they know (a key) and
  something they hold (their phone). That is step 5.

---

## 2. Who does what

Three kinds of access. Keeping them separate is the point, so it is worth
thirty seconds now.

| Role | Who | What they can do |
|---|---|---|
| **Platform admin** | You, setting this up | Create teams. Create people. Cannot read anyone's secrets. |
| **Team member** | Everyone else | Read and write **their own team's** secrets. Nothing else. |
| **Superuser** | Rare — emergencies only | Read across every team. Always needs a phone code. Every use is recorded. |

> A team having its own "admin" is **not** the same as being a platform admin.
> Your team's admin can manage your team; they cannot see other teams.

---

## 3. One-time setup: creating the master keys

You do this **once**, ever.

WSLVault needs several master keys to operate — one that locks the cabinet, one
that stamps sign-in passes, and a few others. They must be long, random, and
unique to your installation.

**Do not invent them yourself.** People pick predictable things. There is a
script that generates proper ones.

### Step 3.1 — Generate them

Open a terminal, go to the WSLVault folder, and run:

```bash
./scripts/gen-local-secrets.sh
```

**You should see:**

```
wrote .env.local (mode 600)

  Every value is freshly random. VAULT_ROOT_KEY now protects your local
  database — keep the file, or the data in it becomes unreadable.
```

This created a file called `.env.local` holding eight random keys.

### Step 3.2 — Understand the one that matters

Open `.env.local` if you like. The one to care about is the first:

```
VAULT_ROOT_KEY=...
```

**This is the key to the cabinet.** Everything else in the vault is locked with
it.

- **If you lose it**, every secret in the vault becomes permanently unreadable.
  There is no recovery, no reset link, no support line. That is the design — a
  cabinet somebody else can unlock is not a cabinet.
- **If someone steals it**, they can read everything.

So: back the file up somewhere safe, and do not email it, paste it into chat,
or commit it to git.

> The script will refuse to run a second time, on purpose. Generating a new
> master key would lock you out of everything the old one protected.

### Step 3.3 — Load them

```bash
set -a; . ./.env.local; set +a
```

This tells your terminal to use those keys. Nothing visible happens — that is
normal.

> **For a real deployment**, keys should not sit in a file at all. WSLVault
> supports splitting the master key into pieces held by different people, so no
> single person can open the vault alone. Ask your engineers about
> `POST /v1/sys/init`. The file approach is fine for trying it out.

---

## 4. Creating your first team and first user

Now start the vault and put someone in it.

### Step 4.1 — Start it

Follow [Local testing](operations/local-testing.md), or ask an engineer to
start it for you. When it is running you can open **http://localhost:3012** in a
browser and see a sign-in page.

### Step 4.2 — Create everything at once

```bash
./scripts/seed-local.sh
```

This creates a team, a person, their phone setup, the permissions, and a few
example secrets — all in one go.

**You should see**, at the end:

```
Done
   UI:      http://localhost:3012
   API key: wslv_veoD6lkUyxsNDGrc40NYj9HGMDUtbgISWkhPlPD4eGk
   Code:    022117   (valid ~30s)
```

That long `wslv_...` line is **your API key** — your username and password
rolled into one. It is also saved to a file called `.local-login`.

> **Write it down now.** For real users the key is shown once and never again —
> not because of a limitation, but so that nobody, including the system
> operator, can look it up later.

Safe to re-run. If the team already exists it reuses it, and it issues you a
fresh key.

---

## 5. Setting up the authenticator app on your phone

Your API key alone is not enough to sign in. You also need a 6-digit code from
your phone, which changes every 30 seconds. This means a stolen key on its own
is useless.

### Step 5.1 — Install an app

**Any of these work.** There is nothing to choose — they all do the same
standard thing, so pick whichever you or your company already use:

| App | Where |
|---|---|
| Google Authenticator | App Store / Play Store |
| Microsoft Authenticator | App Store / Play Store |
| 1Password, Bitwarden, Authy | If you already use one, it has this built in |

### Step 5.2 — Get your setup code

If you ran `seed-local.sh`, it is in `.local-login`:

```bash
grep TOTP_SECRET .local-login
```

**You should see** something like:

```
TOTP_SECRET   HMVNQ3SCBIALOE6PYRYAY6EEZPC24N5W
```

That is your setup code. Treat it like a password.

### Step 5.3 — Add it to the app

**Google Authenticator**
1. Open the app
2. Tap the **+** in the bottom-right
3. Tap **Enter a setup key**
4. **Account:** type `WSLVault`
5. **Your key:** type the code from step 5.2
6. Leave the type as **Time based**
7. Tap **Add**

**Microsoft Authenticator**
1. Open the app
2. Tap the **+** in the top-right
3. Choose **Other account (Google, Facebook, etc.)**
4. Tap **OR ENTER CODE MANUALLY**
5. **Account name:** `WSLVault`
6. **Secret key:** the code from step 5.2
7. Tap **Finish**

**1Password / Bitwarden**
Edit the WSLVault login item, add a one-time-password field, and paste the code.

### Step 5.4 — Check it worked

Your app should now show a 6-digit number under "WSLVault", counting down and
changing every 30 seconds.

**If it does, you are done.** That number is what you will type when signing in.

> **Prefer scanning a QR code?** An engineer can turn your setup code into one
> with `qrencode -t ANSIUTF8 "<the otpauth:// link>"`. Do **not** paste that
> link into a QR generator website — the website would then have your code.

### Step 5.5 — Save your backup codes

When your account was set up, eight **recovery codes** were generated. They look
like `R7MFFQL7-TP72XLUK`. In `.local-login` or the setup output.

Each works once, and only if you lose your phone. Print them, or put them in a
password manager. **Not** on the same phone.

---

## 6. Signing in, day to day

1. Open **http://localhost:3012**
2. Paste your API key (the long `wslv_...` line) → **Sign in**
3. The screen changes to **Two-factor authentication**
4. Open your authenticator app, read the current 6-digit number, type it
5. **Verify**

You are in.

**A few things to expect:**

- The code changes every 30 seconds. If it changes while you are typing, wait
  for the new one and use that.
- Each code works **once**. Re-entering the same one will be refused even
  within its 30 seconds — that is deliberate, so that someone who glimpses your
  screen cannot reuse it.
- Get it wrong and you go back to the key screen. That is also deliberate: the
  sign-in attempt is cancelled entirely rather than letting anyone keep
  guessing.

---

## 7. Adding more people

Each person gets their **own** key. Never share one.

Replace `NAME` with something recognisable, like `sarah-laptop`:

```bash
set -a; . ./.env.local; set +a

curl -sX POST localhost:18082/v1/api-keys \
  -H "X-Admin-Token: $VAULT_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"NAME","tenant_id":"YOUR-TEAM-ID","policies":["admin"],"mfa_required":true}'
```

**You should see** a response containing `"key": "wslv_..."`. Give that to the
person **securely** — a password manager, not email or chat.

`"mfa_required":true` means they must set up a phone app. Leave it in for
people. Leave it **out** only for automated systems, which cannot read a phone.

Then they follow [section 5](#5-setting-up-the-authenticator-app-on-your-phone)
with their own key.

---

## 8. Giving someone admin access

Two levels, and the difference matters.

### Team admin — usual

Someone who manages their own team's secrets. That is what
`"policies":["admin"]` in section 7 gives them. It stops at their team's edge.

### Superuser — rare

Someone who can read **every team's** secrets. Genuinely exceptional: emergency
recovery, or an investigation.

```bash
curl -sX POST localhost:18082/v1/api-keys \
  -H "X-Admin-Token: $VAULT_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"emergency-access","tenant_id":"YOUR-TEAM-ID","is_superuser":true}'
```

Built to be hard to misuse:

- **A phone app is compulsory.** The system refuses to create a superuser
  without it, whatever you ask for. A stolen key alone opens nothing.
- **Every use is recorded**, including which team was accessed.
- **They must name the team** they are acting on, each time. There is no
  ambient "see everything" mode.

Create as few as possible. Two is usually right — one is a single point of
failure, more than a few is a liability.

---

## 9. If something goes wrong

### "api key format is invalid; expected 'wslv_<base64url>'"

You pasted the wrong thing. **Nothing in `.env.local` signs you in** — those
are the machine's keys, not yours.

Yours starts with `wslv_` and is in `.local-login`, or was given to you when
your account was made.

`VAULT_ADMIN_TOKEN` is the usual mix-up: it looks similar and sits nearby, but
it is used for *creating* accounts, not signing in.

### "invalid or already-used code"

One of three things:

1. **The code expired.** Wait for your app to show a new one.
2. **You used it already.** Each code works once. Wait for the next.
3. **Your phone's clock is off.** Codes are time-based. Turn on automatic
   date & time in your phone settings.

### "challenge is unknown or expired"

You took more than two minutes between entering your key and your code. Start
again — this is a safety limit.

### "this key requires an authenticator; enrol one..."

Your key needs a phone app and none is set up yet. Go to
[section 5](#5-setting-up-the-authenticator-app-on-your-phone).

### "permission denied on secret/list"

You are signed in correctly, but nobody has said what you are allowed to read
yet. An admin needs to set your team's permissions — normal on a brand-new
team, and `seed-local.sh` does it for you.

### "Failed to unwrap tenant KEK — investigate immediately"

Serious. The master key does not match the data. Almost always because
`VAULT_ROOT_KEY` was changed or regenerated.

**Stop and restore the original `.env.local` from your backup.** If there is no
backup, the data cannot be recovered — that is what the master key means.

---

## 10. If you lose your phone

**You are not locked out.** Use one of the recovery codes from step 5.5.

1. Sign in with your API key as usual
2. At the 6-digit prompt, type a **recovery code** instead
3. You are in

Each code works once. Then ask an admin to reset your phone setup so you can
enrol your new device, and generate a fresh set of recovery codes.

**Out of recovery codes too?** An admin can clear your phone setup so you can
start again. Your secrets are untouched — only the phone step is reset.

---

## 11. Words explained

| Word | Plain meaning |
|---|---|
| **Secret** | A password or key that software needs — a database password, a payment key |
| **Vault** | The locked cabinet those secrets live in |
| **Tenant** | A team or project with its own compartment. One tenant cannot see another's |
| **API key** | Your personal sign-in credential. Starts `wslv_` |
| **TOTP / 2FA / MFA** | The 6-digit code from your phone. Proves it is really you |
| **Recovery code** | A one-time backup for when your phone is gone |
| **Master key** (`VAULT_ROOT_KEY`) | The key to the whole cabinet. Lose it, lose everything |
| **Policy** | The rule saying who may read or change what |
| **Superuser** | Someone who can reach every team. Rare, always needs a phone code, always recorded |
| **Seal / unseal** | Locking the vault so nothing can be read until enough key-holders re-open it together |

---

## Where to go next

| If you want to | Read |
|---|---|
| Run it on your own machine | [Local testing](operations/local-testing.md) |
| Understand roles in more depth | [Onboarding a tenant](operations/onboarding-a-tenant.md) |
| Deploy it properly | [Deployment](operations/deployment.md) |
| Know what is and is not built | [Status](STATUS.md) |
