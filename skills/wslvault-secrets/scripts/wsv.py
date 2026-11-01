#!/usr/bin/env python3
"""wsv.py - helper for the `wslvault-secrets` agent skill.

Onboards secrets into a wslvault deployment for a tenant, its apps, services
and DTAP environments (INT, TEST, ACC, PROD), with a human in the loop at every
step that changes anything.

Design rules (see SKILL.md for the full procedure):

* Secret VALUES never leave this process. They are resolved from files,
  dotenv files, environment variables or generated here, and are never printed,
  logged, written to the plan or written to the journal. An agent driving this
  script sees key names, paths and versions, never values.
* Nothing is written without (1) a plan the operator has read, (2) an approval
  phrase that is tied to the plan's hash, and (3) a session minted with a fresh
  TOTP code *after* that approval. The agent cannot make up a TOTP code, so the
  code is the step that proves a human approved.
* Every change is appended to a journal before the next one is made, so
  `rollback` can undo a partial run in reverse order.

Standard library only. Python 3.8+.
"""

from __future__ import annotations

import argparse
import base64
import datetime as _dt
import hashlib
import json
import os
import re
import secrets as _secrets
import ssl
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

VERSION = "1.0.0"

ENVS = ("int", "test", "acc", "prod")
SLUG_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")
KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,127}$")
PATH_RE = re.compile(r"^[a-z0-9][a-z0-9._/-]{0,254}$")
RUN_RE = re.compile(r"^[a-z0-9-]{8,64}$")
SOURCE_RE = re.compile(r"^(generate|env|file|dotenv):.+$")

# A session is accepted for this long after it was minted. The server-side
# token lives an hour; the skill wants approvals to be fresh.
SESSION_MAX_AGE = {"plan": 3300, "apply": 900, "rollback": 900}

HOME = Path(os.environ.get("WSLVAULT_HOME", Path.home() / ".wslvault"))
RUNS = HOME / "runs"


# --------------------------------------------------------------------------- #
# Small utilities
# --------------------------------------------------------------------------- #


class Fail(Exception):
    """A user-facing failure. Printed without a traceback."""


def now() -> float:
    return time.time()


def iso(ts: float) -> str:
    return _dt.datetime.fromtimestamp(ts, _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def write_private(path: Path, data: str | bytes) -> None:
    """Write a file only the current user can read."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    mode = "wb" if isinstance(data, bytes) else "w"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, mode) as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())


def read_json(path: Path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def check_private(path: Path) -> None:
    if os.name != "posix":
        return
    mode = path.stat().st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise Fail(
            f"{path} is readable by other users. Run: chmod 600 '{path}'"
        )


def run_dir(run_id: str) -> Path:
    if not RUN_RE.match(run_id or ""):
        raise Fail(f"invalid run id: {run_id!r}")
    rd = RUNS / run_id
    if not rd.is_dir():
        raise Fail(f"no such run: {run_id} (looked in {rd})")
    return rd


def say(msg: str = "") -> None:
    print(msg, flush=True)


# --------------------------------------------------------------------------- #
# Endpoint configuration
# --------------------------------------------------------------------------- #


def endpoints() -> tuple[str, str]:
    base = os.environ.get("VAULT_ADDR", "").rstrip("/")
    identity = os.environ.get("WSLVAULT_IDENTITY_ADDR", base).rstrip("/")
    secrets = os.environ.get("WSLVAULT_SECRETS_ADDR", base).rstrip("/")
    if not identity or not secrets:
        raise Fail(
            "No wslvault API endpoint configured.\n"
            "Ask the operator for their vault API endpoint and set it, e.g.\n"
            "  export VAULT_ADDR=https://vault.example.com\n"
            "If identity-service and secret-engine are on different hosts or ports\n"
            "(typical for local docker-compose), set WSLVAULT_IDENTITY_ADDR and\n"
            "WSLVAULT_SECRETS_ADDR instead (e.g. http://localhost:8082 and :8081)."
        )
    for u in (identity, secrets):
        p = urllib.parse.urlparse(u)
        if p.scheme not in ("http", "https") or not p.netloc:
            raise Fail(f"endpoint is not an http(s) URL: {u}")
        if p.scheme == "http" and p.hostname not in ("localhost", "127.0.0.1", "::1"):
            if os.environ.get("WSLVAULT_ALLOW_HTTP") != "1":
                raise Fail(
                    f"refusing plain http to a non-local host ({u}); credentials would "
                    "cross the network unencrypted. Use https, or set "
                    "WSLVAULT_ALLOW_HTTP=1 if this is a trusted private network."
                )
    return identity, secrets


def ssl_context() -> ssl.SSLContext:
    ca = os.environ.get("WSLVAULT_CA_BUNDLE")
    return ssl.create_default_context(cafile=ca) if ca else ssl.create_default_context()


def http(method: str, url: str, headers: dict | None = None, body=None, timeout: int = 30):
    """Returns (status, parsed_json_or_text). Never raises for HTTP status codes."""
    hdrs = {"Accept": "application/json", "User-Agent": f"wslvault-secrets-skill/{VERSION}"}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        hdrs["Content-Type"] = "application/json"
    hdrs.update(headers or {})
    req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl_context()) as resp:
            raw = resp.read()
            status = resp.status
    except urllib.error.HTTPError as e:
        raw = e.read()
        status = e.code
    except urllib.error.URLError as e:
        raise Fail(f"cannot reach {url}: {e.reason}")
    try:
        parsed = json.loads(raw) if raw else None
    except ValueError:
        parsed = raw.decode(errors="replace")[:500]
    return status, parsed


def err_text(parsed) -> str:
    if isinstance(parsed, dict):
        return str(parsed.get("message") or parsed.get("code") or parsed)[:300]
    return str(parsed)[:300]


def q(path: str) -> str:
    return urllib.parse.quote(path, safe="/")


# --------------------------------------------------------------------------- #
# Credentials and sessions
# --------------------------------------------------------------------------- #


def key_file() -> Path:
    return Path(os.environ.get("WSLVAULT_KEY_FILE", HOME / "superuser.key")).expanduser()


def root_token_file() -> Path | None:
    p = os.environ.get("WSLVAULT_ROOT_TOKEN_FILE")
    return Path(p).expanduser() if p else None


def read_secret_file(path: Path, what: str) -> str:
    if not path.is_file():
        raise Fail(
            f"{what} file not found: {path}\n"
            f"The OPERATOR must create it themselves (never paste it into the chat):\n"
            f"  mkdir -p '{path.parent}' && umask 077 && "
            f"pbpaste > '{path}'   # or: read -rs V && printf %s \"$V\" > '{path}'"
        )
    check_private(path)
    value = path.read_text(encoding="utf-8").strip()
    if not value:
        raise Fail(f"{what} file {path} is empty")
    return value


def session_path(rd: Path, purpose: str) -> Path:
    return rd / f"session.{purpose}.json"


def load_session(rd: Path, purpose: str) -> dict:
    sp = session_path(rd, purpose)
    if not sp.exists():
        raise Fail(
            f"no '{purpose}' session for this run. Run `login {rd.name} --purpose {purpose}` "
            f"and ask the operator for a fresh authenticator code."
        )
    s = read_json(sp)
    age = now() - s["issued_at"]
    if age > SESSION_MAX_AGE[purpose]:
        sp.unlink(missing_ok=True)
        raise Fail(
            f"the '{purpose}' session is {int(age)}s old (limit {SESSION_MAX_AGE[purpose]}s). "
            f"Log in again with a fresh authenticator code."
        )
    return s


def auth_headers(session: dict, tenant_id: str | None = None) -> dict:
    h = {"Authorization": f"Bearer {session['token']}"}
    if tenant_id:
        # Superuser crossing into the target tenant. Ignored for non-superusers
        # and audited at WARN by the server for superusers.
        h["X-Vault-Act-Tenant"] = tenant_id
    return h


def admin_headers(session: dict) -> dict:
    """Tenant administration (list/create/delete) uses the root (bootstrap)
    token when the operator supplied one, otherwise the MFA'd superuser
    session."""
    rf = root_token_file()
    if rf:
        return {"X-Admin-Token": read_secret_file(rf, "root token")}
    return auth_headers(session)


# --------------------------------------------------------------------------- #
# Manifest
# --------------------------------------------------------------------------- #


def tenant_for_env(m: dict, env: str) -> str:
    if m["layout"] == "single":
        return m["tenant"]
    return f"{m['tenant']}-prod" if env == "prod" else m["tenant"]


def tenant_spec(m: dict, slug: str) -> dict:
    """Body for POST /v1/tenants when the tenant does not exist yet."""
    if m["layout"] == "single":
        kind, allowed, default = "project", ["INT", "TEST", "ACC", "PROD"], "INT"
    elif slug.endswith("-prod") and slug == f"{m['tenant']}-prod":
        kind, allowed, default = "production", ["PROD"], "PROD"
    else:
        kind, allowed, default = "project", ["INT", "TEST", "ACC"], "INT"
    display = m.get("display_name") or m["tenant"]
    if kind == "production" and m["layout"] != "single":
        display = f"{display} (PROD)"
    return {
        "slug": slug,
        "display_name": display,
        "tier": m.get("tier", "shared"),
        "root_key_id": f"{slug}-kek",
        "tenant_kind": kind,
        "allowed_environments": allowed,
        "default_environment": default,
        "tags": list(m.get("tenant_tags", [])) + ["managed-by:wslvault-secrets-skill"],
    }


def subst(template: str, app: str, service: str, env: str) -> str:
    return (
        template.replace("{app}", app)
        .replace("{service}", service)
        .replace("{env}", env)
        .replace("{ENV}", env.upper())
    )


def validate_manifest(m: dict) -> dict:
    """Validate and normalise. Raises Fail with every problem found."""
    problems: list[str] = []
    if not isinstance(m, dict):
        raise Fail("manifest must be a JSON object")
    tenant = m.get("tenant", "")
    if not SLUG_RE.match(tenant):
        problems.append("tenant: must be lowercase letters, digits and hyphens (e.g. 'acme')")
    m.setdefault("layout", "split")
    if m["layout"] not in ("split", "single"):
        problems.append("layout: must be 'split' (PROD in <tenant>-prod) or 'single'")
    m.setdefault("path_template", "{app}/{service}/{env}")
    if "{env}" not in m["path_template"] and "{ENV}" not in m["path_template"]:
        problems.append("path_template must contain {env}: paths are unique per tenant, so "
                        "INT and TEST would otherwise overwrite each other")
    envs = m.setdefault("environments", list(ENVS))
    if not envs or any(e not in ENVS for e in envs):
        problems.append(f"environments: subset of {list(ENVS)}")
    apps = m.get("apps")
    if not isinstance(apps, list) or not apps:
        problems.append("apps: at least one app is required")
        apps = []
    for ai, app in enumerate(apps):
        an = app.get("name", "")
        if not NAME_RE.match(an):
            problems.append(f"apps[{ai}].name: lowercase name required")
        services = app.get("services")
        if not isinstance(services, list) or not services:
            problems.append(f"apps[{ai}] ({an}): at least one service is required")
            continue
        for si, svc in enumerate(services):
            where = f"{an}/{svc.get('name', '?')}"
            if not NAME_RE.match(svc.get("name", "")):
                problems.append(f"apps[{ai}].services[{si}].name: lowercase name required")
            senvs = svc.setdefault("environments", app.get("environments", envs))
            if any(e not in envs for e in senvs):
                problems.append(f"{where}: environments must be a subset of the manifest's")
            sec = svc.setdefault("secrets", {})
            fd = svc.setdefault("from_dotenv", {})
            if not sec and not fd:
                problems.append(f"{where}: needs 'secrets' and/or 'from_dotenv'")
            if not isinstance(fd, dict) or any(k not in ENVS for k in fd):
                problems.append(f"{where}: from_dotenv maps env (int/test/acc/prod) -> .env path")
            for key, spec in sec.items():
                if not KEY_RE.match(key):
                    problems.append(f"{where}: bad key name {key!r}")
                specs = spec.values() if isinstance(spec, dict) else [spec]
                if isinstance(spec, dict) and any(k not in ENVS for k in spec):
                    problems.append(f"{where}.{key}: per-env map keys must be int/test/acc/prod")
                for s in specs:
                    if not isinstance(s, str) or not SOURCE_RE.match(s):
                        problems.append(
                            f"{where}.{key}: value source must be generate:N, env:NAME, "
                            f"file:PATH or dotenv:PATH#KEY. Literal values are not allowed "
                            f"in the manifest so it is safe to show to an agent."
                        )
    if problems:
        raise Fail("manifest problems:\n  - " + "\n  - ".join(problems))
    return m


def expand_targets(m: dict) -> list[dict]:
    """One target per (app, service, env): a single KV secret holding a JSON
    object of KEY -> value."""
    out = []
    for app in m["apps"]:
        for svc in app["services"]:
            for env in svc["environments"]:
                keys: dict[str, str] = {}
                dotenv = svc["from_dotenv"].get(env)
                if dotenv:
                    keys["*"] = f"dotenv-all:{subst(dotenv, app['name'], svc['name'], env)}"
                for key, spec in svc["secrets"].items():
                    s = spec.get(env) if isinstance(spec, dict) else spec
                    if s is None:
                        continue
                    keys[key] = subst(s, app["name"], svc["name"], env)
                if not keys:
                    continue
                path = subst(m["path_template"], app["name"], svc["name"], env).lower()
                if not PATH_RE.match(path) or "//" in path or ".." in path:
                    raise Fail(f"invalid secret path produced by path_template: {path!r}")
                tags = sorted(set(m.get("tags", []) + app.get("tags", []) + svc.get("tags", [])
                                  + [f"app:{app['name']}", f"service:{svc['name']}"]))
                out.append({
                    "tenant_slug": tenant_for_env(m, env),
                    "env": env,
                    "environment": env.upper(),
                    "app": app["name"],
                    "service": svc["name"],
                    "path": path,
                    "sources": keys,
                    "tags": tags,
                })
    seen = set()
    for t in out:
        k = (t["tenant_slug"], t["path"])
        if k in seen:
            raise Fail(f"two targets map to the same secret {k}; fix path_template")
        seen.add(k)
    return out


# --------------------------------------------------------------------------- #
# Value resolution - values stay in this process
# --------------------------------------------------------------------------- #


def parse_dotenv(path: Path) -> dict[str, str]:
    out = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        k, v = k.strip(), v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
            quote, v = v[0], v[1:-1]
            if quote == '"':
                v = v.replace("\\n", "\n")
        elif " #" in v:
            v = v.split(" #", 1)[0].rstrip()
        if KEY_RE.match(k):
            out[k] = v
    return out


class Resolver:
    def __init__(self, base: Path):
        self.base = base
        self._dotenv_cache: dict[Path, dict[str, str]] = {}

    def _path(self, p: str) -> Path:
        pp = Path(p).expanduser()
        return pp if pp.is_absolute() else (self.base / pp)

    def _dotenv(self, p: str) -> dict[str, str]:
        path = self._path(p).resolve()
        if path not in self._dotenv_cache:
            if not path.is_file():
                raise Fail(f"dotenv file not found: {path}")
            self._dotenv_cache[path] = parse_dotenv(path)
        return self._dotenv_cache[path]

    def is_generated(self, source: str) -> bool:
        return source.startswith("generate:")

    def check(self, source: str) -> None:
        """Verify a source is resolvable without returning its value."""
        self.resolve(source)

    def expand_all(self, sources: dict[str, str]) -> dict[str, str]:
        """Expand dotenv-all into individual keys. Returns key -> source."""
        out = {}
        if "*" in sources:
            p = sources["*"].split(":", 1)[1]
            for k in self._dotenv(p):
                out[k] = f"dotenv:{p}#{k}"
        out.update({k: v for k, v in sources.items() if k != "*"})
        return out

    def resolve(self, source: str) -> str:
        kind, _, arg = source.partition(":")
        if kind == "generate":
            if not arg.isdigit() or not 16 <= int(arg) <= 256:
                raise Fail(f"{source}: generate:N needs N between 16 and 256 bytes")
            return _secrets.token_urlsafe(int(arg))
        if kind == "env":
            if arg not in os.environ:
                raise Fail(f"{source}: environment variable {arg} is not set in the agent's shell")
            return os.environ[arg]
        if kind == "file":
            p = self._path(arg)
            if not p.is_file():
                raise Fail(f"{source}: file not found ({p})")
            return p.read_text(encoding="utf-8").rstrip("\r\n")
        if kind == "dotenv":
            p, sep, k = arg.rpartition("#")
            if not sep:
                raise Fail(f"{source}: use dotenv:PATH#KEY")
            d = self._dotenv(p)
            if k not in d:
                raise Fail(f"{source}: key {k} not found in that dotenv file")
            return d[k]
        raise Fail(f"unknown value source: {source.split(':', 1)[0]}")


# --------------------------------------------------------------------------- #
# Vault operations
# --------------------------------------------------------------------------- #


def list_tenants(identity: str, session: dict) -> list[dict]:
    st, body = http("GET", f"{identity}/v1/tenants", admin_headers(session))
    if st == 403 or st == 401:
        raise Fail(
            f"listing tenants was refused (HTTP {st}): {err_text(body)}\n"
            "Tenant administration needs a superuser key (MFA) or the root token. "
            "If this deployment has no superuser yet, the operator can put the root "
            "(VAULT_ADMIN_TOKEN) token in a 0600 file and set WSLVAULT_ROOT_TOKEN_FILE."
        )
    if st != 200 or not isinstance(body, list):
        raise Fail(f"could not list tenants (HTTP {st}): {err_text(body)}")
    return body


def read_current(secrets: str, session: dict, tenant_id: str, path: str):
    """Returns (metadata|None, data_dict|None). data is the decoded JSON object.
    Raises Fail if the existing secret is not a JSON object (cannot merge)."""
    h = auth_headers(session, tenant_id)
    st, meta = http("GET", f"{secrets}/v1/secret/metadata/{q(path)}", h)
    if st == 404:
        return None, None
    if st != 200:
        raise Fail(f"metadata read for {path} failed (HTTP {st}): {err_text(meta)}")
    st, body = http("GET", f"{secrets}/v1/secret/data/{q(path)}", h)
    if st == 404:
        # Current version soft-deleted: treat as an update with an empty object.
        return meta, {}
    if st != 200:
        raise Fail(f"reading {path} failed (HTTP {st}): {err_text(body)}")
    try:
        data = json.loads(base64.b64decode(body["data"]))
    except Exception:
        raise Fail(
            f"{path} exists but does not hold a JSON object, so keys cannot be merged "
            f"into it safely. Choose a different path_template or migrate it by hand."
        )
    if not isinstance(data, dict):
        raise Fail(f"{path} exists but is not a JSON object; refusing to merge")
    return meta, data


def write_secret(secrets: str, session: dict, tenant_id: str, path: str,
                 data: dict, environment: str, tags: list[str], cas: int | None) -> int:
    body = {
        "data": base64.b64encode(json.dumps(data, sort_keys=True).encode()).decode(),
        "environment": environment,
        "tags": tags,
        "metadata": {"managed-by": "wslvault-secrets-skill"},
    }
    if cas is not None:
        body["cas"] = cas
    st, resp = http("POST", f"{secrets}/v1/secret/data/{q(path)}",
                    auth_headers(session, tenant_id), body)
    del body
    if st == 409:
        raise Fail(f"{path}: changed by someone else since the plan (CAS mismatch). Re-plan.")
    if st not in (200, 201):
        raise Fail(f"writing {path} failed (HTTP {st}): {err_text(resp)}")
    return int(resp.get("version")) if isinstance(resp, dict) and resp.get("version") else -1


# --------------------------------------------------------------------------- #
# Journal
# --------------------------------------------------------------------------- #


def journal_append(rd: Path, entry: dict) -> None:
    entry = {"ts": iso(now()), **entry}
    line = json.dumps(entry, sort_keys=True) + "\n"
    fd = os.open(rd / "journal.jsonl", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a") as fh:
        fh.write(line)
        fh.flush()
        os.fsync(fh.fileno())


def journal_read(rd: Path) -> list[dict]:
    p = rd / "journal.jsonl"
    if not p.exists():
        return []
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()]


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #


def cmd_preflight(_a) -> None:
    say(f"wsv.py {VERSION}, Python {sys.version.split()[0]}")
    identity, secrets = endpoints()
    say(f"identity endpoint: {identity}")
    say(f"secrets endpoint:  {secrets}")
    st, body = http("GET", f"{secrets}/v1/sys/health")
    say(f"secret-engine health: HTTP {st} {err_text(body) if st != 200 else 'ok'}")
    st, body = http("GET", f"{identity}/v1/identity/.well-known/jwks.json")
    say(f"identity-service JWKS: HTTP {st}")
    kf = key_file()
    say(f"superuser key file: {kf} ({'present' if kf.is_file() else 'MISSING'})")
    rf = root_token_file()
    if rf:
        say(f"root token file: {rf} ({'present' if rf.is_file() else 'MISSING'})")
    if st == 0:
        raise Fail("endpoint unreachable")


def cmd_init(a) -> None:
    mpath = Path(a.manifest).expanduser().resolve()
    if not mpath.is_file():
        raise Fail(f"manifest not found: {mpath}")
    raw = mpath.read_bytes()
    m = validate_manifest(json.loads(raw))
    endpoints()
    run_id = f"{m['tenant'][:30]}-{time.strftime('%Y%m%d-%H%M%S')}-{_secrets.token_hex(2)}"
    rd = RUNS / run_id
    rd.mkdir(parents=True, mode=0o700)
    write_private(rd / "manifest.json", raw)
    write_private(rd / "run.json", json.dumps({
        "run_id": run_id,
        "created_at": now(),
        "manifest_source": str(mpath),
        "manifest_dir": str(mpath.parent),
        "manifest_sha256": sha256_bytes(raw),
        "identity": endpoints()[0],
        "secrets": endpoints()[1],
    }, indent=2))
    say(f"RUN_ID={run_id}")
    say(f"run directory: {rd}")


def cmd_login(a) -> None:
    rd = run_dir(a.run)
    run = read_json(rd / "run.json")
    api_key = read_secret_file(key_file(), "superuser API key")
    st, body = http("POST", f"{run['identity']}/v1/auth/api-key", body={"api_key": api_key})
    del api_key
    if st != 200:
        raise Fail(f"login refused (HTTP {st}): {err_text(body)}")
    if not (isinstance(body, dict) and body.get("mfa_required") and body.get("challenge")):
        # A token came back without a second factor. Discard it.
        raise Fail(
            "this API key did not require MFA. The skill only accepts MFA-protected "
            "keys; superuser keys always require MFA. Enrol an authenticator "
            "(/v1/auth/mfa/totp/enroll) or use a superuser key."
        )
    write_private(rd / f"challenge.{a.purpose}", body["challenge"])
    say(f"MFA_REQUIRED purpose={a.purpose} expires_in={body.get('expires_in_seconds', 120)}s")
    say("Ask the operator for the CURRENT 6-digit code from their authenticator app.")


def cmd_mfa(a) -> None:
    rd = run_dir(a.run)
    run = read_json(rd / "run.json")
    code = (a.code or "").strip().replace(" ", "")
    if not re.match(r"^[A-Za-z0-9-]{6,32}$", code):
        raise Fail("that does not look like an authenticator or recovery code")
    cp = rd / f"challenge.{a.purpose}"
    if not cp.exists():
        raise Fail(f"no pending challenge; run `login {a.run} --purpose {a.purpose}` first")
    if a.purpose in ("apply", "rollback"):
        prev = rd / "session.plan.json"
        if prev.exists() and read_json(prev).get("code_sha") == sha256_bytes(code.encode()):
            raise Fail("that is the same code used for planning; wait for the next code")
    challenge = cp.read_text().strip()
    cp.unlink()  # single use, server-side too
    st, body = http("POST", f"{run['identity']}/v1/auth/mfa/totp",
                    body={"challenge": challenge, "code": code})
    if st != 200 or not isinstance(body, dict) or not body.get("token"):
        raise Fail(
            f"MFA rejected (HTTP {st}): {err_text(body)}. The challenge is now spent; "
            f"run login again and use the NEXT code."
        )
    sess = {
        "purpose": a.purpose,
        "issued_at": now(),
        "token": body["token"],
        "tenant_id": body.get("tenant_id"),
        "policies": body.get("policies", []),
        "expires_at": body.get("expires_at"),
        "code_sha": sha256_bytes(code.encode()),
    }
    write_private(session_path(rd, a.purpose), json.dumps(sess))
    say(f"AUTHENTICATED purpose={a.purpose} home_tenant={sess['tenant_id']} "
        f"policies={','.join(sess['policies'])} token_expires={sess['expires_at']}")


def cmd_plan(a) -> None:
    rd = run_dir(a.run)
    run = read_json(rd / "run.json")
    session = load_session(rd, "plan")
    raw = (rd / "manifest.json").read_bytes()
    m = validate_manifest(json.loads(raw))
    resolver = Resolver(Path(run["manifest_dir"]))
    targets = expand_targets(m)

    tenants = list_tenants(run["identity"], session)
    by_slug = {t["slug"]: t for t in tenants if not t.get("deleted_at")}
    deleted = {t["slug"] for t in tenants if t.get("deleted_at")}

    tenant_plan = {}
    for slug in sorted({t["tenant_slug"] for t in targets}):
        if slug in by_slug:
            t = by_slug[slug]
            tenant_plan[slug] = {"action": "exists", "id": t["id"],
                                 "display_name": t.get("display_name"),
                                 "allowed_environments": t.get("allowed_environments", [])}
        elif slug in deleted:
            raise Fail(f"tenant {slug} exists but is soft-deleted; restore or pick another name")
        else:
            near = [t["slug"] for t in tenants
                    if (t.get("display_name") or "").lower() == slug.lower()
                    or t["slug"].replace("-", "") == slug.replace("-", "")]
            tenant_plan[slug] = {"action": "create", "id": None, "spec": tenant_spec(m, slug),
                                 "similar_existing": near}

    rows = []
    errors = []
    for t in targets:
        tp = tenant_plan[t["tenant_slug"]]
        allowed = tp.get("allowed_environments") or tp.get("spec", {}).get("allowed_environments")
        if t["environment"] not in allowed:
            errors.append(f"{t['tenant_slug']} does not allow {t['environment']} "
                          f"(allowed: {', '.join(allowed)}) for {t['path']}")
            continue
        try:
            sources = resolver.expand_all(t["sources"])
            for s in sources.values():
                if not resolver.is_generated(s):
                    resolver.check(s)
        except Fail as e:
            errors.append(f"{t['path']} [{t['environment']}]: {e}")
            continue

        meta, current = (None, None)
        if tp["action"] == "exists":
            try:
                meta, current = read_current(run["secrets"], session, tp["id"], t["path"])
            except Fail as e:
                errors.append(str(e))
                continue
        keys = []
        for k, s in sorted(sources.items()):
            if current is None or k not in current:
                op = "add"
            elif resolver.is_generated(s):
                op = "keep"  # generate only fills missing keys; never rotates
            else:
                op = "unchanged" if current[k] == resolver.resolve(s) else "change"
            keys.append({"key": k, "op": op, "source": s.split(":", 1)[0]})
        untouched = sorted(set(current or {}) - set(sources))
        if meta is None:
            action = "create"
        elif any(k["op"] in ("add", "change") for k in keys):
            action = "update"
        else:
            action = "noop"
        rows.append({
            "tenant_slug": t["tenant_slug"], "path": t["path"],
            "environment": t["environment"], "tags": t["tags"],
            "action": action,
            "prior_version": int(meta["current_version"]) if meta else None,
            "keys": keys, "existing_keys_kept": untouched,
            "sources": sources,
        })
        del current

    if errors:
        raise Fail("planning found problems (nothing was changed):\n  - " + "\n  - ".join(errors))

    plan = {
        "run_id": a.run,
        "created_at": now(),
        "manifest_sha256": sha256_bytes(raw),
        "identity": run["identity"],
        "secrets": run["secrets"],
        "admin_auth": "root-token" if root_token_file() else "superuser-session",
        "tenants": tenant_plan,
        "secrets_plan": rows,
    }
    blob = json.dumps(plan, sort_keys=True, indent=2).encode()
    write_private(rd / "plan.json", blob)
    phash = sha256_bytes(blob)[:12]
    write_private(rd / "plan.sha256", phash)
    (rd / "approval.json").unlink(missing_ok=True)

    # Human-readable plan. Key names, paths, versions; never values.
    out = [f"# wslvault change plan  run={a.run}  plan-hash={phash}", "",
           f"Endpoint: {run['secrets']}", ""]
    out.append("## Tenants")
    for slug, tp in tenant_plan.items():
        if tp["action"] == "create":
            s = tp["spec"]
            out.append(f"- CREATE tenant `{slug}` kind={s['tenant_kind']} "
                       f"envs={','.join(s['allowed_environments'])} root_key_id={s['root_key_id']}"
                       f"  (via {plan['admin_auth']})")
            if tp["similar_existing"]:
                out.append(f"  ! similar existing tenants: {', '.join(tp['similar_existing'])} "
                           f"- confirm you do not mean one of these")
        else:
            out.append(f"- use existing tenant `{slug}` ({tp['display_name']}) id={tp['id']}")
    out += ["", "## Secrets", "",
            "| tenant | env | path | action | version | keys |",
            "|---|---|---|---|---|---|"]
    counts = {"create": 0, "update": 0, "noop": 0}
    for r in rows:
        counts[r["action"]] += 1
        ks = ", ".join(f"{k['key']}({k['op']})" for k in r["keys"])
        if r["existing_keys_kept"]:
            ks += f"; kept as-is: {', '.join(r['existing_keys_kept'])}"
        ver = "new" if r["prior_version"] is None else f"v{r['prior_version']}"
        out.append(f"| {r['tenant_slug']} | {r['environment']} | `{r['path']}` | "
                   f"{r['action'].upper()} | {ver} | {ks} |")
    out += ["", f"Totals: {counts['create']} create, {counts['update']} update, "
            f"{counts['noop']} unchanged, "
            f"{sum(1 for t in tenant_plan.values() if t['action'] == 'create')} new tenant(s).",
            "", "Values are never shown. Sources: generate = new random value (only for "
            "missing keys), file/dotenv/env = read locally at apply time.", "",
            f"To approve, the operator types exactly:  APPLY {a.run} {phash}"]
    text = "\n".join(out)
    write_private(rd / "plan.md", text)
    say(text)


def cmd_approve(a) -> None:
    rd = run_dir(a.run)
    if not (rd / "plan.json").exists():
        raise Fail("no plan yet; run plan first")
    phash = (rd / "plan.sha256").read_text().strip()
    if sha256_bytes((rd / "plan.json").read_bytes())[:12] != phash:
        raise Fail("plan.json was modified after it was produced; re-plan")
    expected = f"APPLY {a.run} {phash}"
    if a.phrase.strip() != expected:
        raise Fail(f"approval phrase does not match. The operator must type exactly: {expected}")
    write_private(rd / "approval.json", json.dumps({
        "phrase": expected, "plan_hash": phash, "approved_at": now(),
        "approved_by": os.environ.get("USER") or os.environ.get("USERNAME") or "unknown",
    }))
    say(f"APPROVED plan {phash}. Next: login --purpose apply with a NEW authenticator code.")


def cmd_apply(a) -> None:
    rd = run_dir(a.run)
    run = read_json(rd / "run.json")
    if not (rd / "approval.json").exists():
        raise Fail("plan not approved. Show the operator plan.md and record their approval phrase.")
    approval = read_json(rd / "approval.json")
    blob = (rd / "plan.json").read_bytes()
    if sha256_bytes(blob)[:12] != approval["plan_hash"]:
        raise Fail("the plan changed after approval; re-plan and re-approve")
    plan = json.loads(blob)
    if sha256_bytes((rd / "manifest.json").read_bytes()) != plan["manifest_sha256"]:
        raise Fail("the manifest changed after planning; re-plan")
    session = load_session(rd, "apply")
    if session["issued_at"] <= approval["approved_at"]:
        raise Fail("the apply session must be minted AFTER approval. Log in again for apply.")
    if any(e.get("op") == "apply_finished" for e in journal_read(rd)):
        raise Fail("this run was already applied. Start a new run for further changes.")

    resolver = Resolver(Path(run["manifest_dir"]))
    journal_append(rd, {"op": "apply_started", "plan_hash": approval["plan_hash"]})
    tenant_ids = {s: t["id"] for s, t in plan["tenants"].items()}
    done = 0
    try:
        for slug, tp in plan["tenants"].items():
            if tp["action"] != "create":
                continue
            st, body = http("POST", f"{plan['identity']}/v1/tenants",
                            admin_headers(session), tp["spec"])
            if st not in (200, 201) or not isinstance(body, dict) or "id" not in body:
                raise Fail(f"creating tenant {slug} failed (HTTP {st}): {err_text(body)}")
            tenant_ids[slug] = body["id"]
            journal_append(rd, {"op": "tenant_created", "slug": slug, "tenant_id": body["id"]})
            say(f"created tenant {slug} id={body['id']}")

        for r in plan["secrets_plan"]:
            if r["action"] == "noop":
                continue
            tid = tenant_ids[r["tenant_slug"]]
            meta, current = read_current(plan["secrets"], session, tid, r["path"])
            cur_ver = int(meta["current_version"]) if meta else None
            if cur_ver != r["prior_version"]:
                raise Fail(f"{r['path']} is at version {cur_ver}, plan expected "
                           f"{r['prior_version']}; someone changed it. Re-plan.")
            data = dict(current or {})
            for k in r["keys"]:
                if k["op"] in ("add", "change"):
                    data[k["key"]] = resolver.resolve(r["sources"][k["key"]])
            new_ver = write_secret(plan["secrets"], session, tid, r["path"], data,
                                   r["environment"], r["tags"], r["prior_version"])
            del data, current
            journal_append(rd, {"op": "secret_written", "tenant_slug": r["tenant_slug"],
                                "tenant_id": tid, "path": r["path"],
                                "prior_version": r["prior_version"], "new_version": new_ver})
            done += 1
            say(f"wrote {r['tenant_slug']}:{r['path']} [{r['environment']}] -> v{new_ver}")
    except Fail as e:
        journal_append(rd, {"op": "apply_failed", "error": str(e)[:300]})
        raise Fail(
            f"{e}\n\nAPPLY STOPPED after {done} secret write(s). Nothing further was changed.\n"
            f"Review with `status {a.run}`; undo with `rollback {a.run}` (needs a fresh MFA)."
        )
    journal_append(rd, {"op": "apply_finished", "writes": done})
    session_path(rd, "apply").unlink(missing_ok=True)
    say(f"APPLY COMPLETE: {done} secret write(s). Journal: {rd / 'journal.jsonl'}")


def cmd_status(a) -> None:
    rd = run_dir(a.run)
    say(f"run {a.run}  dir={rd}")
    for f in ("plan.md", "approval.json"):
        say(f"  {f}: {'yes' if (rd / f).exists() else 'no'}")
    for p in ("plan", "apply", "rollback"):
        sp = session_path(rd, p)
        if sp.exists():
            age = int(now() - read_json(sp)["issued_at"])
            say(f"  session {p}: {age}s old")
    for e in journal_read(rd):
        say("  " + json.dumps({k: v for k, v in e.items()}, sort_keys=True))


def cmd_rollback(a) -> None:
    rd = run_dir(a.run)
    expected = f"ROLLBACK {a.run}"
    if (a.phrase or "").strip() != expected:
        raise Fail(f"rollback needs the operator to type exactly: {expected}")
    session = load_session(rd, "rollback")
    run = read_json(rd / "run.json")
    entries = journal_read(rd)
    undone = {(e["tenant_id"], e["path"], e.get("new_version")) for e in entries
              if e.get("op") == "secret_rolled_back"}
    undone_t = {e["tenant_id"] for e in entries if e.get("op") == "tenant_rolled_back"}
    todo = [e for e in entries if e.get("op") in ("secret_written", "tenant_created")]
    if not todo:
        say("nothing to roll back: the journal has no applied changes")
        return
    journal_append(rd, {"op": "rollback_started", "destroy": bool(a.destroy)})
    problems = []
    for e in reversed(todo):
        if e["op"] == "secret_written":
            key = (e["tenant_id"], e["path"], e["new_version"])
            if key in undone:
                continue
            h = auth_headers(session, e["tenant_id"])
            st, meta = http("GET", f"{run['secrets']}/v1/secret/metadata/{q(e['path'])}", h)
            cur = int(meta["current_version"]) if st == 200 else None
            if cur != e["new_version"] and not a.force:
                problems.append(f"{e['path']}: now at v{cur}, not v{e['new_version']} written by "
                                f"this run; someone changed it since. Skipped (use --force).")
                continue
            if e["prior_version"] is None:
                # Created by this run: soft-delete (recoverable), optionally destroy.
                st, b = http("POST", f"{run['secrets']}/v1/secret/delete/{q(e['path'])}", h,
                             {"versions": [e["new_version"]]})
                ok = st in (200, 204)
                how = "soft-deleted"
                if ok and a.destroy:
                    st, b = http("POST", f"{run['secrets']}/v1/secret/destroy/{q(e['path'])}", h,
                                 {"versions": [e["new_version"]]})
                    ok, how = st in (200, 204), "destroyed"
            else:
                st, b = http("POST", f"{run['secrets']}/v1/secret/rollback/{q(e['path'])}", h,
                             {"target_version": e["prior_version"]})
                ok, how = st in (200, 201), f"rolled back to v{e['prior_version']} content"
                if not ok and st in (403, 404, 405):
                    # Rollback endpoint is power_admin only. Restore by re-writing
                    # the prior version's content, inside this process.
                    st2, prior = http("GET", f"{run['secrets']}/v1/secret/data/{q(e['path'])}"
                                      f"?version={e['prior_version']}", h)
                    if st2 == 200:
                        data = json.loads(base64.b64decode(prior["data"]))
                        meta_env = (meta or {}).get("environment")
                        write_secret(run["secrets"], session, e["tenant_id"], e["path"], data,
                                     meta_env, (meta or {}).get("tags", []), e["new_version"])
                        del data, prior
                        ok, how = True, f"restored v{e['prior_version']} content as a new version"
            if ok:
                journal_append(rd, {"op": "secret_rolled_back", "tenant_id": e["tenant_id"],
                                    "path": e["path"], "new_version": e["new_version"],
                                    "how": how})
                say(f"{e['tenant_slug']}:{e['path']} {how}")
            else:
                problems.append(f"{e['path']}: rollback failed (HTTP {st}): {err_text(b)}")
        else:
            if e["tenant_id"] in undone_t:
                continue
            if problems:
                problems.append(f"tenant {e['slug']}: NOT deleted because secret rollbacks failed")
                continue
            st, b = http("DELETE", f"{run['identity']}/v1/tenants/{e['tenant_id']}",
                         admin_headers(session))
            if st in (200, 204):
                journal_append(rd, {"op": "tenant_rolled_back", "tenant_id": e["tenant_id"],
                                    "slug": e["slug"]})
                say(f"tenant {e['slug']} soft-deleted")
            else:
                problems.append(f"tenant {e['slug']}: delete failed (HTTP {st}): {err_text(b)}")
    journal_append(rd, {"op": "rollback_finished", "problems": len(problems)})
    session_path(rd, "rollback").unlink(missing_ok=True)
    if problems:
        raise Fail("rollback finished with problems:\n  - " + "\n  - ".join(problems))
    say("ROLLBACK COMPLETE")


def cmd_logout(a) -> None:
    rd = run_dir(a.run)
    for p in ("plan", "apply", "rollback"):
        session_path(rd, p).unlink(missing_ok=True)
        (rd / f"challenge.{p}").unlink(missing_ok=True)
    say("local session tokens removed (server tokens expire on their own within the hour)")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="wsv.py", description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("preflight")
    p = sub.add_parser("init"); p.add_argument("--manifest", required=True)
    p = sub.add_parser("login"); p.add_argument("run")
    p.add_argument("--purpose", choices=["plan", "apply", "rollback"], required=True)
    p = sub.add_parser("mfa"); p.add_argument("run")
    p.add_argument("--purpose", choices=["plan", "apply", "rollback"], required=True)
    p.add_argument("--code", required=True)
    p = sub.add_parser("plan"); p.add_argument("run")
    p = sub.add_parser("approve"); p.add_argument("run"); p.add_argument("--phrase", required=True)
    p = sub.add_parser("apply"); p.add_argument("run")
    p = sub.add_parser("status"); p.add_argument("run")
    p = sub.add_parser("rollback"); p.add_argument("run")
    p.add_argument("--phrase", required=True)
    p.add_argument("--destroy", action="store_true",
                   help="irreversibly destroy versions created by this run (default: soft-delete)")
    p.add_argument("--force", action="store_true",
                   help="roll back even if a secret changed after this run wrote it")
    p = sub.add_parser("logout"); p.add_argument("run")
    a = ap.parse_args(argv)
    try:
        globals()[f"cmd_{a.cmd}"](a)
    except Fail as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
