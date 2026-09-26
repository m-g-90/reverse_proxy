"""A reverse proxy as one command: a small TOML file maps names and paths to upstreams, Caddy does the rest
(HTTPS from Let's Encrypt, obtained at start and renewed on its own, or a local CA without a public name;
HTTP/2, WebSockets and streaming out of the box). Decided 2026-09-26: it runs on a rented Ubuntu server with a
public address and the domain, and reaches the upstreams over Tailscale; no docker involved.

    python -m reverse_proxy setup                     # a short wizard: writes proxy.toml (nothing personal is in the repo)
    python -m reverse_proxy render proxy.toml         # write the Caddyfile and show it
    python -m reverse_proxy run proxy.toml            # fetch Caddy if missing, validate, run in the foreground
    python -m reverse_proxy install proxy.toml        # as root: a systemd service that runs it at boot
    python -m reverse_proxy caddy                     # fetch or update the Caddy binary

The config (`proxy.toml`, git-ignored: it names your server):

    [server]
    name = "example.org"             # the domain (or a public IP: Let's Encrypt issues six-day IP certificates)
    tls = "letsencrypt"              # letsencrypt (default) | internal (Caddy's local CA, no public name needed)
    email = "you@example.org"        # optional: the Let's Encrypt account address (expiry warnings, recovery)

    [routes]
    "example.org" = "http://100.64.0.10:8765"                # a host -> an upstream over the private network
    "code.example.org" = { to = "https://100.64.0.10:8443", insecure = true }   # an upstream with a self-signed certificate
    "example.org/api/*" = "http://100.64.0.10:9000/v1/"      # a path under a host (the prefix stripped), an upstream path prepended

Everything lives under one folder (`--home`, default `~/.local/share/reverse_proxy`): the Caddy binary (fetched
from the GitHub release with its checksum verified), the Caddyfile, and Caddy's own state with the certificates.
Ports 80 and 443 need the right to bind them: `install` grants it to the binary (`setcap`), or run as root."""

from __future__ import annotations

import hashlib
import io
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tomllib
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

CADDY_VERSION = "2.11.4"  # the release `caddy` fetches (2026-06-03); `caddy --version X` for another
HOME_DEFAULT = Path("~/.local/share/reverse_proxy").expanduser()
SERVICE = "reverse-proxy"


class ConfigError(ValueError):
    """The config file cannot be used; the message names the key and the problem."""


@dataclass(slots=True)
class Route:
    host: str
    path: str  # "" for the host itself, else a prefix like "/api" (the config's "/api/*")
    upstream: str  # scheme://host:port
    prefix: str = ""  # a path on the upstream, prepended to every request ("/proxy/8765")
    insecure: bool = False  # the upstream's certificate is not verified (self-signed)


TLS = ("letsencrypt", "internal")


@dataclass(slots=True)
class Config:
    name: str
    tls: str = "letsencrypt"
    email: str = ""
    routes: list[Route] = field(default_factory=list)

    @property
    def public(self) -> bool:
        """Public certificates from Let's Encrypt, else Caddy's local CA."""
        return self.tls == "letsencrypt"


_HOST = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$|^\d{1,3}(?:\.\d{1,3}){3}$")


def parse_route(key: str, value: Any) -> Route:
    """`"host"` or `"host/prefix/*"` -> an upstream: a URL string, or a table `{to = ..., insecure = ...}`."""
    if isinstance(value, dict):
        to = value.get("to")
        insecure = bool(value.get("insecure", False))
        extra = set(value) - {"to", "insecure"}
        if extra:
            raise ConfigError(f"route {key!r}: unknown keys {sorted(extra)}")
    else:
        to, insecure = value, False
    if not isinstance(to, str) or not to:
        raise ConfigError(f"route {key!r}: the upstream must be a URL string (or a table with `to`)")
    host, _, path = key.strip().lower().partition("/")
    if not _HOST.match(host):
        raise ConfigError(f"route {key!r}: {host!r} is not a host name or IPv4 address")
    if path:
        if not path.endswith("/*"):
            raise ConfigError(f"route {key!r}: a path route ends with '/*' (it is a prefix), e.g. \"{host}/{path.rstrip('/')}/*\"")
        path = "/" + path[:-2].strip("/")
        if path == "/":
            raise ConfigError(f"route {key!r}: use \"{host}\" for the root")
    url = urlsplit(to if "://" in to else "http://" + to)
    if url.scheme not in ("http", "https") or not url.hostname:
        raise ConfigError(f"route {key!r}: the upstream {to!r} must be http(s)://host[:port][/path]")
    port = url.port or (443 if url.scheme == "https" else 80)
    upstream = f"{url.scheme}://{url.hostname}:{port}"
    prefix = url.path.rstrip("/")
    return Route(host, path, upstream, prefix, insecure)


def load(path: str | Path) -> Config:
    """Read and check the config file."""
    with open(path, "rb") as f:
        data = tomllib.load(f)
    server = data.get("server") or {}
    name = str(server.get("name") or "").strip().lower()
    if not name:
        raise ConfigError("[server] name is required: the domain (or public IP) this server answers for")
    if not _HOST.match(name):
        raise ConfigError(f"[server] name {name!r} is not a host name or IPv4 address")
    email = str(server.get("email") or "").strip()
    if email and "@" not in email:
        raise ConfigError(f"[server] email {email!r} is not an address")
    tls = str(server.get("tls") or "letsencrypt").strip().lower()
    if tls not in TLS:
        raise ConfigError(f"[server] tls must be one of {', '.join(TLS)}, not {tls!r}")
    extra = set(server) - {"name", "email", "tls"}
    if extra:
        raise ConfigError(f"[server]: unknown keys {sorted(extra)}")
    routes_in = data.get("routes") or {}
    if not routes_in:
        raise ConfigError("[routes] is empty: at least one \"host\" = \"upstream\" line is needed")
    routes = [parse_route(k, v) for k, v in routes_in.items()]
    seen: set[tuple[str, str]] = set()
    for r in routes:
        if (r.host, r.path) in seen:
            raise ConfigError(f"route {r.host}{r.path or ''} is given twice")
        seen.add((r.host, r.path))
    for r in routes:
        if r.host != name and not r.host.endswith("." + name):
            raise ConfigError(f"route {r.host!r} is not {name!r} or a subdomain of it; a certificate cannot be obtained for it")
    return Config(name, tls, email, routes)


# --- the Caddyfile ------------------------------------------------------------------------------------------

def caddyfile(c: Config) -> str:
    """One site block per host; path routes first (longest prefix first), the host's own route last."""
    out = ["# written by `python -m reverse_proxy render`; change the config and render again, not this file"]
    if c.public:
        out.append("{\n" + f"    email {c.email}\n" + "}" if c.email else "{\n}")
    else:
        out.append("{\n    local_certs\n}")
    hosts: dict[str, list[Route]] = {}
    for r in c.routes:
        hosts.setdefault(r.host, []).append(r)
    for host in sorted(hosts, key=lambda h: (h != c.name, h)):
        block = [f"{host} {{"]
        if not c.public:
            block.append("    tls internal")
        block.append("    encode zstd gzip")
        for r in sorted(hosts[host], key=lambda r: (-len(r.path), r.path)):
            block.append(_handle(r))
        block.append("}")
        out.append("\n".join(block))
    return "\n\n".join(out) + "\n"


def _handle(r: Route) -> str:
    url = urlsplit(r.upstream)
    proxy = [f"        reverse_proxy {r.upstream} {{"]
    proxy.append(f"            header_up Host {url.hostname}:{url.port}")
    proxy.append("            flush_interval -1")  # streams (server-sent events) are not buffered
    if url.scheme == "https" and r.insecure:
        proxy.append("            transport http {\n                tls_insecure_skip_verify\n            }")
    proxy.append("        }")
    lines = []
    if r.path:
        lines.append(f"    handle_path {r.path}/* {{")
    else:
        lines.append("    handle {")
    if r.prefix:
        lines.append(f"        rewrite * {r.prefix}{{uri}}")
    lines += proxy
    lines.append("    }")
    return "\n".join(lines)


# --- the Caddy binary ----------------------------------------------------------------------------------------

def _asset(version: str) -> tuple[str, str]:
    machine = platform.machine().lower()
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(machine)
    if platform.system() != "Linux" or arch is None:
        raise SystemExit(f"reverse_proxy: no Caddy download for {platform.system()} {machine}; put a `caddy` binary in the home folder")
    base = f"https://github.com/caddyserver/caddy/releases/download/v{version}"
    return f"{base}/caddy_{version}_linux_{arch}.tar.gz", f"{base}/caddy_{version}_checksums.txt"


def fetch_caddy(home: Path = HOME_DEFAULT, version: str = CADDY_VERSION, force: bool = False) -> Path:
    """The Caddy binary at `<home>/caddy`, downloaded from the GitHub release and verified against the release's
    checksum file; kept when it is already that version."""
    home.mkdir(parents=True, exist_ok=True)
    binary, stamp = home / "caddy", home / "caddy.version"
    if binary.exists() and stamp.exists() and stamp.read_text().strip() == version and not force:
        return binary
    url, sums_url = _asset(version)
    name = url.rsplit("/", 1)[1]
    with urllib.request.urlopen(sums_url, timeout=60) as r:
        sums = r.read().decode("utf-8")
    expected = next((line.split()[0] for line in sums.splitlines() if line.strip().endswith(name)), None)
    if expected is None:
        raise SystemExit(f"reverse_proxy: {name} is not in the release's checksum file")
    with urllib.request.urlopen(url, timeout=600) as r:
        data = r.read()
    got = (hashlib.sha512 if len(expected) == 128 else hashlib.sha256)(data).hexdigest()  # the release file lists sha512 digests
    if got != expected:
        raise SystemExit(f"reverse_proxy: checksum mismatch for {name}: {got} != {expected}")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        member = tar.getmember("caddy")
        with tar.extractfile(member) as f:  # type: ignore[union-attr]
            tmp = home / "caddy.new"
            tmp.write_bytes(f.read())
    os.chmod(tmp, 0o755)
    tmp.replace(binary)
    stamp.write_text(version + "\n")
    return binary


def caddy_env(home: Path) -> dict[str, str]:
    """Caddy keeps its state (certificates, ACME account) under XDG paths: all of it inside the home folder."""
    env = dict(os.environ)
    env["XDG_DATA_HOME"] = str(home / "data")
    env["XDG_CONFIG_HOME"] = str(home / "config")
    return env


def render(config: str | Path, home: Path = HOME_DEFAULT) -> Path:
    """Write `<home>/Caddyfile` from the config file; returns its path."""
    c = load(config)
    home.mkdir(parents=True, exist_ok=True)
    out = home / "Caddyfile"
    out.write_text(caddyfile(c), encoding="utf-8")
    return out


def run_argv(binary: Path, caddyfile_path: Path, validate: bool = False) -> list[str]:
    cmd = "validate" if validate else "run"
    return [str(binary), cmd, "--config", str(caddyfile_path), "--adapter", "caddyfile"]


def unit(home: Path, config: Path, user: str) -> str:
    """A systemd unit that renders on every start (so a changed config takes effect on restart) and runs Caddy."""
    python = sys.executable
    return f"""[Unit]
Description=reverse proxy (Caddy) for {config}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User={user}
Environment=XDG_DATA_HOME={home / 'data'}
Environment=XDG_CONFIG_HOME={home / 'config'}
ExecStartPre={python} -m reverse_proxy render {config} --home {home}
ExecStart={home / 'caddy'} run --config {home / 'Caddyfile'} --adapter caddyfile
ExecReload={home / 'caddy'} reload --config {home / 'Caddyfile'} --adapter caddyfile
Restart=on-failure
RestartSec=5
AmbientCapabilities=CAP_NET_BIND_SERVICE
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
"""


def toml_text(name: str, tls: str, email: str, routes: dict[str, Any]) -> str:
    """The config file for the given answers."""
    lines = ["# written by `python -m reverse_proxy setup`; edit freely, then `python -m reverse_proxy run proxy.toml`",
             "[server]", f'name = "{name}"', f'tls = "{tls}"', f'email = "{email}"', "", "[routes]"]
    for key, value in routes.items():
        if isinstance(value, dict):
            lines.append(f'"{key}" = {{ to = "{value["to"]}", insecure = {"true" if value.get("insecure") else "false"} }}')
        else:
            lines.append(f'"{key}" = "{value}"')
    return "\n".join(lines) + "\n"


def setup(path: Path, ask=input, say=print) -> Path:
    """The wizard: the server's name, the certificate source, the account address, then routes until an empty
    host; every answer is checked the way `load` checks the file; writes `path` (asks before replacing one)."""
    say("reverse_proxy setup: a few questions, then proxy.toml is written. Nothing here is stored anywhere else.")
    if path.exists() and ask(f"{path} exists; replace it? [y/N] ").strip().lower() not in ("y", "yes"):
        raise SystemExit("kept the existing file")
    while True:
        name = ask("The domain this server answers for (DNS points at this machine), or its public IP: ").strip().lower()
        if _HOST.match(name):
            break
        say("  that is not a host name or IPv4 address")
    say("Certificates: 'letsencrypt' needs ports 80 and 443 reachable from the internet and gives browsers a trusted")
    say("certificate; 'internal' uses Caddy's own local CA (a warning in the browser once, no public port needed).")
    while True:
        tls = (ask("Certificate source [letsencrypt]: ").strip().lower() or "letsencrypt")
        if tls in TLS:
            break
        say(f"  one of {', '.join(TLS)}")
    email = ""
    if tls == "letsencrypt":
        say("Let's Encrypt keeps an account for this server; an address on it gets expiry warnings and can recover")
        say("the account. It is optional and never published.")
        while True:
            email = ask("Account address (empty for none): ").strip()
            if not email or "@" in email:
                break
            say("  that is not an address")
    routes: dict[str, Any] = {}
    say(f"Routes: a host ({name} or a subdomain of it, optionally with /prefix/*) and where it goes,")
    say("e.g. http://100.64.0.10:8765 over the private network. An empty host ends the list.")
    while True:
        default = "" if routes else name
        host = ask(f"Host to serve [{default or 'done'}]: ").strip().lower() or default
        if not host:
            if routes:
                break
            say("  at least one route is needed")
            continue
        to = ask(f"Upstream for {host} (URL, e.g. http://100.64.0.10:8765): ").strip()
        insecure = False
        if to.lower().startswith("https://"):
            insecure = ask("Does the upstream use a self-signed certificate? [y/N] ").strip().lower() in ("y", "yes")
        try:
            r = parse_route(host, {"to": to, "insecure": insecure} if insecure else to)
            if r.host != name and not r.host.endswith("." + name):
                raise ConfigError(f"{r.host!r} is not {name!r} or a subdomain of it")
        except ConfigError as e:
            say(f"  {e}")
            continue
        routes[host] = {"to": to, "insecure": True} if insecure else to
    path.write_text(toml_text(name, tls, email, routes), encoding="utf-8")
    load(path)  # the file must pass the same checks
    say(f"wrote {path}\nnext: python -m reverse_proxy run {path}   (or: sudo python -m reverse_proxy install {path})")
    return path


def main(argv: list[str] | None = None) -> None:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("command", choices=("setup", "render", "run", "install", "caddy"))
    ap.add_argument("config", nargs="?", help="the TOML config (render, run, install; setup writes it, default proxy.toml)")
    ap.add_argument("--home", default=str(HOME_DEFAULT), help="the folder for the binary, the Caddyfile and the state (default: %(default)s)")
    ap.add_argument("--version", default=CADDY_VERSION, help="the Caddy release to fetch (default: %(default)s)")
    ap.add_argument("--user", default=None, help="install: the user the service runs as (default: the current one)")
    a = ap.parse_args(argv)
    home = Path(a.home).expanduser()
    try:
        if a.command == "caddy":
            print(fetch_caddy(home, a.version, force=True))
            return
        if a.command == "setup":
            if not sys.stdin.isatty():
                raise SystemExit("reverse_proxy setup: needs a terminal to ask on; write proxy.toml by hand instead (see proxy.example.toml)")
            setup(Path(a.config or "proxy.toml"))
            return
        if not a.config:
            raise SystemExit(f"reverse_proxy {a.command}: the config file is needed")
        config = Path(a.config).resolve()
        cf = render(config, home)
        if a.command == "render":
            print(cf.read_text(encoding="utf-8"))
            return
        binary = fetch_caddy(home, a.version)
        check = subprocess.run(run_argv(binary, cf, validate=True), env=caddy_env(home), capture_output=True, text=True)
        if check.returncode != 0:
            raise SystemExit(f"reverse_proxy: Caddy refuses the generated Caddyfile:\n{check.stderr.strip()}")
        if a.command == "install":
            user = a.user or os.environ.get("SUDO_USER") or os.environ.get("USER") or "root"
            if os.geteuid() != 0:
                raise SystemExit("reverse_proxy install: run as root (sudo): it writes the systemd unit and grants port 80/443")
            if shutil.which("setcap"):
                subprocess.run(["setcap", "cap_net_bind_service=+ep", str(binary)], check=False)
            unit_path = Path(f"/etc/systemd/system/{SERVICE}.service")
            unit_path.write_text(unit(home, config, user), encoding="utf-8")
            subprocess.run(["systemctl", "daemon-reload"], check=True)
            subprocess.run(["systemctl", "enable", "--now", SERVICE], check=True)
            print(f"installed and started {SERVICE} ({unit_path}); logs: journalctl -u {SERVICE} -f")
            return
        print(f"reverse_proxy: running Caddy {a.version} with {cf} (ctrl-c stops it)", file=sys.stderr)
        os.execve(str(binary), run_argv(binary, cf), caddy_env(home))
    except ConfigError as e:
        raise SystemExit(f"reverse_proxy: {e}")
    except urllib.error.URLError as e:  # type: ignore[attr-defined]
        raise SystemExit(f"reverse_proxy: download failed: {e}")
