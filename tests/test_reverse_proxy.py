"""The config, the generated Caddyfile, the command lines and the systemd unit."""

from pathlib import Path

import pytest

import reverse_proxy as rp


def write(tmp_path, text):
    p = tmp_path / "proxy.toml"
    p.write_text(text, encoding="utf-8")
    return p


GOOD = '''
[server]
name = "example.org"
email = "me@example.org"
tls = "letsencrypt"

[routes]
"example.org" = "http://100.64.0.10:30145/proxy/8765/"
"code.example.org" = { to = "https://100.64.0.10:8443", insecure = true }
"example.org/api/*" = "100.64.0.10:9000"
"example.org/api/v2/*" = "http://100.64.0.10:9002"
'''


def test_config_is_parsed_and_checked(tmp_path):
    c = rp.load(write(tmp_path, GOOD))
    assert c.name == "example.org" and c.public and len(c.routes) == 4
    root = next(r for r in c.routes if r.host == "example.org" and not r.path)
    assert (root.upstream, root.prefix, root.insecure) == ("http://100.64.0.10:30145", "/proxy/8765", False)
    code = next(r for r in c.routes if r.host == "code.example.org")
    assert (code.upstream, code.prefix, code.insecure) == ("https://100.64.0.10:8443", "", True)
    api = next(r for r in c.routes if r.path == "/api")
    assert api.upstream == "http://100.64.0.10:9000"  # scheme and port defaulted
    assert rp.load(write(tmp_path, '[server]\nname = "example.org"\n[routes]\n"example.org" = "http://x:1"\n')).public  # the default
    assert not rp.load(write(tmp_path, '[server]\nname = "example.org"\ntls = "internal"\n[routes]\n"example.org" = "http://x:1"\n')).public
    for text, why in (
        ('[routes]\n"a" = "http://x:1"\n', "name is required"),
        ('[server]\nname = "example.org"\n', "routes] is empty"),
        ('[server]\nname = "example.org"\nemail = "nope"\n[routes]\n"example.org" = "http://x:1"\n', "not an address"),
        ('[server]\nname = "example.org"\n[routes]\n"other.org" = "http://x:1"\n', "not 'example.org' or a subdomain"),
        ('[server]\nname = "example.org"\n[routes]\n"example.org/api" = "http://x:1"\n', "ends with '/\\*'"),
        ('[server]\nname = "example.org"\n[routes]\n"example.org" = "ftp://x:1"\n', "must be http"),
        ('[server]\nname = "example.org"\n[routes]\n"example.org" = { to = "http://x:1", foo = 1 }\n', "unknown keys"),
        ('[server]\nname = "example.org"\nport = 1\n[routes]\n"example.org" = "http://x:1"\n', "unknown keys"),
        ('[server]\nname = "example.org"\ntls = "acme"\n[routes]\n"example.org" = "http://x:1"\n', "tls must be"),
        ('[server]\nname = "example.org"\n[routes]\n"example.org" = "http://x:1"\n"EXAMPLE.ORG" = "http://y:1"\n', "given twice"),
    ):
        with pytest.raises(rp.ConfigError, match=why):
            rp.load(write(tmp_path, text))


def test_caddyfile_has_one_block_per_host_paths_first(tmp_path):
    text = rp.caddyfile(rp.load(write(tmp_path, GOOD)))
    assert text.startswith("# written by") and "{\n    email me@example.org\n}" in text and "local_certs" not in text
    blocks = text.split("\n\n")
    assert blocks[2].startswith("example.org {") and blocks[3].startswith("code.example.org {")  # the server's own name first
    main = blocks[2]
    assert main.index("handle_path /api/v2/*") < main.index("handle_path /api/*") < main.index("    handle {")  # longest prefix first
    assert "        rewrite * /proxy/8765{uri}\n        reverse_proxy http://100.64.0.10:30145 {" in main
    assert "header_up Host 100.64.0.10:30145" in main and "flush_interval -1" in main and "tls_insecure_skip_verify" not in main
    assert "tls_insecure_skip_verify" in blocks[3] and "reverse_proxy https://100.64.0.10:8443" in blocks[3]
    local = rp.caddyfile(rp.load(write(tmp_path, '[server]\nname = "example.org"\ntls = "internal"\n[routes]\n"example.org" = "http://x:1"\n')))
    assert "{\n    local_certs\n}" in local and "    tls internal\n" in local and "email" not in local
    anon = rp.caddyfile(rp.load(write(tmp_path, '[server]\nname = "example.org"\n[routes]\n"example.org" = "http://x:1"\n')))
    assert anon.split("\n\n")[1] == "{\n}" and "tls internal" not in anon  # Let's Encrypt without an account address


def test_render_run_and_unit(tmp_path):
    cf = rp.render(write(tmp_path, GOOD), tmp_path / "home")
    assert cf == tmp_path / "home" / "Caddyfile" and "example.org {" in cf.read_text(encoding="utf-8")
    argv = rp.run_argv(Path("/x/caddy"), cf)
    assert argv == ["/x/caddy", "run", "--config", str(cf), "--adapter", "caddyfile"] and rp.run_argv(Path("/x/caddy"), cf, validate=True)[1] == "validate"
    env = rp.caddy_env(tmp_path / "home")
    assert env["XDG_DATA_HOME"] == str(tmp_path / "home" / "data") and "PATH" in env
    u = rp.unit(tmp_path / "home", tmp_path / "proxy.toml", "ubuntu")
    assert "User=ubuntu" in u and "AmbientCapabilities=CAP_NET_BIND_SERVICE" in u and f"ExecStartPre={rp.sys.executable} -m reverse_proxy render" in u
    assert f"ExecStart={tmp_path / 'home' / 'caddy'} run --config {cf} --adapter caddyfile" in u


def test_release_asset_names():
    url, sums = rp._asset("2.11.4")
    assert url.endswith("/v2.11.4/caddy_2.11.4_linux_amd64.tar.gz") or url.endswith("/v2.11.4/caddy_2.11.4_linux_arm64.tar.gz")
    assert sums.endswith("/v2.11.4/caddy_2.11.4_checksums.txt")


def test_setup_wizard_writes_a_valid_config(tmp_path):
    answers = iter(["", "Example.ORG", "acme", "internal", "", "http://100.64.0.10:8765", "code.example.org", "https://100.64.0.10:8443", "y",
                    "other.org", "http://x:1", ""])
    said = []
    p = tmp_path / "proxy.toml"
    rp.setup(p, ask=lambda q: next(answers), say=said.append)
    c = rp.load(p)
    assert c.name == "example.org" and c.tls == "internal" and not c.public and c.email == ""
    assert [(r.host, r.upstream, r.insecure) for r in c.routes] == [("example.org", "http://100.64.0.10:8765", False),
                                                                     ("code.example.org", "https://100.64.0.10:8443", True)]
    assert any("not a host name" in m for m in said) and any("one of letsencrypt, internal" in m for m in said)
    assert any("not 'example.org' or a subdomain" in m for m in said) and p.read_text(encoding="utf-8").startswith("# written by")
    answers = iter(["n"])
    with pytest.raises(SystemExit, match="kept"):
        rp.setup(p, ask=lambda q: next(answers), say=said.append)
    answers = iter(["y", "example.org", "letsencrypt", "me@example.org", "", "http://100.64.0.10:8765", ""])
    rp.setup(p, ask=lambda q: next(answers), say=said.append)
    assert rp.load(p).email == "me@example.org" and rp.load(p).public
