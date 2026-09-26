# reverse_proxy

A reverse proxy as one command. A small TOML file maps names and paths to upstreams; Caddy underneath does
HTTPS (certificates from Let's Encrypt, obtained at start and renewed on their own; a local CA when there is no
public name), HTTP/2, WebSockets and streaming. Meant for a server with a public address and a domain that
reaches the upstreams over a private network such as Tailscale. No docker, no root except to install the service.

    git clone git@github.com:m-g-90/reverse_proxy.git && cd reverse_proxy
    python3 -m reverse_proxy setup                 # a short wizard writes proxy.toml (or copy proxy.example.toml)
    python3 -m reverse_proxy render proxy.toml     # show the generated Caddyfile
    python3 -m reverse_proxy run proxy.toml        # fetch Caddy (checksum verified), validate, run in the foreground
    sudo python3 -m reverse_proxy install proxy.toml   # a systemd service, started now and at boot

Python 3.11 or newer, nothing else to install. Everything lives under `~/.local/share/reverse_proxy`
(`--home`): the Caddy binary, the Caddyfile, and the certificates and ACME account in Caddy's state. The
repository holds no server names or addresses; `proxy.toml` is yours and git-ignored.

The config:

    [server]
    name = "example.org"             # the domain (or a public IP: Let's Encrypt issues six-day IP certificates)
    tls = "letsencrypt"              # letsencrypt (default) | internal (Caddy's local CA, no public name needed)
    email = "you@example.org"        # optional: the Let's Encrypt account address (expiry warnings, recovery)

    [routes]
    "example.org" = "http://100.64.0.10:8765"                # host -> upstream over the private network
    "code.example.org" = { to = "https://100.64.0.10:8443", insecure = true }   # a self-signed upstream
    "example.org/api/*" = "http://100.64.0.10:9000/v1/"      # a path under a host (prefix stripped), an upstream path prepended

Every route's host must be the server's name or a subdomain of it: those are the names a certificate can be
obtained for, and each gets its own. Ports 80 and 443 must be open to the internet for Let's Encrypt (HTTP-01).
A changed config takes effect with `systemctl restart reverse-proxy` (the service renders on every start).
Logs: `journalctl -u reverse-proxy -f`.
