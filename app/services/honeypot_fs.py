"""Deceptive virtual filesystem for the interactive SSH honeypot.

Builds a plausible Ubuntu 22.04 web-server tree. Dynamic files (logs, decoy
credentials) are generated per-session: attacker-controlled fields such as
their source IP show up inside ``/var/log/auth.log`` and every embedded
secret carries a per-session watermark so captured credentials can be
traced back to the exact session when they are reused anywhere else.

A fresh tree is built for every connection, so writes (mkdir/touch/rm/echo>)
stay session-scoped and never leak between attackers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import SimpleNamespace

FAKE_OS_RELEASE = """PRETTY_NAME="Ubuntu 22.04.4 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.4 LTS (Jammy Jellyfish)"
VERSION_CODENAME=jammy
ID=ubuntu
ID_LIKE=debian
"""

FAKE_ISSUE = "Ubuntu 22.04.4 LTS \\n \\l\n"


@dataclass
class FsNode:
    kind: str  # "dir" | "file"
    mode: str = "0644"
    owner: str = "root"
    group: str = "root"
    content: object = ""  # str | bytes | callable(ctx) -> str
    children: dict = field(default_factory=dict)

    def text(self, ctx) -> str:
        if callable(self.content):
            return str(self.content(ctx))
        if isinstance(self.content, bytes):
            return self.content.decode("utf-8", errors="replace")
        return str(self.content)

    def current_size(self, ctx) -> int:
        if self.kind == "dir":
            return 4096
        return len(self.text(ctx).encode("utf-8"))


def _dir(mode: str = "0755", owner: str = "root", children: dict | None = None) -> FsNode:
    return FsNode(kind="dir", mode=mode, owner=owner, group=owner, children=dict(children or {}))


def _file(content="", mode: str = "0644", owner: str = "root", group: str = "") -> FsNode:
    return FsNode(kind="file", mode=mode, owner=owner, group=group or owner, content=content)


def build_context(session_id: str, source_ip: str, username: str = "root") -> SimpleNamespace:
    """Per-session generation context handed to dynamic file callables."""
    return SimpleNamespace(
        session_id=session_id,
        source_ip=source_ip,
        username=username,
        watermark=session_id.replace("-", "")[-8:] or "deadbeef",
        now=datetime.now(timezone.utc),
        hostname=None,  # filled by the shell session
    )


def decoy_password(ctx) -> str:
    """Watermarked decoy credential — grep events for this string to trace
    credential reuse back to the exact honeypot session."""
    return f"Bk2026!{ctx.watermark}"


# ---------------------------------------------------------------------------
# Content builders
# ---------------------------------------------------------------------------


def _etc_passwd(ctx=None) -> str:
    return (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
        "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        "backup:x:34:34:backup:/var/backups:/usr/sbin/nologin\n"
        "deploy:x:1000:1000:Deploy User:/home/deploy:/bin/bash\n"
        "svc_backup:x:1001:1001::/var/backups:/bin/bash\n"
    )


def _etc_shadow(ctx) -> str:
    # $6$ hashes are plausible-looking SHA512 strings (not real passwords).
    return (
        "root:$6$rounds=4096$K7xJ2vN9q$H4Yq8pWm2RtZ5nL3bC6dV8sX1wQ0eA9uJ7hG4kM2nP6rT3yU5iO1aS8dF0gH2jK4lM6nP8rT0vX2zB4:19800:0:99999:7:::\n"
        "deploy:$6$rounds=4096$m2Qw9zR4t$Y8uI3oP6aS9dF1gH4jK7lM0nQ3rT6vX9zC2bE5hK8mP1sV4xZ7aN0qD3gJ6lW9oS2uY5:19800:0:99999:7:::\n"
        "svc_backup:$6$rounds=4096$p5Ta0sW7u$D2gJ5lM8oQ1tV4xZ7aN0qC3fI6kN9pS2vY5bE8hK1mP4sW7xZ0aD3gJ6lO9rU2vX5:19800:0:99999:7:::\n"
    )


def _crontab(ctx) -> str:
    return (
        "# /etc/crontab: system-wide crontab\n"
        "SHELL=/bin/sh\n"
        "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n"
        "17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly\n"
        "25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )\n"
        "47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )\n"
        "*/5 *   * * *   root    /opt/app/scripts/healthcheck.sh >> /var/log/app-health.log 2>&1\n"
        "0 2     * * *   root    /root/backup/run_backup.sh >> /var/log/backup.log 2>&1\n"
    )


def _auth_log(ctx) -> str:
    now = ctx.now
    stamp = now.strftime("%b %d %H:%M:%S")
    host = ctx.hostname or "web-prod-01"
    return (
        f"{stamp} {host} sshd[1201]: Server listening on 0.0.0.0 port 22.\n"
        f"{stamp} {host} systemd[1]: Started Daily apt download activities.\n"
        f"{stamp} {host} sshd[21457]: Accepted password for {ctx.username} from {ctx.source_ip} port 51234 ssh2\n"
        f"{stamp} {host} sshd[21457]: pam_unix(sshd:session): session opened for user {ctx.username}(uid=0) by (uid=0)\n"
        f"{stamp} {host} CRON[21400]: (root) CMD (/opt/app/scripts/healthcheck.sh >> /var/log/app-health.log 2>&1)\n"
    )


def _bash_history(ctx) -> str:
    return (
        "cd /opt/app\n"
        "docker compose ps\n"
        "tail -f /var/log/nginx/access.log\n"
        "./scripts/deploy.sh production\n"
        "mysql -u app -p appdb < migrations/014_add_index.sql\n"
        "crontab -e\n"
        "htop\n"
        "exit\n"
    )


def _db_credentials(ctx) -> str:
    return (
        "# production database credentials (rotate quarterly)\n"
        "# updated 2026-07-14 by deploy\n"
        "[primary]\nhost=db-primary.internal\nport=5432\ndbname=appdb\n"
        f"user=svc_backup\npassword={decoy_password(ctx)}\n"
        "\n[replica]\nhost=db-replica.internal\nport=5432\ndbname=appdb\n"
        f"user=svc_backup\npassword={decoy_password(ctx)}\n"
    )


def _app_env(ctx) -> str:
    return (
        "APP_ENV=production\n"
        "APP_KEY=base64:x9Tg2Wq8nP1sV4xZ7aN0qC3fI6kN9pS2vY5bE8hK1mP=\n"
        "DB_HOST=db-primary.internal\n"
        "DB_PORT=5432\n"
        "DB_DATABASE=appdb\n"
        f"DB_USERNAME=svc_backup\nDB_PASSWORD={decoy_password(ctx)}\n"
        "REDIS_URL=redis://cache-primary.internal:6379/0\n"
        "MAIL_HOST=smtp.internal\n"
        "S3_BACKUP_BUCKET=prod-app-backups\n"
        f"DEPLOY_WATERMARK={ctx.watermark}\n"
    )


def _nginx_conf(ctx) -> str:
    return (
        "user www-data;\n"
        "worker_processes auto;\n"
        "pid /run/nginx.pid;\n"
        "events { worker_connections 1024; }\n"
        "http {\n"
        "    sendfile on;\n"
        "    tcp_nopush on;\n"
        "    keepalive_timeout 65;\n"
        "    include /etc/nginx/mime.types;\n"
        "    default_type application/octet-stream;\n"
        "    access_log /var/log/nginx/access.log;\n"
        "    server {\n"
        "        listen 80 default_server;\n"
        "        root /var/www/html;\n"
        "        location / { try_files $uri $uri/ =404; }\n"
        "    }\n"
        "}\n"
    )


def _sshd_config(ctx) -> str:
    return (
        "Port 22\n"
        "PermitRootLogin yes\n"
        "PasswordAuthentication yes\n"
        "PubkeyAuthentication yes\n"
        "X11Forwarding no\n"
        "MaxAuthTries 6\n"
        "Subsystem sftp /usr/lib/openssh/sftp-server\n"
    )


def _fake_private_key(ctx) -> str:
    # Looks like an OpenSSH ED25519 private key; carries the session
    # watermark in a trailing comment so exfiltration is traceable.
    return (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
        "QyNTUxOQAAACB0ZXN0LW9ubHktaG9uZXlwb3Qtc3R1Yi1ub3QtYS1yZWFsLWtleQ\n"
        f"-----END OPENSSH PRIVATE KEY----- honeypot-watermark:{ctx.watermark}\n"
    )


def _proc_cpuinfo(ctx=None) -> str:
    lines = []
    for i in range(4):
        lines.append(f"processor\t: {i}")
        lines.append("vendor_id\t: GenuineIntel")
        lines.append("model name\t: Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz")
        lines.append("cache size\t: 36608 KB")
        lines.append("")
    return "\n".join(lines)


def _access_log(ctx) -> str:
    now = ctx.now
    stamp = now.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return (
        f'10.0.1.23 - - [{stamp}] "GET / HTTP/1.1" 200 6120 "-" "Mozilla/5.0"\n'
        f'10.0.1.23 - - [{stamp}] "GET /assets/app.js HTTP/1.1" 200 142301 "-" "Mozilla/5.0"\n'
        f'52.14.98.201 - - [{stamp}] "GET /wp-login.php HTTP/1.1" 404 153 "-" "python-requests/2.31.0"\n'
    )


# ---------------------------------------------------------------------------
# Tree
# ---------------------------------------------------------------------------


def build_default_fs(ctx=None) -> FsNode:
    """Build a fresh per-session filesystem tree."""
    if ctx is None:
        ctx = build_context("session-unknown", "unknown")

    etc = _dir(children={
        "hostname": _file("web-prod-01\n"),
        "hosts": _file(
            "127.0.0.1 localhost\n"
            "10.0.7.10 web-prod-01\n"
            "10.0.7.11 db-primary.internal\n"
            "10.0.7.12 intranet.corp.local wiki.corp.local\n"
            "10.0.7.13 git.corp.local\n"
            "10.0.7.20 backup.internal\n"
        ),
        "os-release": _file(FAKE_OS_RELEASE),
        "issue": _file(FAKE_ISSUE),
        "passwd": _file(_etc_passwd),
        "shadow": _file(_etc_shadow, mode="0640", group="shadow"),
        "crontab": _file(_crontab),
        "resolv.conf": _file("nameserver 10.0.0.2\nnameserver 10.0.0.3\n"),
        "ssh": _dir(children={"sshd_config": _file(_sshd_config, mode="0600")}),
        "nginx": _dir(children={
            "nginx.conf": _file(_nginx_conf),
            "sites-enabled": _dir(children={
                "default": _file("server { listen 80; root /var/www/html; }\n"),
            }),
        }),
    })

    home = _dir(children={
        "deploy": _dir(owner="deploy", children={
            ".bashrc": _file("# deploy bashrc\nexport PS1='\\u@\\h:\\w\\$ '\n", owner="deploy"),
            "notes.md": _file("# Handover notes\n- prod deploy key lives in /root/backup\n", owner="deploy"),
            ".ssh": _dir(mode="0700", owner="deploy", children={
                "authorized_keys": _file(
                    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyHashForDeployUser deploy@bastion\n",
                    mode="0600", owner="deploy",
                ),
            }),
        }),
    })

    opt = _dir(children={
        "app": _dir(owner="deploy", children={
            ".env": _file(_app_env, mode="0600", owner="deploy"),
            "docker-compose.yml": _file(
                "services:\n  app:\n    image: registry.internal/app:2.4.1\n    ports: ['8000:8000']\n"
            ),
            "scripts": _dir(children={
                "healthcheck.sh": _file("#!/bin/bash\ncurl -fsS http://127.0.0.1:8000/healthz\n", mode="0755"),
                "deploy.sh": _file("#!/bin/bash\nset -e\ndocker compose pull && docker compose up -d\n", mode="0755"),
            }),
        }),
    })

    proc = _dir(children={
        "cpuinfo": _file(_proc_cpuinfo),
        "meminfo": _file(
            "MemTotal:       16384000 kB\nMemFree:         4200000 kB\nMemAvailable:     9800000 kB\n"
        ),
        "uptime": _file("86400.25 320100.10\n"),
    })

    root = _dir(mode="0700", children={
        ".bash_history": _file(_bash_history, mode="0600"),
        ".ssh": _dir(mode="0700", children={
            "authorized_keys": _file(
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyHashForRootUser ops@bastion\n",
                mode="0600",
            ),
            "id_ed25519": _file(_fake_private_key, mode="0600"),
        }),
        "backup": _dir(mode="0700", children={
            "db_credentials.ini": _file(_db_credentials, mode="0600"),
            "run_backup.sh": _file(
                "#!/bin/bash\npg_dump -h db-primary.internal -U svc_backup appdb | gzip > /var/backups/appdb-$(date +%F).sql.gz\n",
                mode="0700",
            ),
        }),
    })

    var = _dir(children={
        "log": _dir(children={
            "auth.log": _file(_auth_log),
            "syslog": _file(_auth_log),
            "nginx": _dir(children={
                "access.log": _file(_access_log),
                "error.log": _file("2026/08/30 03:12:41 [warn] 812#812: *44 upstream server temporarily disabled\n"),
            }),
        }),
        "backups": _dir(children={
            "appdb-2026-08-29.sql.gz": _file(b"\x1f\x8b\x08\x00FAKE-GZIP-PAYLOAD\x00", mode="0600"),
        }),
        "www": _dir(children={
            "html": _dir(children={
                "index.html": _file(
                    "<!doctype html><html><head><title>Corporate Portal</title></head>"
                    "<body><h1>Corporate Portal</h1></body></html>\n"
                ),
            }),
        }),
    })

    return _dir(children={
        "bin": _dir(),
        "boot": _dir(),
        "dev": _dir(),
        "etc": etc,
        "home": home,
        "opt": opt,
        "proc": proc,
        "root": root,
        "srv": _dir(),
        "tmp": _dir(mode="1777"),
        "usr": _dir(),
        "var": var,
    })


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------


def normalize_path(cwd: str, path: str, home: str = "/root") -> str:
    """Resolve *path* against *cwd* the way a shell would (no symlinks)."""
    if not path or path == ".":
        path = cwd
    path = path.replace("~", home)
    if not path.startswith("/"):
        path = f"{cwd.rstrip('/')}/{path}"
    parts: list[str] = []
    for segment in path.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if parts:
                parts.pop()
            continue
        parts.append(segment)
    return "/" + "/".join(parts) if parts else "/"


def resolve_node(root: FsNode, cwd: str, path: str, home: str = "/root") -> FsNode | None:
    absolute = normalize_path(cwd, path, home)
    if absolute == "/":
        return root
    current = root
    for segment in absolute.strip("/").split("/"):
        if current.kind != "dir":
            return None
        child = current.children.get(segment)
        if child is None:
            return None
        current = child
    return current


def parent_path(path: str) -> str:
    if path == "/":
        return "/"
    return path.rsplit("/", 1)[0] or "/"


def base_name(path: str) -> str:
    return path.rstrip("/").rsplit("/", 1)[-1]
