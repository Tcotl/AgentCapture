"""Fake bash engine for the interactive SSH honeypot.

Implements the command surface a human operator (red teamer) expects on an
Ubuntu web server: navigation, file inspection, process/network introspection,
and enough extras (wget/curl, grep, find, crontab) to keep a live session
going. Every result is generated from the per-session deceptive filesystem —
nothing here touches the real machine.

The engine is socket-free and fully deterministic per (fs, input), which
makes it unit-testable without paramiko or network.
"""

from __future__ import annotations

import re
import shlex
from datetime import timezone

from app.core.config import get_settings
from app.services import honeypot_fs
from app.services.honeypot_fs import FsNode, build_context, build_default_fs, decoy_password

# Cap per-command output so `cat` of a huge generated blob can't blow up the
# transcript or the channel.
MAX_OUTPUT_CHARS = 24000
MAX_HISTORY = 500

_PS_OUTPUT = (
    "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
    "root           1  0.0  0.2 167504 11520 ?        Ss   03:01   0:02 /sbin/init splash\n"
    "root         412  0.0  0.1 154190  9216 ?        Ss   03:01   0:00 /usr/sbin/sshd -D\n"
    "root         470  0.0  0.3 311210 26104 ?        Ssl  03:02   0:01 /usr/bin/python3 /opt/app/venv/bin/gunicorn app:app -b 0.0.0.0:8000 -w 4\n"
    "www-data     611  0.1  0.6 412020 40120 ?        S    03:02   0:04 gunicorn: worker [app:app]\n"
    "www-data     612  0.1  0.6 412020 40120 ?        S    03:02   0:04 gunicorn: worker [app:app]\n"
    "root         815  0.0  0.0   2712   960 ?        Ss   03:02   0:00 nginx: master process /usr/sbin/nginx\n"
    "www-data     816  0.0  0.1  32110  8120 ?        S    03:02   0:00 nginx: worker process\n"
    "postgres     940  0.0  0.4 211900 36400 ?        S    03:03   0:00 postgres: checkwriter \n"
)

_NETSTAT_OUTPUT = (
    "Active Internet connections (only servers)\n"
    "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\n"
    "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      412/sshd\n"
    "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      815/nginx\n"
    "tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      815/nginx\n"
    "tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      470/gunicorn\n"
    "tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN      940/postgres\n"
)

_IFCONFIG_OUTPUT = (
    "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 9001\n"
    "        inet 10.0.7.10  netmask 255.255.255.0  broadcast 10.0.7.255\n"
    "        ether 06:1f:3a:92:7b:c4  txqueuelen 1000  (Ethernet)\n"
    "        RX packets 1843011  bytes 2201904211 (2.2 GB)\n"
    "        TX packets 1421103  bytes 310425117 (310.4 MB)\n\n"
    "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
    "        inet 127.0.0.1  netmask 255.0.0.0\n"
)

_LAST_OUTPUT = (
    "deploy   pts/0        bastion.internal  Tue Aug 25 09:12   still logged in\n"
    "root     pts/1        203.0.113.44      Mon Aug 24 22:41 - 23:03  (00:22)\n"
    "reboot   system boot  5.15.0-91-generic  Mon Aug 24 03:01   still running\n"
)


class ShellSession:
    """One fake login shell. Owns its own filesystem instance, cwd and history."""

    def __init__(
        self,
        session_id: str,
        source_ip: str,
        username: str = "root",
        hostname: str | None = None,
    ) -> None:
        settings = get_settings()
        self.hostname = hostname or settings.ssh_hostname
        self.username = username
        self.home = "/root" if username == "root" else f"/home/{username}"
        self.session_id = session_id
        self.ctx = build_context(session_id, source_ip, username)
        self.ctx.hostname = self.hostname
        self.fs: FsNode = build_default_fs(self.ctx)
        self.cwd = self.home if self.fs.children.get(self.home.lstrip("/")) else "/"
        self.history: list[str] = []
        from urllib.parse import urlparse

        base_url = settings.payload_callback_host or f"http://{settings.host}:{settings.port}"
        self.self_host = urlparse(base_url).netloc  # e.g. 10.0.0.1:4877
        self.env = {
            "USER": username,
            "HOME": self.home,
            "SHELL": "/bin/bash",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "en_US.UTF-8",
            "TERM": "xterm-256color",
            "PWD": self.cwd,
        }

    # ------------------------------------------------------------------
    # entry points
    # ------------------------------------------------------------------

    @property
    def prompt(self) -> str:
        short = self.cwd if len(self.cwd) < 30 else f"...{self.cwd[-27:]}"
        suffix = "#" if self.username == "root" else "$"
        return f"{self.username}@{self.hostname}:{short}{suffix} "

    def motd(self) -> str:
        return (
            f"Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-91-generic x86_64)\n\n"
            f" * Documentation:  https://help.ubuntu.com\n"
            f" * Management:     https://landscape.canonical.com\n"
            f" * Support:        https://ubuntu.com/advantage\n\n"
            f"  System information as of {self.ctx.now.astimezone(timezone.utc).strftime('%a %b %d %H:%M:%S %Y')}\n\n"
            f"  System load:  0.08               Processes:              112\n"
            f"  Usage of /:   41.2% of 78.20GB   Users logged in:        1\n"
            f"  Memory usage: 39%                IPv4 address for eth0:  10.0.7.10\n\n"
            f"Last login: {self.ctx.now.astimezone(timezone.utc).strftime('%a %b %d %H:%M:%S %Y')} from {self.ctx.source_ip}\n"
        )

    def run(self, line: str) -> str:
        line = line.strip()
        if not line:
            return ""
        self.history.append(line)
        if len(self.history) > MAX_HISTORY:
            self.history.pop(0)

        outputs: list[str] = []
        # `;` and `&&` sequencing (no subshells/pipes — rare in recon work)
        segments = re.split(r"\s*&&\s*|\s*;\s*", line)
        for segment in segments:
            if not segment:
                continue
            output = self._run_single(segment)
            if output:
                outputs.append(output)
        return "\n".join(outputs)[:MAX_OUTPUT_CHARS]

    # ------------------------------------------------------------------
    # single command dispatch (incl. redirect handling)
    # ------------------------------------------------------------------

    def _run_single(self, segment: str) -> str:
        redirect = None
        append = False
        match = re.search(r"\s(>>?)\s*([^\s>]+)\s*$", segment)
        if match and ">" in segment:
            append = match.group(1) == ">>"
            redirect = match.group(2)
            segment = segment[: match.start()].strip()

        try:
            tokens = shlex.split(segment)
        except ValueError:
            tokens = segment.split()
        if not tokens:
            return ""

        command, args = tokens[0], tokens[1:]
        if command == "sudo":
            if not args:
                return "usage: sudo command"
            command, args = args[0], args[1:]
            if command in ("su",):
                return "Authentication failure"

        handler = _HANDLERS.get(command)
        if handler is None:
            return f"bash: {command}: command not found"
        output = handler(self, args)
        if redirect:
            self._write_redirect(redirect, output, append)
            return ""
        return output

    def _write_redirect(self, target: str, content: str, append: bool) -> None:
        absolute = honeypot_fs.normalize_path(self.cwd, target, self.home)
        parent = honeypot_fs.resolve_node(self.fs, "/", honeypot_fs.parent_path(absolute))
        if parent is None or parent.kind != "dir":
            return
        name = honeypot_fs.base_name(absolute)
        existing = parent.children.get(name)
        if existing and existing.kind == "file" and append:
            base = existing.content if isinstance(existing.content, str) else ""
            existing.content = base.rstrip("\n") + ("\n" if base else "") + content + "\n"
        else:
            parent.children[name] = FsNode(kind="file", mode="0644", owner=self.username, content=content + "\n")

    # ------------------------------------------------------------------
    # shared helpers
    # ------------------------------------------------------------------

    def _resolve(self, path: str) -> tuple[str, FsNode | None]:
        absolute = honeypot_fs.normalize_path(self.cwd, path, self.home)
        return absolute, honeypot_fs.resolve_node(self.fs, self.cwd, path, self.home)

    def _fmt_ls(self, node: FsNode, name: str, ctx) -> str:
        kind_char = "d" if node.kind == "dir" else "-"
        perms = node.mode
        size = node.current_size(ctx)
        stamp = self.ctx.now.strftime("%b %d %H:%M")
        suffix = "/" if node.kind == "dir" else ""
        return f"{kind_char}{perms} 1 {node.owner:<8} {node.group:<8} {size:>8} {stamp} {name}{suffix}"


# ---------------------------------------------------------------------------
# command handlers (take (shell, args) -> output)
# ---------------------------------------------------------------------------


def _cmd_pwd(sh, args):
    return sh.cwd


def _cmd_cd(sh, args):
    target = args[0] if args else sh.home
    absolute, node = sh._resolve(target)
    if node is None:
        return f"bash: cd: {target}: No such file or directory"
    if node.kind != "dir":
        return f"bash: cd: {target}: Not a directory"
    sh.cwd = absolute or "/"
    sh.env["PWD"] = sh.cwd
    return ""


def _cmd_ls(sh, args):
    flags = {a for a in args if a.startswith("-")}
    paths = [a for a in args if not a.startswith("-")]
    long_mode = any(f.lstrip("-") and set(f.lstrip("-")) & set("la") for f in flags)
    show_all = any("a" in f.lstrip("-") for f in flags)
    target = paths[0] if paths else sh.cwd
    absolute, node = sh._resolve(target)
    if node is None:
        return f"ls: cannot access '{target}': No such file or directory"
    if node.kind == "file":
        return sh._fmt_ls(node, honeypot_fs.base_name(absolute), sh.ctx) if long_mode else name_or(absolute)
    entries = sorted(node.children.items())
    if not show_all:
        entries = [(n, c) for n, c in entries if not n.startswith(".")]
    if not long_mode:
        return "  ".join(n + ("/" if c.kind == "dir" else "") for n, c in entries) or ""
    lines = [f"total {len(entries) * 4}"]
    for name, child in entries:
        lines.append(sh._fmt_ls(child, name, sh.ctx))
    return "\n".join(lines)


def name_or(absolute: str) -> str:
    return honeypot_fs.base_name(absolute)


def _cmd_cat(sh, args):
    if not args:
        return "cat: missing operand"
    outs = []
    for path in args:
        _, node = sh._resolve(path)
        if node is None:
            outs.append(f"cat: {path}: No such file or directory")
        elif node.kind == "dir":
            outs.append(f"cat: {path}: Is a directory")
        else:
            outs.append(node.text(sh.ctx).rstrip("\n"))
    return "\n".join(outs)


def _cmd_head_tail(sh, args, lines=10, from_end=False):
    paths = [a for a in args if not a.startswith("-")]
    n = lines
    if "-n" in args:
        idx = args.index("-n")
        if idx + 1 < len(args):
            try:
                n = int(args[idx + 1])
            except ValueError:
                pass
    if not paths:
        return ""
    _, node = sh._resolve(paths[0])
    if node is None:
        cmd = "tail" if from_end else "head"
        return f"{cmd}: cannot open '{paths[0]}' for reading: No such file or directory"
    content = node.text(sh.ctx).rstrip("\n").split("\n")
    selected = content[-n:] if from_end else content[:n]
    return "\n".join(selected)


def _cmd_echo(sh, args):
    text = " ".join(args).strip("'\"")
    return text


def _cmd_touch(sh, args):
    for path in args:
        absolute = honeypot_fs.normalize_path(sh.cwd, path, sh.home)
        parent = honeypot_fs.resolve_node(sh.fs, "/", honeypot_fs.parent_path(absolute))
        if parent and parent.kind == "dir":
            name = honeypot_fs.base_name(absolute)
            if name not in parent.children:
                parent.children[name] = FsNode(kind="file", owner=sh.username, content="")
    return ""


def _cmd_mkdir(sh, args):
    for path in [a for a in args if not a.startswith("-")]:
        absolute = honeypot_fs.normalize_path(sh.cwd, path, sh.home)
        parent = honeypot_fs.resolve_node(sh.fs, "/", honeypot_fs.parent_path(absolute))
        if parent is None or parent.kind != "dir":
            return f"mkdir: cannot create directory '{path}': No such file or directory"
        name = honeypot_fs.base_name(absolute)
        if name in parent.children:
            return f"mkdir: cannot create directory '{path}': File exists"
        parent.children[name] = FsNode(kind="dir", mode="0755", owner=sh.username)
    return ""


def _cmd_rm(sh, args):
    recursive = any(a.lstrip("-") and "r" in a.lstrip("-") for a in args)
    for path in [a for a in args if not a.startswith("-")]:
        absolute = honeypot_fs.normalize_path(sh.cwd, path, sh.home)
        if absolute in ("/", "/etc", "/usr", "/var", "/bin"):
            return f"rm: it is dangerous to operate recursively on '{path}'"
        parent = honeypot_fs.resolve_node(sh.fs, "/", honeypot_fs.parent_path(absolute))
        name = honeypot_fs.base_name(absolute)
        if not parent or name not in parent.children:
            return f"rm: cannot remove '{path}': No such file or directory"
        target = parent.children[name]
        if target.kind == "dir" and target.children and not recursive:
            return f"rm: cannot remove '{path}': Is a directory"
        del parent.children[name]
    return ""


def _cmd_id(sh, args):
    if sh.username == "root":
        return "uid=0(root) gid=0(root) groups=0(root)"
    return f"uid=1000({sh.username}) gid=1000({sh.username}) groups=1000({sh.username}),27(sudo)"


def _cmd_whoami(sh, args):
    return sh.username


def _cmd_hostname(sh, args):
    return sh.hostname


def _cmd_uname(sh, args):
    joined = " ".join(args)
    if "a" in joined:
        return f"Linux {sh.hostname} 5.15.0-91-generic #101-Ubuntu SMP Thu Jul 24 12:12:23 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux"
    if "r" in joined:
        return "5.15.0-91-generic"
    return "Linux"


def _cmd_ps(sh, args):
    return _PS_OUTPUT


def _cmd_netstat(sh, args):
    return _NETSTAT_OUTPUT


def _cmd_ss(sh, args):
    return (
        "Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process\n"
        "tcp   LISTEN 0      128          0.0.0.0:22           0.0.0.0:*       users:((\"sshd\",pid=412,fd=3))\n"
        "tcp   LISTEN 0      511          0.0.0.0:80           0.0.0.0:*       users:((\"nginx\",pid=816,fd=6))\n"
        "tcp   LISTEN 0      244        127.0.0.1:5432         0.0.0.0:*       users:((\"postgres\",pid=940,fd=5))\n"
    )


def _cmd_ip(sh, args):
    if args and args[0] in ("a", "addr", "address"):
        return (
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n"
            "    inet 127.0.0.1/8 scope host lo\n"
            "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001\n"
            "    inet 10.0.7.10/24 brd 10.0.7.255 scope global eth0\n"
        )
    return "default via 10.0.7.1 dev eth0 proto dhcp metric 100"


def _cmd_ifconfig(sh, args):
    return _IFCONFIG_OUTPUT


def _cmd_env(sh, args):
    return "\n".join(f"{k}={v}" for k, v in sh.env.items())


def _cmd_history(sh, args):
    return "\n".join(f"  {i + 1}  {cmd}" for i, cmd in enumerate(sh.history[-50:]))


def _cmd_uptime(sh, args):
    return " 03:41:07 up 1 day, 40 min,  1 user,  load average: 0.08, 0.12, 0.09"


def _cmd_free(sh, args):
    return (
        "               total        used        free      shared  buff/cache   available\n"
        "Mem:       16000000     6240000     4200000      210000     5560000     9800000\n"
        "Swap:       2000000           0     2000000\n"
    )


def _cmd_df(sh, args):
    return (
        "Filesystem      Size  Used Avail Use% Mounted on\n"
        "/dev/nvme0n1p2   78G   32G   46G  41% /\n"
        "tmpfs           7.7G     0  7.7G   0% /dev/shm\n"
        "/dev/nvme0n1p1  512M  6.4M  506M   2% /boot/efi\n"
    )


def _cmd_last(sh, args):
    return _LAST_OUTPUT


def _cmd_w(sh, args):
    return (
        " 03:41:07 up 1 day, 40 min,  1 user,  load average: 0.08, 0.12, 0.09\n"
        "USER     TTY      FROM             LOGIN@   IDLE   WHAT\n"
        f"{sh.username:<8} pts/0    {sh.ctx.source_ip:<16} 03:12    0.00s  w\n"
    )


def _cmd_grep(sh, args):
    flags = [a for a in args if a.startswith("-")]
    rest = [a for a in args if not a.startswith("-")]
    if len(rest) < 2:
        return "usage: grep [-i] PATTERN FILE..."
    pattern, paths = rest[0], rest[1:]
    ignore_case = any("i" in f.lstrip("-") for f in flags)
    outs = []
    for path in paths:
        _, node = sh._resolve(path)
        if node is None:
            outs.append(f"grep: {path}: No such file or directory")
            continue
        if node.kind == "dir":
            outs.append(f"grep: {path}: Is a directory")
            continue
        for line in node.text(sh.ctx).splitlines():
            haystack = line if ignore_case else line
            needle = pattern if ignore_case else pattern
            if (needle.lower() in haystack.lower()) if ignore_case else (needle in haystack):
                outs.append(line)
    return "\n".join(outs)


def _cmd_find(sh, args):
    # find <path> [-name PATTERN] — supports the wildcard shapes recon uses.
    start = args[0] if args and not args[0].startswith("-") else "."
    name_idx = args.index("-name") if "-name" in args else None
    pattern = args[name_idx + 1] if name_idx is not None and name_idx + 1 < len(args) else None
    _, start_node = sh._resolve(start)
    if start_node is None:
        return f"find: '{start}': No such file or directory"
    regex = None
    if pattern:
        regex = re.compile("^" + re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".") + "$")
    results: list[str] = []
    base = honeypot_fs.normalize_path(sh.cwd, start, sh.home)

    def walk(node: FsNode, absolute: str) -> None:
        for name, child in sorted(node.children.items()):
            child_abs = f"{absolute.rstrip('/')}/{name}"
            if regex is None or regex.match(name):
                results.append(child_abs)
            if child.kind == "dir":
                walk(child, child_abs)

    walk(start_node, base)
    return "\n".join(results[:200])


def _cmd_wc(sh, args):
    paths = [a for a in args if not a.startswith("-")]
    if not paths:
        return ""
    _, node = sh._resolve(paths[0])
    if node is None:
        return f"wc: {paths[0]}: No such file or directory"
    text = node.text(sh.ctx)
    return f"{len(text.splitlines())} {len(text.split())} {len(text)} {paths[0]}"


def _cmd_crontab(sh, args):
    if args and args[0] == "-l":
        return (
            "# m h  dom mon dow   command\n"
            "0 2 * * * /root/backup/run_backup.sh >> /var/log/backup.log 2>&1\n"
        )
    if args and args[0] == "-e":
        return "no terminal available for interactive editor (crontab -e)"
    return ""


def _cmd_systemctl(sh, args):
    if args and args[0] in ("status", "is-active"):
        unit = args[1] if len(args) > 1 else "ssh"
        active = "ssh" in unit or "nginx" in unit or "postgres" in unit
        if active:
            return (
                f"● {unit}.service - {unit} service\n"
                f"     Loaded: loaded (/lib/systemd/system/{unit}.service; enabled)\n"
                f"     Active: active (running) since Mon 2026-08-24 03:02:11 UTC; 1 day ago\n"
                f"   Main PID: 470 (python3)\n"
                f"      Tasks: 6 (limit: 4519)\n"
            )
        return f"Unit {unit}.service could not be found."
    if args and args[0] == "list-units":
        return (
            "UNIT                    LOAD   ACTIVE SUB     DESCRIPTION\n"
            "ssh.service             loaded active running OpenBSD Secure Shell server\n"
            "nginx.service           loaded active running A high performance web server\n"
            "postgresql.service      loaded active running PostgreSQL RDBMS\n"
        )
    return ""


def _cmd_docker(sh, args):
    if args and args[0] == "ps":
        return (
            "CONTAINER ID   IMAGE                          STATUS         NAMES\n"
            "9f2a1c7b4d01   registry.internal/app:2.4.1    Up 1 day       app\n"
            "3e88ba91cc72   postgres:15                     Up 1 day       db\n"
        )
    return "Cannot connect to the Docker daemon" if args and args[0] == "info" else ""


INTERNAL_HOSTS = ("intranet.corp.local", "wiki.corp.local", "10.0.7.12")

INTRANET_PAGE = (
    "<html><head><title>内部知识库 · Corp Wiki</title></head>"
    "<body><h1>内部知识库</h1>"
    "<ul><li>生产数据库 db-primary.internal (10.0.7.11)</li>"
    "<li>备份服务 backup.internal（/backup 目录）</li>"
    "<li>运维数据接口 /portal/api/content</li></ul>"
    "<p>本周值班：wei.chen / fang.wang（审计码 {code}）</p>"
    "</body></html>"
)


def _cmd_wget_curl(sh, args, is_curl: bool = False):
    joined = " ".join(args)
    if any(host in joined for host in INTERNAL_HOSTS):
        from app.services.counter_intel import watermark_token

        code = watermark_token(getattr(sh, "session_fingerprint", "") or sh.session_id)
        return INTRANET_PAGE.replace("{code}", code)
    urls = [a for a in args if a.startswith(("http://", "https://"))]
    if not urls:
        return ("curl: try 'curl --help'" if is_curl else "wget: missing URL")
    url = urls[0]
    target = "index.html" if is_curl else None
    # Determine an output filename (-O / -o / trailing path segment)
    if "-O" in args and is_curl:
        idx = args.index("-O")
        if idx + 1 < len(args):
            target = args[idx + 1]
    if not is_curl:
        for flag in ("-O", "-o"):
            if flag in args:
                idx = args.index(flag)
                if idx + 1 < len(args):
                    target = args[idx + 1]
                break
        if target is None:
            target = url.rstrip("/").rsplit("/", 1)[-1] or "index.html"

    content = _fetch_decoy_content(sh, url)
    sh._write_redirect(target if target else "download.bin", content, append=False)
    if is_curl:
        return (
            f"  % Total    % Received % Time    Time     Time  Current\n"
            f"                                 Dload  Upload   Total   Spent    Left  Speed\n"
            f"100  {len(content):>5}  100  {len(content):>5}    0     0   88k      0 --:--:-- --:--:-- --:--:--  88k"
        )
    return (
        f"--{sh.ctx.now.strftime('%Y-%m-%d %H:%M:%S')}--  {url}\n"
        f"Resolving host... connected.\n"
        f"HTTP request sent, awaiting response... 200 OK\n"
        f"Length: {len(content)} (application/octet-stream)\n"
        f"Saving to: '{target}'\n\n"
        f"'{target}' saved [{len(content)}]\n"
    )


def _fetch_decoy_content(sh, url: str) -> str:
    """Content handed back for a wget/curl inside the fake shell.

    We deliberately never fetch attacker-chosen remote URLs (that would turn
    the honeypot into a request proxy). Payload-style URLs pointing back at
    this platform fetch the real payload; everything else gets a plausible
    watermarked stub.
    """
    from urllib.parse import urlparse

    host = urlparse(url).netloc
    own_hosts = {sh.self_host, f"{sh.hostname}:8000"} - {None, ""}
    if host and host in own_hosts and "/payload/" in url or (host and host in own_hosts and "/c2/" in url):
        # Real payload delivery from our own endpoints over loopback.
        try:
            import urllib.request

            with urllib.request.urlopen(url, timeout=3) as resp:  # noqa: S310 - our own server
                return resp.read(65536).decode("utf-8", errors="replace")
        except Exception:
            pass
    return (
        f"#!/bin/sh\n"
        f"# fetched: {url}\n"
        f"# honeypot-watermark: {decoy_password(sh.ctx)}\n"
        f"echo staged\n"
    )


def _cmd_clear(sh, args):
    return "\x1b[2J\x1b[H"


def _cmd_exit(sh, args):
    return "logout"


def _cmd_mysql(sh, args):
    return "ERROR 2002 (HY000): Can't connect to local MySQL server through socket '/var/run/mysqld/mysqld.sock' (2)"


def _cmd_psql(sh, args):
    return "psql: error: connection to server on socket failed: No such file or directory"


def _cmd_python(sh, args):
    if any("--version" in a or "-V" in a for a in args):
        return "Python 3.10.12"
    return ""


def _cmd_vim_nano(sh, args):
    return "Warning: output is not to a terminal (interactive editors are not supported here)"


def _cmd_unknown_interactive(sh, args):
    return ""


_HANDLERS = {
    "pwd": _cmd_pwd,
    "cd": _cmd_cd,
    "ls": _cmd_ls,
    "dir": _cmd_ls,
    "cat": _cmd_cat,
    "head": lambda sh, a: _cmd_head_tail(sh, a, 10, from_end=False),
    "tail": lambda sh, a: _cmd_head_tail(sh, a, 10, from_end=True),
    "echo": _cmd_echo,
    "touch": _cmd_touch,
    "mkdir": _cmd_mkdir,
    "rm": _cmd_rm,
    "rmdir": _cmd_rm,
    "id": _cmd_id,
    "whoami": _cmd_whoami,
    "hostname": _cmd_hostname,
    "uname": _cmd_uname,
    "ps": _cmd_ps,
    "netstat": _cmd_netstat,
    "ss": _cmd_ss,
    "ip": _cmd_ip,
    "ifconfig": _cmd_ifconfig,
    "env": _cmd_env,
    "printenv": _cmd_env,
    "history": _cmd_history,
    "uptime": _cmd_uptime,
    "free": _cmd_free,
    "df": _cmd_df,
    "last": _cmd_last,
    "w": _cmd_w,
    "grep": _cmd_grep,
    "find": _cmd_find,
    "wc": _cmd_wc,
    "crontab": _cmd_crontab,
    "systemctl": _cmd_systemctl,
    "service": _cmd_systemctl,
    "docker": _cmd_docker,
    "wget": lambda sh, a: _cmd_wget_curl(sh, a, is_curl=False),
    "curl": lambda sh, a: _cmd_wget_curl(sh, a, is_curl=True),
    "clear": _cmd_clear,
    "logout": _cmd_exit,
    "exit": _cmd_exit,
    "mysql": _cmd_mysql,
    "psql": _cmd_psql,
    "python": _cmd_python,
    "python3": _cmd_python,
    "vim": _cmd_vim_nano,
    "vi": _cmd_vim_nano,
    "nano": _cmd_vim_nano,
    # no-ops that must not look broken
    "chmod": lambda sh, a: "",
    "chown": lambda sh, a: "",
    "sleep": lambda sh, a: "",
    "date": lambda sh, a: sh.ctx.now.astimezone(timezone.utc).strftime("%a %b %d %H:%M:%S UTC %Y"),
    "groups": lambda sh, a: _cmd_id(sh, a).split("groups=")[-1],
    "tty": lambda sh, a: "/dev/pts/0",
    "ping": lambda sh, a: f"PING {a[0] if a else '?'} 56(84) bytes of data.\n^C",
    "tar": lambda sh, a: "tar: This is the stub implementation",
    "scp": lambda sh, a: "",
    "ssh": lambda sh, a: "",
    "apt": lambda sh, a: "Reading package lists... Done\nBuilding dependency tree... Done",
    "apt-get": lambda sh, a: "Reading package lists... Done",
    "top": _cmd_ps,
    "htop": _cmd_ps,
}
