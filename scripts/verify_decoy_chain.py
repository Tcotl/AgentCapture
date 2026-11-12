#!/usr/bin/env python3
"""End-to-end smoke test for AgentCapture three-type decoy chain.

It uses the admin UI HTTP endpoints to create:
1) API route decoy, 2) credential decoy, 3) file decoy bound to both;
then deploys the file decoy, downloads it, uses the generated credential login,
and verifies the credential record page contains the triggered credential.
"""
from __future__ import annotations

import argparse
import http.cookiejar
import re
import sys
import time
import urllib.parse
import urllib.request
from urllib.error import HTTPError


def build_opener() -> urllib.request.OpenerDirector:
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


def post_form(opener: urllib.request.OpenerDirector, base: str, path: str, data: dict[str, str]) -> tuple[int, str, str]:
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(
        base + path,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        resp = opener.open(req, timeout=15)
        return resp.status, resp.geturl(), resp.read().decode("utf-8", errors="replace")
    except HTTPError as exc:
        return exc.code, exc.geturl(), exc.read().decode("utf-8", errors="replace")


def get_text(opener: urllib.request.OpenerDirector, base: str, path: str) -> tuple[int, str]:
    try:
        resp = opener.open(base + path, timeout=15)
        return resp.status, resp.read().decode("utf-8", errors="replace")
    except HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace")


def must(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"[FAIL] {message}")


def find_template_id(html: str, name: str) -> str:
    escaped = re.escape(name)
    for row in re.findall(r'<tr>.*?</tr>', html, flags=re.S):
        if name not in row:
            continue
        form_match = re.search(r'/admin/decoys/templates/(\d+)/(?:deploy|update|delete)', row)
        if form_match:
            return form_match.group(1)
    option_match = re.search(rf'<option value="(\d+)">[^<]*{escaped}', html)
    if option_match:
        return option_match.group(1)
    must(False, f"template id not found for: {name}")
    return ""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="http://localhost:4877")
    parser.add_argument("--honeypot-base", default="http://localhost:48777",
                        help="Web 蜜罐源（蜜饵下载与触发端点所在平面）")
    parser.add_argument("--admin-path", default="agentcapture",
                        help="控制台安全路径前缀（系统设置中配置）")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default="admin")
    args = parser.parse_args()
    base = args.base.rstrip("/")
    hp = args.honeypot_base.rstrip("/")
    A = "/" + args.admin_path.strip("/")  # console security path prefix
    opener = build_opener()

    status, url, _ = post_form(opener, base, A + "/admin/login", {"username": args.username, "password": args.password})
    must(status == 200 and not url.endswith("/admin/login"), "admin login failed")

    nonce = str(int(time.time() * 1000))
    api_name = f"自检API路由蜜饵{nonce}"
    cred_name = f"自检凭证蜜饵{nonce}"
    file_name = f"自检文件蜜饵{nonce}"
    route_path = f"/api/private/self-check-{nonce}"

    post_form(opener, base, A + "/admin/decoys/templates", {
        "return_to": "/admin/decoy-management",
        "decoy_type": "api_route",
        "name": api_name,
        "route_path": route_path,
        "exposure_channel": "js",
        "description": "self-check api route",
    })
    post_form(opener, base, A + "/admin/decoys/templates", {
        "return_to": "/admin/decoy-management",
        "decoy_type": "credential",
        "name": cred_name,
        "target_service_key": "web-admin",
        "username_dictionary": "selfcheckadmin",
        "password_length": "14",
        "description": "self-check credential",
    })
    status, html = get_text(opener, base, A + "/admin/decoy-management")
    must(status == 200, "cannot read decoy management after create")
    api_id = find_template_id(html, api_name)
    cred_id = find_template_id(html, cred_name)

    post_form(opener, base, A + "/admin/decoys/templates", {
        "return_to": "/admin/decoy-management",
        "decoy_type": "file",
        "name": file_name,
        "file_name": f"self-check-{nonce}.txt",
        "target_service_key": "file-decoy",
        "bind_route_template_id": api_id,
        "bind_credential_template_id": cred_id,
        "description": "self-check chained file",
        "content_template": "api=$api_route\nlogin=$credential_login\nuser=$credential_username\npass=$credential_password\n",
    })
    status, html = get_text(opener, base, A + "/admin/decoy-management")
    file_id = find_template_id(html, file_name)
    post_form(opener, base, A + f"/admin/decoys/templates/{file_id}/deploy", {
        "return_to": "/admin/decoy-management",
        "deployed_host": "self-check-system",
    })

    # Verify the built-in default chain shortcut is functional too.
    post_form(opener, base, A + "/admin/decoys/deploy-default-chain", {
        "return_to": "/admin/decoy-management",
        "deployed_host": "self-check-default-chain",
    })

    status, html = get_text(opener, base, A + "/admin/decoy-management")
    must("一键生成默认攻击链路" in html, "default chain shortcut missing")
    must("默认攻击链路文件蜜饵" in html, "default chain template missing")
    must("JS 投放片段" in html and "凭证投放 SQL" in html and "文件下载链接" in html, "delivery snippets missing")
    file_path_match = re.search(rf'(/d/[a-f0-9]+/self-check-{nonce}\.txt)', html)
    must(bool(file_path_match), "file deployment path missing")
    file_path = file_path_match.group(1)
    manifest_match = re.search(r'/admin/decoys/deployments/(\d+)/manifest\.json', html)
    must(bool(manifest_match), "deployment manifest link missing")
    status, manifest = get_text(opener, base, A + f"/admin/decoys/deployments/{manifest_match.group(1)}/manifest.json")
    must(status == 200 and '"snippets"' in manifest and '"bindings"' in manifest, "manifest download invalid")

    status, file_body = get_text(opener, hp, file_path)
    must(status == 200, "file decoy download failed")
    login_match = re.search(r'login=(/_bait/credential/[a-f0-9]+/login)', file_body)
    user_match = re.search(r'user=([^\n]+)', file_body)
    pass_match = re.search(r'pass=([^\n]+)', file_body)
    api_match = re.search(r'api=(/_bait/api/private/self-check-\d+)', file_body)
    must(bool(login_match and user_match and pass_match and api_match), "bound chain variables not rendered")

    # Trigger API route and credential login.
    get_text(opener, hp, api_match.group(1))
    status, _, _ = post_form(opener, hp, login_match.group(1), {
        "username": user_match.group(1),
        "password": pass_match.group(1),
    })
    must(status == 403, "credential decoy login did not block")

    status, creds = get_text(opener, base, A + "/admin/credentials")
    must("credential-decoy" in creds and user_match.group(1) in creds, "credential record missing")
    status, decoy_ops = get_text(opener, base, A + "/admin/decoy-management")
    must(status == 200 and (file_path in decoy_ops or "fetched" in decoy_ops), "decoy deployment record missing")

    print("[OK] decoy chain verified")
    print(f"api={api_match.group(1)}")
    print(f"file={file_path}")
    print(f"credential_login={login_match.group(1)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
