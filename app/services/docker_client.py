"""Minimal Docker Engine API client over the unix socket.

Uses httpx's UDS transport (already a platform dependency) instead of the
docker SDK — the platform only needs a narrow slice of the Engine API:
image listing/loading, container create/start/stop/remove/inspect/logs.

Every call degrades to ``DockerUnavailable`` when the socket is absent so
the UI can show a clear "Docker 不可用" state instead of a traceback.
"""
from __future__ import annotations

import json
from typing import Any

import httpx

DOCKER_SOCKET = "/var/run/docker.sock"
API_VERSION = "v1.41"
LABEL_MANAGED = "agentcapture.honeypot"
LABEL_NAME = "agentcapture.name"


class DockerUnavailable(RuntimeError):
    pass


class DockerError(RuntimeError):
    pass


def _client(timeout: float = 60.0) -> httpx.Client:
    try:
        return httpx.Client(
            transport=httpx.HTTPTransport(uds=DOCKER_SOCKET),
            base_url="http://docker",
            timeout=timeout,
        )
    except Exception as exc:  # noqa: BLE001
        raise DockerUnavailable(f"Docker socket 不可用：{exc}") from exc


def _ok(resp: httpx.Response) -> httpx.Response:
    if resp.status_code >= 400:
        try:
            msg = resp.json().get("message", "")
        except Exception:  # noqa: BLE001
            msg = resp.text[:200]
        raise DockerError(f"Docker API {resp.status_code}: {msg}")
    return resp


def available() -> bool:
    try:
        with _client(timeout=4.0) as c:
            return c.get(f"/{API_VERSION}/version").status_code == 200
    except Exception:  # noqa: BLE001
        return False


def version() -> str:
    with _client(timeout=4.0) as c:
        r = _ok(c.get(f"/{API_VERSION}/version"))
        return r.json().get("Version", "")


def list_images() -> list[dict[str, Any]]:
    with _client() as c:
        r = _ok(c.get(f"/{API_VERSION}/images/json"))
        out = []
        for img in r.json():
            tags = img.get("RepoTags") or []
            out.append({
                "id": (img.get("Id") or "").replace("sha256:", "")[:12],
                "tags": tags,
                "size": img.get("Size", 0),
            })
        return out


def load_image(tar: bytes | Any, *, timeout: float = 600.0) -> list[str]:
    """``docker load`` a saved image tar; returns the loaded repo tags."""
    with _client(timeout=timeout) as c:
        r = _ok(c.post(
            f"/{API_VERSION}/images/load",
            content=tar,
            headers={"Content-Type": "application/x-tar"},
        ))
    tags: list[str] = []
    for line in r.text.splitlines():
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        stream = obj.get("stream") or ""
        if "Loaded image" in stream:
            tags.append(stream.split("Loaded image", 1)[1].strip().rstrip("\n"))
    return tags


def create_container(name: str, image: str, container_port: int,
                     host_port: int | None = None,
                     labels: dict[str, str] | None = None) -> str:
    """Create (not start) a container; returns the 64-char container id.

    ``host_port=None`` keeps the container un-published — the deception
    proxy reaches it over the bridge network instead.
    """
    body: dict[str, Any] = {
        "Image": image,
        "Labels": {LABEL_MANAGED: "true", **(labels or {})},
        "HostConfig": {},
    }
    if host_port is not None:
        body["HostConfig"]["PortBindings"] = {
            f"{container_port}/tcp": [{"HostPort": str(host_port)}]
        }
        body["ExposedPorts"] = {f"{container_port}/tcp": {}}
    with _client() as c:
        r = _ok(c.post(f"/{API_VERSION}/containers/create?name={name}", json=body))
        return r.json()["Id"]


def start_container(cid: str) -> None:
    with _client() as c:
        _ok(c.post(f"/{API_VERSION}/containers/{cid}/start"))


def stop_container(cid: str, *, timeout: int = 10) -> None:
    with _client(timeout=timeout + 20.0) as c:
        c.post(f"/{API_VERSION}/containers/{cid}/stop?t={timeout}")


def remove_container(cid: str, *, force: bool = True, volumes: bool = True) -> None:
    with _client() as c:
        q = f"force={'true' if force else 'false'}&v={'true' if volumes else 'false'}"
        _ok(c.delete(f"/{API_VERSION}/containers/{cid}?{q}"))


def inspect_container(cid: str) -> dict[str, Any]:
    with _client() as c:
        return _ok(c.get(f"/{API_VERSION}/containers/{cid}/json")).json()


def container_ip(cid: str) -> str:
    """Bridge-network IP of a running container (empty when none)."""
    info = inspect_container(cid)
    nets = (info.get("NetworkSettings") or {}).get("Networks") or {}
    for net in nets.values():
        ip = net.get("IPAddress")
        if ip:
            return ip
    return ""


def container_state(cid: str) -> str:
    try:
        info = inspect_container(cid)
        return "running" if (info.get("State") or {}).get("Running") else "stopped"
    except DockerError:
        return "removed"


def list_managed() -> list[dict[str, Any]]:
    filters = json.dumps({"label": [f"{LABEL_MANAGED}=true"]})
    with _client() as c:
        r = _ok(c.get(f"/{API_VERSION}/containers/json", params={"all": "true", "filters": filters}))
        out = []
        for cinfo in r.json():
            names = [n.lstrip("/") for n in cinfo.get("Names") or []]
            ports = []
            for p in (cinfo.get("Ports") or []):
                if p.get("PublicPort"):
                    ports.append(f"{p.get('PublicPort')}->{p.get('PrivatePort')}")
            out.append({
                "id": (cinfo.get("Id") or "")[:12],
                "name": names[0] if names else "",
                "image": cinfo.get("Image", ""),
                "state": cinfo.get("State", ""),
                "ports": ", ".join(ports),
            })
        return out


def container_logs(cid: str, *, tail: int = 200) -> str:
    with _client() as c:
        r = c.get(f"/{API_VERSION}/containers/{cid}/logs",
                  params={"stdout": "true", "stderr": "true", "tail": tail, "timestamps": "true"})
        return r.text
