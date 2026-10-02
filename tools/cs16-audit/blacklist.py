"""Append-only blacklist updates and optional publication to the fork's main branch."""
from datetime import datetime
import ipaddress
import json
import math
import os
from pathlib import Path
import subprocess
import tempfile

GROUP = "CS 1.6 automated audit"
REASON = "Fake 32+ players / Repeated misleading A2S replies (ping <100 ms)"
DEFAULT_BLACKLIST = Path(__file__).resolve().parents[2] / "blacklisted_iplist.json"


def detected_ips(report):
    """Import only classified positives with a measured ping strictly below 100 ms."""
    if not isinstance(report, dict) or not isinstance(report.get("servers"), list):
        raise ValueError("Informe inválido: falta servers")
    result = set()
    for row in report["servers"]:
        if row.get("status") not in ("spam", "sospechoso"):
            continue
        ping = row.get("median_ping_ms")
        if ping is None and row.get("ping_source") == "Steam":
            ping = row.get("steam_ping_ms")
        if isinstance(ping, bool) or not isinstance(ping, (int, float)) or not math.isfinite(ping) or not 0 <= ping < 100:
            continue
        address = ipaddress.IPv4Address(row["ip"])
        if not address.is_global:
            raise ValueError(f"IP no pública en informe: {address}")
        result.add(str(address))
    return sorted(result, key=ipaddress.IPv4Address)


def append_ips(path, incoming):
    """Prevent simultaneous runs from replacing one another's additions."""
    path = Path(path)
    lock = path.with_name(path.name + ".lock")
    try:
        descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as error:
        raise RuntimeError(f"Otra actualización tiene el lock: {lock}") from error
    try:
        os.close(descriptor)
        return _append_ips(path, incoming)
    finally:
        lock.unlink()


def _append_ips(path, incoming):
    """Preserve every existing entry; deduplicate additions across all groups."""
    path = Path(path)
    # Validate everything before touching the file, even if the input is a generator.
    candidates = {str(ipaddress.IPv4Address(ip)) for ip in incoming}
    if any(not ipaddress.IPv4Address(ip).is_global for ip in candidates):
        raise ValueError("Sólo se pueden agregar IPv4 públicas")
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict) or not isinstance(data.get("list"), list):
        raise ValueError("Blacklist inválida: falta list")
    existing = set()
    for group in data["list"]:
        if not isinstance(group, dict) or not isinstance(group.get("ip"), list):
            raise ValueError("Grupo inválido en blacklist")
        existing.update(str(ipaddress.IPv4Address(ip)) for ip in group["ip"])
    additions = sorted(candidates - existing, key=ipaddress.IPv4Address)
    if not additions:
        return []  # No rewrite: repeated executions preserve the exact file bytes.
    group = next((g for g in data["list"] if g.get("name") == GROUP), None)
    if group is None:
        group = {"name": GROUP, "reason": REASON, "ip": []}
        data["list"].append(group)
    group["ip"].extend(additions)
    # Same-directory atomic replacement prevents a truncated JSON on interruption.
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                                         dir=path.parent, prefix=path.name + ".", suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(data, stream, ensure_ascii=False, indent=4)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return additions


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def check_publish(path):
    path = Path(path).resolve()
    root = Path(git(path.parent, "rev-parse", "--show-toplevel")).resolve()
    if path != root / "blacklisted_iplist.json":
        raise ValueError("--publish requiere el blacklisted_iplist.json de la raíz del repo")
    if git(root, "branch", "--show-current") != "main":
        raise ValueError("--publish requiere estar en main")
    if git(root, "diff", "--cached", "--name-only"):
        raise ValueError("Hay cambios staged; resolvelos antes de publicar")
    git(root, "ls-files", "--error-unmatch", "blacklisted_iplist.json")
    git(root, "fetch", "origin", "main")
    if git(root, "rev-parse", "HEAD") != git(root, "rev-parse", "origin/main"):
        raise ValueError("main debe estar sincronizada con origin/main antes de publicar")
    return root


def publish(path):
    root = check_publish(path)
    if not git(root, "diff", "HEAD", "--", "blacklisted_iplist.json"):
        print("JSON sin cambios: no se crea commit ni se pushea.", flush=True)
        return None
    message = "feat: blacklist updated (" + datetime.now().strftime("%Y-%m-%d") + ")"
    # --only never includes unrelated working-tree files in the commit.
    git(root, "commit", "--only", "-m", message, "--", "blacklisted_iplist.json")
    commit = git(root, "rev-parse", "HEAD")
    subprocess.run(["git", "-C", str(root), "push", "origin", "main"], check=True)
    return commit


def update_blacklist(path, report):
    ips = detected_ips(report)
    additions = append_ips(path, ips)
    print(f"Blacklist: {len(ips)} IPs detectadas; {len(additions)} nuevas. {Path(path).resolve()}", flush=True)
    return additions
