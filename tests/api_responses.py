"""Sample API payloads modelled after real OPNsense responses."""

from typing import Any, Dict, List

ACTIVITY_HEADERS = [
    "last pid: 24927;  load averages:  2.06,  0.74,  0.29  up 0+00:00:52    08:44:18",
    "147 threads:   2 running, 123 sleeping, 22 waiting",
    "CPU:  0.0% user,  0.0% nice,  0.4% system,  0.0% interrupt, 99.6% idle",
    "Mem: 159M Active, 117M Inact, 212M Wired, 103M Buf, 471M Free",
    "Swap: 7674M Total, 7674M Free",
]


def activity(load1: float = 2.06, load5: float = 0.74, load15: float = 0.29, idle: float = 99.6):
    """Build a diagnostics/activity/get_activity response."""
    headers = list(ACTIVITY_HEADERS)
    headers[0] = (
        f"last pid: 24927;  load averages:  {load1},  {load5},  {load15}"
        "  up 0+00:00:52    08:44:18"
    )
    headers[2] = f"CPU:  0.0% user,  0.0% nice,  0.4% system,  0.0% interrupt, {idle}% idle"
    return {"headers": headers}


def system_resources(total: int = 8192, used: int = 2048, arc: int = 0) -> Dict[str, Any]:
    """Build a diagnostics/system/system_resources response."""
    memory = {"total_frmt": str(total), "used_frmt": str(used)}
    if arc:
        memory["arc_frmt"] = str(arc)
    return {"memory": memory}


def system_swap(*devices: Dict[str, Any]) -> Dict[str, Any]:
    """Build a diagnostics/system/system_swap response."""
    return {"swap": list(devices)}


def swap_device(device: str = "/dev/gpt/swapfs", total: int = 8192, used: int = 82):
    """Build a single swap device entry."""
    return {"device": device, "total": str(total), "used": str(used)}


def system_disk(*devices: Dict[str, Any]) -> Dict[str, Any]:
    """Build a diagnostics/system/system_disk response."""
    return {"devices": list(devices)}


def disk_device(mountpoint: str = "/", used_pct: int = 2) -> Dict[str, Any]:
    """Build a single disk device entry."""
    return {
        "device": "/dev/gpt/rootfs",
        "type": "ufs",
        "blocks": "222G",
        "used": "3.9G",
        "available": "201G",
        "used_pct": used_pct,
        "mountpoint": mountpoint,
    }


def interfaces(*rows: Dict[str, Any]) -> Dict[str, Any]:
    """Build an interfaces/overview/interfaces_info response."""
    return {"rows": list(rows)}


def interface(device: str, status: str = "up", enabled: bool = True) -> Dict[str, Any]:
    """Build a single interface entry."""
    return {"device": device, "enabled": enabled, "status": status}


def services(*rows: Dict[str, Any]) -> Dict[str, Any]:
    """Build a core/service/search response."""
    return {"rows": list(rows)}


def service(name: str, running: bool = True, description: str = "") -> Dict[str, Any]:
    """Build a single service entry."""
    return {
        "id": name,
        "name": name,
        "description": description or name,
        "running": 1 if running else 0,
    }


def ipsec(*rows: Dict[str, Any]) -> Dict[str, Any]:
    """Build an ipsec/sessions/search_phase1 response."""
    return {"rows": list(rows)}


def tunnel(desc: str, connected: bool = True) -> Dict[str, Any]:
    """Build a single IPsec phase 1 entry."""
    return {"phase1desc": desc, "connected": connected}


def wireguard(*rows: Dict[str, Any]) -> Dict[str, Any]:
    """Build a wireguard/service/show response."""
    return {"rows": list(rows)}


def peer(name: str, status: str = "online", wg_type: str = "peer") -> Dict[str, Any]:
    """Build a single WireGuard entry."""
    return {
        "name": name,
        "type": wg_type,
        "peer-status": status,
        "endpoint": "203.0.113.1:51820",
    }


def firmware(
    status: str = "none",
    status_msg: str = "There are no updates available.",
    upgrade: int = 0,
    reinstall: int = 0,
    remove: int = 0,
    status_reboot: str = "0",
) -> Dict[str, Any]:
    """Build a core/firmware/status response."""

    def pkgs(count: int) -> List[Dict[str, str]]:
        return [{"name": f"pkg{i}"} for i in range(count)]

    return {
        "status": status,
        "status_msg": status_msg,
        "status_reboot": status_reboot,
        "upgrade_packages": pkgs(upgrade),
        "reinstall_packages": pkgs(reinstall),
        "remove_packages": pkgs(remove),
    }
