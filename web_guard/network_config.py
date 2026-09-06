"""Capture, apply, and restore Windows DNS settings without shell interpolation."""

from __future__ import annotations

import ipaddress
import json
import subprocess


CREATE_NO_WINDOW = 0x08000000


def _run(arguments, timeout=30):
    result = subprocess.run(
        arguments,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
        creationflags=CREATE_NO_WINDOW,
    )
    if result.returncode:
        message = (result.stderr or result.stdout or "Windows command failed").strip()
        raise RuntimeError(message)
    return result.stdout.strip()


def _powershell(script: str, timeout=30):
    return _run([
        "powershell.exe", "-NoProfile", "-NonInteractive",
        "-ExecutionPolicy", "Bypass", "-Command", script,
    ], timeout=timeout)


def capture_active_dns() -> list[dict]:
    script = r"""
$ErrorActionPreference = 'Stop'
$indices = @(
  Get-NetRoute -DestinationPrefix '0.0.0.0/0','::/0' -ErrorAction SilentlyContinue |
  Where-Object { $_.State -eq 'Alive' -or -not $_.State } |
  Sort-Object RouteMetric, InterfaceMetric |
  Select-Object -ExpandProperty InterfaceIndex -Unique
)
$rows = @()
foreach ($index in $indices) {
  $adapter = Get-NetAdapter -InterfaceIndex $index -ErrorAction SilentlyContinue
  if (-not $adapter -or $adapter.Status -ne 'Up') { continue }
  $guid = $adapter.InterfaceGuid
  $v4 = Get-DnsClientServerAddress -InterfaceIndex $index -AddressFamily IPv4 -ErrorAction SilentlyContinue
  $v6 = Get-DnsClientServerAddress -InterfaceIndex $index -AddressFamily IPv6 -ErrorAction SilentlyContinue
  $r4 = Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$guid" -ErrorAction SilentlyContinue
  $r6 = Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$guid" -ErrorAction SilentlyContinue
  $hasV4 = $null -ne (Get-NetRoute -InterfaceIndex $index -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object -First 1)
  $hasV6 = $null -ne (Get-NetRoute -InterfaceIndex $index -DestinationPrefix '::/0' -ErrorAction SilentlyContinue | Select-Object -First 1)
  $rows += [pscustomobject]@{
    interface_index = [int]$index
    alias = [string]$adapter.Name
    ipv4_automatic = [string]::IsNullOrWhiteSpace([string]$r4.NameServer)
    ipv6_automatic = [string]::IsNullOrWhiteSpace([string]$r6.NameServer)
    ipv4_active = [bool]$hasV4
    ipv6_active = [bool]$hasV6
    ipv4_servers = @($v4.ServerAddresses)
    ipv6_servers = @($v6.ServerAddresses)
  }
}
@($rows) | ConvertTo-Json -Depth 4 -Compress
"""
    raw = _powershell(script)
    if not raw:
        return []
    parsed = json.loads(raw)
    rows = parsed if isinstance(parsed, list) else [parsed]
    clean = []
    for row in rows:
        try:
            index = int(row["interface_index"])
        except (KeyError, TypeError, ValueError):
            continue
        clean.append({
            "interface_index": index,
            "alias": str(row.get("alias", "Network adapter"))[:200],
            "ipv4_automatic": bool(row.get("ipv4_automatic", True)),
            "ipv6_automatic": bool(row.get("ipv6_automatic", True)),
            "ipv4_active": bool(row.get("ipv4_active", True)),
            "ipv6_active": bool(row.get("ipv6_active", False)),
            "ipv4_servers": _clean_servers(row.get("ipv4_servers"), 4),
            "ipv6_servers": _clean_servers(row.get("ipv6_servers"), 6),
        })
    return clean


def _clean_servers(values, version: int) -> list[str]:
    if isinstance(values, str):
        values = [values]
    result = []
    for value in values if isinstance(values, list) else []:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        if address.version == version and not address.is_loopback:
            text = str(address)
            if text not in result:
                result.append(text)
    return result[:8]


def upstreams(snapshot: list[dict]) -> list[str]:
    result = []
    for row in snapshot:
        for value in row.get("ipv4_servers", []) + row.get("ipv6_servers", []):
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                continue
            if address.is_unspecified or address.is_loopback:
                continue
            # Windows' old site-local placeholders are not usable resolvers.
            if str(address).lower().startswith("fec0:0:0:ffff::"):
                continue
            text = str(address)
            if text not in result:
                result.append(text)
    # Never silently send requests to a third-party resolver. Activation fails
    # safely if Windows does not provide a usable original resolver.
    return result


def apply_local_dns(snapshot: list[dict]):
    changed = []
    try:
        for row in snapshot:
            index = int(row["interface_index"])
            changed.append(row)
            if row.get("ipv4_active", True):
                _run(["netsh", "interface", "ipv4", "set", "dnsservers",
                      f"name={index}", "source=static", "address=127.0.0.1",
                      "register=primary", "validate=no"])
            if row.get("ipv6_active", False):
                _run(["netsh", "interface", "ipv6", "set", "dnsservers",
                      f"name={index}", "source=static", "address=::1",
                      "register=primary", "validate=no"])
    except Exception:
        restore_dns(changed)
        raise
    flush_dns()


def _restore_family(index: int, family: str, automatic: bool, servers: list[str]):
    if automatic or not servers:
        _run(["netsh", "interface", family, "set", "dnsservers",
              f"name={index}", "source=dhcp"])
        return
    _run(["netsh", "interface", family, "set", "dnsservers",
          f"name={index}", "source=static", f"address={servers[0]}",
          "register=primary", "validate=no"])
    for position, address in enumerate(servers[1:], start=2):
        _run(["netsh", "interface", family, "add", "dnsservers",
              f"name={index}", f"address={address}", f"index={position}",
              "validate=no"])


def restore_dns(snapshot: list[dict]):
    failures = []
    for row in snapshot:
        try:
            index = int(row["interface_index"])
            if row.get("ipv4_active", True):
                _restore_family(index, "ipv4", bool(row.get("ipv4_automatic", True)),
                                _clean_servers(row.get("ipv4_servers"), 4))
            if row.get("ipv6_active", False):
                _restore_family(index, "ipv6", bool(row.get("ipv6_automatic", True)),
                                _clean_servers(row.get("ipv6_servers"), 6))
        except (RuntimeError, ValueError) as exc:
            failures.append(f"{row.get('alias', 'Adapter')}: {exc}")
    flush_dns()
    if failures:
        raise RuntimeError("; ".join(failures))


def flush_dns():
    try:
        _run(["ipconfig", "/flushdns"], timeout=20)
    except (OSError, RuntimeError, subprocess.TimeoutExpired):
        pass


def network_environment() -> dict:
    """Report VPN, NRPT, and active-adapter DNS state without changing it."""
    script = r"""
$ErrorActionPreference = 'Stop'
$defaultIndices = @(
  Get-NetRoute -DestinationPrefix '0.0.0.0/0','::/0' -ErrorAction SilentlyContinue |
  Where-Object { $_.State -eq 'Alive' -or -not $_.State } |
  Select-Object -ExpandProperty InterfaceIndex -Unique
)
$connectedVpns = @()
foreach ($allUsers in @($false, $true)) {
  try {
    $items = if ($allUsers) { Get-VpnConnection -AllUserConnection -ErrorAction Stop } else { Get-VpnConnection -ErrorAction Stop }
    foreach ($item in @($items)) {
      if ($item.ConnectionStatus -eq 'Connected' -and $connectedVpns -notcontains $item.Name) {
        $connectedVpns += [string]$item.Name
      }
    }
  } catch {}
}
$adapters = @()
foreach ($adapter in @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object Status -eq 'Up')) {
  $name = [string]$adapter.Name
  $description = [string]$adapter.InterfaceDescription
  $isDefault = $defaultIndices -contains $adapter.ifIndex
  $isVpn = ($name + ' ' + $description) -match '(?i)vpn|wireguard|wintun|openvpn|nordlynx|tailscale|zerotier|tap-windows|proton|mullvad'
  if (-not $isDefault -and -not $isVpn) { continue }
  $dns = @(
    Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue |
    ForEach-Object { $_.ServerAddresses } |
    Where-Object { $_ }
  )
  $adapters += [pscustomobject]@{
    interface_index = [int]$adapter.ifIndex
    alias = $name
    description = $description
    default_route = [bool]$isDefault
    vpn = [bool]$isVpn
    dns_servers = @($dns)
  }
  if ($isVpn -and $connectedVpns -notcontains $name) { $connectedVpns += $name }
}
$nrpt = @(Get-DnsClientNrptPolicy -Effective -ErrorAction SilentlyContinue | Where-Object { $_.Namespace })
[pscustomobject]@{
  vpn_names = @($connectedVpns)
  nrpt_rules = [int]$nrpt.Count
  adapters = @($adapters)
} | ConvertTo-Json -Depth 5 -Compress
"""
    try:
        raw = _powershell(script, timeout=12)
        parsed = json.loads(raw) if raw else {}
    except (OSError, RuntimeError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return {"vpn_names": [], "nrpt_rules": 0, "adapters": [], "scan_error": True}
    supplied_adapters = parsed.get("adapters", []) if isinstance(parsed, dict) else []
    if isinstance(supplied_adapters, dict):
        supplied_adapters = [supplied_adapters]
    adapters = []
    for row in supplied_adapters if isinstance(supplied_adapters, list) else []:
        if not isinstance(row, dict):
            continue
        servers = row.get("dns_servers", [])
        if isinstance(servers, str):
            servers = [servers]
        adapters.append({
            "interface_index": int(row.get("interface_index", 0)),
            "alias": str(row.get("alias", "Network adapter"))[:200],
            "description": str(row.get("description", ""))[:300],
            "default_route": bool(row.get("default_route")),
            "vpn": bool(row.get("vpn")),
            "dns_servers": [str(item)[:100] for item in servers if item][:16],
        })
    names = parsed.get("vpn_names", []) if isinstance(parsed, dict) else []
    if isinstance(names, str):
        names = [names]
    try:
        nrpt_rules = max(0, int(parsed.get("nrpt_rules", 0)))
    except (TypeError, ValueError):
        nrpt_rules = 0
    return {
        "vpn_names": [str(item)[:200] for item in names if item][:16],
        "nrpt_rules": nrpt_rules,
        "adapters": adapters,
        "scan_error": False,
    }


def compatibility_summary(environment: dict, filter_running: bool) -> dict:
    adapters = environment.get("adapters", []) if isinstance(environment, dict) else []
    bypass = []
    if filter_running:
        for row in adapters:
            if not row.get("default_route"):
                continue
            servers = {str(item).lower() for item in row.get("dns_servers", [])}
            if servers and not servers.issubset({"127.0.0.1", "::1"}):
                bypass.append(str(row.get("alias", "Network adapter")))
    vpn_names = list(environment.get("vpn_names", [])) if isinstance(environment, dict) else []
    try:
        nrpt_rules = int(environment.get("nrpt_rules", 0)) if isinstance(environment, dict) else 0
    except (TypeError, ValueError):
        nrpt_rules = 0
    return {
        "vpn_active": bool(vpn_names),
        "vpn_names": vpn_names,
        "nrpt_rules": max(0, nrpt_rules),
        "dns_bypass": bool(bypass or (filter_running and nrpt_rules)),
        "bypass_adapters": bypass,
        "scan_error": bool(environment.get("scan_error")) if isinstance(environment, dict) else True,
    }
