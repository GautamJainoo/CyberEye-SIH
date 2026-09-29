"""
Scope Manifest and Scope Guard implementation for WMSA.
Enforces loopback isolation, rejects out-of-scope targets, and provides kill-switch logic.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from pathlib import Path
from typing import Any, List, Optional
from urllib.parse import urlparse, urlunparse

import yaml
from pydantic import BaseModel, Field, field_validator


class ScopeViolation(Exception):
    """Raised when an outbound URL or action violates scope rules."""


class KillSwitchActive(Exception):
    """Raised when an active kill switch is detected."""


class TestIdentity(BaseModel):
    id: str
    role: str
    token: str
    entitled: bool = False


DEFAULT_REPO_URL = "https://github.com/koala73/worldmonitor"
DEFAULT_WEBSITE_URL = "https://www.worldmonitor.app"


class ScopeManifest(BaseModel):
    scope_id: str
    repo_url: str
    website_url: str = DEFAULT_WEBSITE_URL
    commit_sha: str = Field(..., min_length=7, max_length=64)
    local_path: str = "target"
    allowed_hosts: List[str] = Field(
        default_factory=lambda: ["127.0.0.1", "localhost", "worldmonitor", "target"]
    )
    allowed_ports: List[int] = Field(default_factory=lambda: [3000, 8080, 46123])
    allowed_route_prefixes: List[str] = Field(
        default_factory=lambda: ["/", "/api/", "/docs/"]
    )
    test_identities: List[TestIdentity] = Field(default_factory=list)
    profile: str = "lite"
    max_requests_per_probe: int = 20
    max_scan_minutes: int = 15
    approved_by: str
    approved_at: str

    @field_validator("allowed_hosts")
    @classmethod
    def validate_allowed_hosts(cls, v: List[str]) -> List[str]:
        forbidden = {"worldmonitor.app", "www.worldmonitor.app"}
        for host in v:
            if host.lower() in forbidden:
                raise ValueError(f"Host '{host}' is explicitly forbidden in scope manifest")
        return v


from wmsa.paths import get_base_dir


def get_kill_sentinel_path(base_dir: Optional[Path] = None) -> Path:
    base = base_dir or get_base_dir()
    return base / "KILL"


def is_kill_active(base_dir: Optional[Path] = None) -> bool:
    sentinel = get_kill_sentinel_path(base_dir)
    alt_sentinel = (base_dir or get_base_dir()) / ".kill"
    return sentinel.exists() or alt_sentinel.exists()


def activate_kill_switch(base_dir: Optional[Path] = None) -> Path:
    sentinel = get_kill_sentinel_path(base_dir)
    sentinel.touch(exist_ok=True)
    return sentinel


def deactivate_kill_switch(base_dir: Optional[Path] = None) -> None:
    sentinel = get_kill_sentinel_path(base_dir)
    if sentinel.exists():
        sentinel.unlink()
    alt_sentinel = (base_dir or get_base_dir()) / ".kill"
    if alt_sentinel.exists():
        alt_sentinel.unlink()


def load_scope_manifest(path: Optional[Path] = None) -> ScopeManifest:
    if path:
        manifest_path = path
        if not manifest_path.exists():
            if (manifest_path.parent / "backend" / "config" / "scope.yaml").exists():
                manifest_path = manifest_path.parent / "backend" / "config" / "scope.yaml"
            elif (get_base_dir() / "config" / "scope.yaml").exists():
                manifest_path = get_base_dir() / "config" / "scope.yaml"
    else:
        manifest_path = get_base_dir() / "config" / "scope.yaml"

    if not manifest_path.exists():
        raise ScopeViolation(
            f"Scope manifest missing at {manifest_path}. Outbound active scans refused (fail closed)."
        )
    with open(manifest_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not data or not isinstance(data, dict):
        raise ScopeViolation(f"Invalid scope manifest at {manifest_path}")
    return ScopeManifest(**data)


def canonicalize_url(raw_url: str) -> str:
    """
    Parses and canonicalizes URL.
    Strips userinfo (e.g. user:pass@host) to prevent URL spoofing.
    Ensures lower-case scheme and netloc.
    """
    if not raw_url or not isinstance(raw_url, str):
        raise ScopeViolation("URL must be a non-empty string")

    parsed = urlparse(raw_url.strip())
    scheme = parsed.scheme.lower()

    if scheme not in ("http", "https"):
        raise ScopeViolation(f"Prohibited URL scheme '{scheme}'. Only http and https permitted.")

    hostname = parsed.hostname
    if not hostname:
        raise ScopeViolation(f"Invalid URL '{raw_url}': missing hostname.")

    hostname = hostname.lower()
    port = parsed.port
    if port is None:
        port = 80 if scheme == "http" else 443

    path = parsed.path or "/"
    netloc = f"{hostname}:{port}"

    canonical = urlunparse((scheme, netloc, path, parsed.params, parsed.query, ""))
    return canonical


def is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def resolve_and_verify_host(hostname: str, allowed_hosts: List[str]) -> None:
    """
    Verifies that the hostname resolves ONLY to loopback or approved docker aliases.
    Rejects cloud metadata (169.254.169.254), public IPs, and non-allowlisted destinations.
    """
    norm_host = hostname.lower().strip("[]")

    # Explicit ban on target public domain
    if "worldmonitor.app" in norm_host:
        raise ScopeViolation(
            f"Access to public target '{norm_host}' is strictly forbidden by non-negotiable rules."
        )

    # Directly check allowed list names
    norm_allowed = [h.lower().strip("[]") for h in allowed_hosts]
    if norm_host in norm_allowed:
        # If it's a numeric IP, make sure it's loopback or private docker alias
        if is_ip_address(norm_host):
            ip = ipaddress.ip_address(norm_host)
            if not (ip.is_loopback or ip.is_private):
                raise ScopeViolation(f"Host IP '{norm_host}' is not loopback or private.")
        return

    # Check IP directly if host is numeric
    if is_ip_address(norm_host):
        ip = ipaddress.ip_address(norm_host)
        if ip.is_link_local or str(ip) == "169.254.169.254":
            raise ScopeViolation(f"Metadata/link-local address '{norm_host}' blocked.")
        if ip.is_loopback and ("127.0.0.1" in norm_allowed or "localhost" in norm_allowed):
            return
        raise ScopeViolation(f"Resolved IP '{norm_host}' is not in allowed hosts.")

    # DNS Resolution check (prevent DNS rebinding or external resolution)
    try:
        resolved_ips = socket.getaddrinfo(norm_host, None)
    except socket.gaierror as e:
        raise ScopeViolation(f"Cannot resolve host '{norm_host}': {e}")

    for item in resolved_ips:
        sockaddr = item[4]
        ip_str = sockaddr[0]
        ip_obj = ipaddress.ip_address(ip_str)

        # Reject link-local / cloud metadata
        if ip_obj.is_link_local or str(ip_obj) == "169.254.169.254":
            raise ScopeViolation(f"Metadata/link-local address '{ip_str}' blocked.")

        # Reject public IPs
        if not (ip_obj.is_loopback or ip_obj.is_private):
            raise ScopeViolation(f"Host '{norm_host}' resolved to public IP '{ip_str}' (blocked).")

        # Must resolve to an allowed host representation
        if not (ip_obj.is_loopback and ("127.0.0.1" in norm_allowed or "localhost" in norm_allowed)):
            if str(ip_obj) not in norm_allowed:
                raise ScopeViolation(
                    f"Host '{norm_host}' resolved to '{ip_str}' which is not in allowed_hosts."
                )


class ScopeGuard:
    """
    Enforces scope constraints for outbound requests.
    Fail-closed: Every outbound HTTP request must pass guard(url).
    """

    def __init__(self, manifest: Optional[ScopeManifest] = None, base_dir: Optional[Path] = None):
        self.base_dir = base_dir or get_base_dir()
        self._manifest = manifest

    @property
    def manifest(self) -> ScopeManifest:
        if self._manifest is None:
            self._manifest = load_scope_manifest(self.base_dir / "config" / "scope.yaml")
        return self._manifest

    def guard(self, raw_url: str) -> str:
        """
        Validates URL against scope and kill switch.
        Returns canonicalized URL if permitted.
        Raises ScopeViolation or KillSwitchActive if rejected.
        """
        if is_kill_active(self.base_dir):
            raise KillSwitchActive("Kill switch is active! Aborting all active operations.")

        manifest = self.manifest
        canonical = canonicalize_url(raw_url)
        parsed = urlparse(canonical)
        host = parsed.hostname or ""
        port = parsed.port or (80 if parsed.scheme == "http" else 443)
        path = parsed.path or "/"

        # Check host & DNS resolution FIRST (reject forbidden domains and metadata IPs immediately)
        resolve_and_verify_host(host, manifest.allowed_hosts)

        # Check port
        if port not in manifest.allowed_ports:
            raise ScopeViolation(
                f"Port {port} not in allowed_ports {manifest.allowed_ports} for URL '{raw_url}'."
            )

        # Check route prefix
        matched_prefix = any(
            path.startswith(prefix) for prefix in manifest.allowed_route_prefixes
        )
        if not matched_prefix:
            raise ScopeViolation(
                f"Path '{path}' does not match allowed_route_prefixes {manifest.allowed_route_prefixes}."
            )

        return canonical
