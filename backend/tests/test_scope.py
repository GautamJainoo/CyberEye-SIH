"""
Unit tests for WMSA Scope Guard, URL Canonicalizer, and Kill Switch.
Enforces non-negotiable rules: loopback only, out-of-scope targets blocked.
"""

from pathlib import Path
import pytest

from wmsa.scope import (
    ScopeGuard,
    ScopeManifest,
    ScopeViolation,
    KillSwitchActive,
    canonicalize_url,
    activate_kill_switch,
    deactivate_kill_switch,
    is_kill_active,
)


@pytest.fixture
def manifest():
    return ScopeManifest(
        scope_id="test-scope",
        repo_url="https://github.com/koala73/worldmonitor",
        commit_sha="0d5c618e4307414546a9be84a482ac06b7d56749",
        local_path="target",
        allowed_hosts=["127.0.0.1", "localhost", "worldmonitor"],
        allowed_ports=[3000, 8080, 46123],
        allowed_route_prefixes=["/", "/api/", "/docs/"],
        approved_by="Tester",
        approved_at="2026-09-28T00:00:00Z",
    )


@pytest.fixture
def scope_guard(manifest, tmp_path):
    # Ensure kill switch is off in tmp_path
    deactivate_kill_switch(tmp_path)
    return ScopeGuard(manifest=manifest, base_dir=tmp_path)


def test_canonicalize_url():
    # Userinfo stripping
    assert canonicalize_url("http://user:pass@127.0.0.1:3000/api") == "http://127.0.0.1:3000/api"
    # Scheme lowercase
    assert canonicalize_url("HTTP://127.0.0.1:3000/path") == "http://127.0.0.1:3000/path"


def test_scope_guard_permits_allowed_loopback(scope_guard):
    assert scope_guard.guard("http://127.0.0.1:3000/api/health") == "http://127.0.0.1:3000/api/health"
    assert scope_guard.guard("http://localhost:8080/docs/guide") == "http://localhost:8080/docs/guide"
    assert scope_guard.guard("http://127.0.0.1:46123/") == "http://127.0.0.1:46123/"


def test_scope_guard_blocks_target_production_domain(scope_guard):
    with pytest.raises(ScopeViolation, match="strictly forbidden"):
        scope_guard.guard("https://worldmonitor.app/api/search")

    with pytest.raises(ScopeViolation, match="strictly forbidden"):
        scope_guard.guard("http://worldmonitor.app:3000/")


def test_scope_guard_blocks_public_ips(scope_guard):
    with pytest.raises(ScopeViolation):
        scope_guard.guard("http://8.8.8.8:3000/")

    with pytest.raises(ScopeViolation):
        scope_guard.guard("http://93.184.216.34:3000/api")


def test_scope_guard_blocks_cloud_metadata(scope_guard):
    with pytest.raises(ScopeViolation, match="Metadata/link-local address"):
        scope_guard.guard("http://169.254.169.254/latest/meta-data/")


def test_scope_guard_blocks_userinfo_evasion(scope_guard):
    # E.g. http://127.0.0.1@evil.com:3000
    with pytest.raises(ScopeViolation):
        scope_guard.guard("http://127.0.0.1@evil.com:3000/api")


def test_scope_guard_blocks_disallowed_schemes(scope_guard):
    with pytest.raises(ScopeViolation, match="Prohibited URL scheme"):
        scope_guard.guard("file:///etc/passwd")

    with pytest.raises(ScopeViolation, match="Prohibited URL scheme"):
        scope_guard.guard("gopher://127.0.0.1:3000/")


def test_scope_guard_blocks_disallowed_ports(scope_guard):
    with pytest.raises(ScopeViolation, match="Port 22 not in allowed_ports"):
        scope_guard.guard("http://127.0.0.1:22/api")

    with pytest.raises(ScopeViolation, match="Port 8000 not in allowed_ports"):
        scope_guard.guard("http://127.0.0.1:8000/")


def test_scope_guard_blocks_disallowed_routes(scope_guard):
    with pytest.raises(ScopeViolation, match="does not match allowed_route_prefixes"):
        # If prefix list is explicitly restricted and does not have root prefix "/"
        restricted_manifest = ScopeManifest(
            scope_id="restricted",
            repo_url="https://github.com/koala73/worldmonitor",
            commit_sha="0d5c618e4307414546a9be84a482ac06b7d56749",
            local_path="target",
            allowed_hosts=["127.0.0.1"],
            allowed_ports=[3000],
            allowed_route_prefixes=["/api/", "/docs/"],
            approved_by="Tester",
            approved_at="2026-09-28T00:00:00Z",
        )
        guard = ScopeGuard(manifest=restricted_manifest)
        guard.guard("http://127.0.0.1:3000/secret/admin")


def test_kill_switch_blocks_operations(scope_guard, tmp_path):
    activate_kill_switch(tmp_path)
    assert is_kill_active(tmp_path) is True

    with pytest.raises(KillSwitchActive, match="Kill switch is active"):
        scope_guard.guard("http://127.0.0.1:3000/api/health")

    deactivate_kill_switch(tmp_path)
    assert is_kill_active(tmp_path) is False
    assert scope_guard.guard("http://127.0.0.1:3000/api/health") == "http://127.0.0.1:3000/api/health"
