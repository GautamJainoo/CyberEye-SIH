"""
Unit tests for TargetManager and target health checking.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from wmsa.scope import ScopeManifest
from wmsa.target import TargetManager, TargetError


@pytest.fixture
def manifest():
    return ScopeManifest(
        scope_id="test-scope",
        repo_url="https://github.com/koala73/worldmonitor",
        commit_sha="0d5c618e4307414546a9be84a482ac06b7d56749",
        local_path="target",
        allowed_hosts=["127.0.0.1", "localhost"],
        allowed_ports=[3000, 8080],
        allowed_route_prefixes=["/"],
        approved_by="Tester",
        approved_at="2026-09-28T00:00:00Z",
    )


def test_target_health_offline(tmp_path, manifest):
    # Port 3000 is not running target during unit test -> health check returns false cleanly
    mgr = TargetManager(base_dir=tmp_path, scope_manifest=manifest)
    healthy, msg = mgr.check_health("http://127.0.0.1:3000")
    assert healthy is False
    assert "Connection refused" in msg or "failed" in msg or "Unexpected" in msg


def test_target_health_scope_enforced(tmp_path, manifest):
    mgr = TargetManager(base_dir=tmp_path, scope_manifest=manifest)
    healthy, msg = mgr.check_health("https://worldmonitor.app")
    assert healthy is False
    assert "Scope guard error" in msg


def test_target_health_success_mocked(tmp_path, manifest):
    mgr = TargetManager(base_dir=tmp_path, scope_manifest=manifest)
    with patch("httpx.Client.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_get.return_value = mock_resp

        healthy, msg = mgr.check_health("http://127.0.0.1:3000")
        assert healthy is True
        assert "HTTP 200" in msg


def test_verify_commit_mismatch(tmp_path, manifest):
    mgr = TargetManager(base_dir=tmp_path, scope_manifest=manifest)
    target_git = tmp_path / "target" / ".git"
    target_git.parent.mkdir(parents=True, exist_ok=True)
    target_git.mkdir()

    with patch("subprocess.run") as mock_run:
        mock_res = MagicMock()
        mock_res.stdout = "1111111111111111111111111111111111111111\n"
        mock_run.return_value = mock_res

        with pytest.raises(TargetError, match="Commit verification failed"):
            mgr.verify_commit()
