"""
Tests for FMGLockContext workspace management
"""
from unittest.mock import Mock

import pytest

from pyFMG.fortimgr import FMGLockContext


class TestFMGLockContext:
    """Test FMGLockContext functionality"""

    @pytest.fixture
    def mock_fmg_with_lock_context(self):
        """Create mock FMG with lock context"""
        fmg = Mock()
        fmg.check_adom_workspace = True
        lock_ctx = FMGLockContext(fmg)
        return fmg, lock_ctx

    def test_init(self, mock_fmg_with_lock_context):
        """Test FMGLockContext initialization"""
        fmg, lock_ctx = mock_fmg_with_lock_context

        assert lock_ctx._fmg is fmg
        assert lock_ctx._locked_adom_list == []
        assert lock_ctx._uses_workspace is False
        assert lock_ctx._uses_adoms is False

    def test_properties(self, mock_fmg_with_lock_context):
        """Test property getters and setters"""
        fmg, lock_ctx = mock_fmg_with_lock_context

        # Test uses_workspace
        lock_ctx.uses_workspace = True
        assert lock_ctx.uses_workspace is True

        # Test uses_adoms
        lock_ctx.uses_adoms = True
        assert lock_ctx.uses_adoms is True

    def test_add_adom_to_lock_list(self, mock_fmg_with_lock_context):
        """Test adding ADOM to lock list"""
        fmg, lock_ctx = mock_fmg_with_lock_context

        lock_ctx.add_adom_to_lock_list("root")
        assert "root" in lock_ctx._locked_adom_list

        # Adding same ADOM again should not duplicate
        lock_ctx.add_adom_to_lock_list("root")
        assert lock_ctx._locked_adom_list.count("root") == 1

        # Add different ADOM
        lock_ctx.add_adom_to_lock_list("test_adom")
        assert "test_adom" in lock_ctx._locked_adom_list
        assert len(lock_ctx._locked_adom_list) == 2

    def test_remove_adom_from_lock_list(self, mock_fmg_with_lock_context):
        """Test removing ADOM from lock list"""
        fmg, lock_ctx = mock_fmg_with_lock_context

        # Add ADOMs first
        lock_ctx.add_adom_to_lock_list("root")
        lock_ctx.add_adom_to_lock_list("test_adom")

        # Remove one ADOM
        lock_ctx.remove_adom_from_lock_list("root")
        assert "root" not in lock_ctx._locked_adom_list
        assert "test_adom" in lock_ctx._locked_adom_list

        # Removing non-existent ADOM should not raise error
        lock_ctx.remove_adom_from_lock_list("non_existent")
        assert len(lock_ctx._locked_adom_list) == 1

    def test_check_mode_no_workspace_check(self, mock_fmg_with_lock_context):
        """Test check_mode when check_adom_workspace is disabled"""
        fmg, lock_ctx = mock_fmg_with_lock_context
        fmg.check_adom_workspace = False

        lock_ctx.check_mode()

        assert lock_ctx.uses_workspace is False
        assert lock_ctx.uses_adoms is False

    def test_check_mode_with_workspace_enabled(self, mock_fmg_with_lock_context):
        """Test check_mode with workspace enabled"""
        fmg, lock_ctx = mock_fmg_with_lock_context

        # Mock successful get response with workspace enabled
        fmg.get.return_value = (0, {
            "workspace-mode": 1,
            "adom-status": 1
        })

        lock_ctx.check_mode()

        assert lock_ctx.uses_workspace is True
        assert lock_ctx.uses_adoms is True
        fmg.get.assert_called_once_with(
            "/cli/global/system/global",
            fields=["workspace-mode", "adom-status"]
        )

    def test_check_mode_workspace_disabled(self, mock_fmg_with_lock_context):
        """Test check_mode with workspace disabled"""
        fmg, lock_ctx = mock_fmg_with_lock_context

        # Mock response with workspace disabled
        fmg.get.return_value = (0, {
            "workspace-mode": 0,
            "adom-status": 0
        })

        lock_ctx.check_mode()

        assert lock_ctx.uses_workspace is False
        assert lock_ctx.uses_adoms is False

    def test_check_mode_missing_keys(self, mock_fmg_with_lock_context):
        """Test check_mode with missing response keys"""
        fmg, lock_ctx = mock_fmg_with_lock_context

        # Mock response with missing keys
        fmg.get.return_value = (0, {})

        lock_ctx.check_mode()

        assert lock_ctx.uses_workspace is False
        assert lock_ctx.uses_adoms is False

    def test_lock_adom_root(self, mock_fmg_with_lock_context):
        """Test locking root ADOM"""
        fmg, lock_ctx = mock_fmg_with_lock_context

        # Mock successful lock response
        fmg.execute.return_value = (0, {"status": {"message": "OK"}})

        code, response = lock_ctx.lock_adom("root")

        assert code == 0
        assert "root" in lock_ctx._locked_adom_list
        fmg.execute.assert_called_once_with("/dvmdb/adom/root/workspace/lock/", {})

    def test_lock_adom_global(self, mock_fmg_with_lock_context):
        """Test locking global ADOM"""
        fmg, lock_ctx = mock_fmg_with_lock_context

        fmg.execute.return_value = (0, {"status": {"message": "OK"}})

        code, response = lock_ctx.lock_adom("global")

        assert code == 0
        assert "global" in lock_ctx._locked_adom_list
        fmg.execute.assert_called_once_with("/dvmdb/global/workspace/lock/", {})

    def test_lock_adom_custom(self, mock_fmg_with_lock_context):
        """Test locking custom ADOM"""
        fmg, lock_ctx = mock_fmg_with_lock_context

        fmg.execute.return_value = (0, {"status": {"message": "OK"}})

        code, response = lock_ctx.lock_adom("test_adom")

        assert code == 0
        assert "test_adom" in lock_ctx._locked_adom_list
        fmg.execute.assert_called_once_with("/dvmdb/adom/test_adom/workspace/lock/", {})

    def test_lock_adom_none(self, mock_fmg_with_lock_context):
        """Test locking with None ADOM (defaults to root)"""
        fmg, lock_ctx = mock_fmg_with_lock_context

        fmg.execute.return_value = (0, {"status": {"message": "OK"}})

        code, response = lock_ctx.lock_adom(None)

        assert code == 0
        assert None in lock_ctx._locked_adom_list
        fmg.execute.assert_called_once_with("/dvmdb/adom/root/workspace/lock", {})

    def test_lock_adom_failure(self, mock_fmg_with_lock_context):
        """Test lock ADOM failure"""
        fmg, lock_ctx = mock_fmg_with_lock_context

        fmg.execute.return_value = (-1, {"status": {"message": "Failed"}})

        code, response = lock_ctx.lock_adom("root")

        assert code == -1
        assert "root" not in lock_ctx._locked_adom_list

    def test_unlock_adom_success(self, mock_fmg_with_lock_context):
        """Test unlocking ADOM successfully"""
        fmg, lock_ctx = mock_fmg_with_lock_context

        # Add ADOM to locked list first
        lock_ctx.add_adom_to_lock_list("root")

        fmg.execute.return_value = (0, {"status": {"message": "OK"}})

        code, response = lock_ctx.unlock_adom("root")

        assert code == 0
        assert "root" not in lock_ctx._locked_adom_list
        fmg.execute.assert_called_once_with("/dvmdb/adom/root/workspace/unlock/", {})

    def test_unlock_adom_global(self, mock_fmg_with_lock_context):
        """Test unlocking global ADOM"""
        fmg, lock_ctx = mock_fmg_with_lock_context

        lock_ctx.add_adom_to_lock_list("global")
        fmg.execute.return_value = (0, {"status": {"message": "OK"}})

        code, response = lock_ctx.unlock_adom("global")

        assert code == 0
        assert "global" not in lock_ctx._locked_adom_list
        fmg.execute.assert_called_once_with("/dvmdb/global/workspace/unlock/", {})

    def test_run_unlock(self, mock_fmg_with_lock_context):
        """Test unlocking all locked ADOMs"""
        fmg, lock_ctx = mock_fmg_with_lock_context

        # Add multiple ADOMs to locked list
        lock_ctx.add_adom_to_lock_list("root")
        lock_ctx.add_adom_to_lock_list("test_adom")
        lock_ctx.add_adom_to_lock_list("global")

        # Mock successful unlock for all
        fmg.execute.return_value = (0, {"status": {"message": "OK"}})

        lock_ctx.run_unlock()

        # All ADOMs should be unlocked
        assert len(lock_ctx._locked_adom_list) == 0
        assert fmg.execute.call_count == 3

    def test_commit_changes_root(self, mock_fmg_with_lock_context):
        """Test committing changes to root ADOM"""
        fmg, lock_ctx = mock_fmg_with_lock_context

        fmg.execute.return_value = (0, {"status": {"message": "OK"}})

        code, response = lock_ctx.commit_changes("root")

        assert code == 0
        fmg.execute.assert_called_once_with("/dvmdb/adom/root/workspace/commit", {})

    def test_commit_changes_global(self, mock_fmg_with_lock_context):
        """Test committing changes to global ADOM"""
        fmg, lock_ctx = mock_fmg_with_lock_context

        fmg.execute.return_value = (0, {"status": {"message": "OK"}})

        code, response = lock_ctx.commit_changes("global")

        assert code == 0
        fmg.execute.assert_called_once_with("/dvmdb/global/workspace/commit/", {})

    def test_commit_changes_aux(self, mock_fmg_with_lock_context):
        """Test committing changes with aux flag"""
        fmg, lock_ctx = mock_fmg_with_lock_context

        fmg.execute.return_value = (0, {"status": {"message": "OK"}})

        code, response = lock_ctx.commit_changes("test_adom", aux=True)

        assert code == 0
        fmg.execute.assert_called_once_with("/pm/config/adom/test_adom/workspace/commit", {})

    def test_commit_changes_none(self, mock_fmg_with_lock_context):
        """Test committing changes with None ADOM"""
        fmg, lock_ctx = mock_fmg_with_lock_context

        fmg.execute.return_value = (0, {"status": {"message": "OK"}})

        code, response = lock_ctx.commit_changes(None)

        assert code == 0
        fmg.execute.assert_called_once_with("/dvmdb/adom/root/workspace/commit", {})


class TestFortiManagerLockIntegration:
    """Test integration of lock context with FortiManager"""

    def test_fmg_lock_methods(self, mock_fmg):
        """Test that FortiManager properly delegates to lock context"""
        # Mock the lock context methods
        mock_fmg._lock_ctx.lock_adom = Mock(return_value=(0, {}))
        mock_fmg._lock_ctx.unlock_adom = Mock(return_value=(0, {}))
        mock_fmg._lock_ctx.commit_changes = Mock(return_value=(0, {}))

        # Test lock_adom delegation
        code, response = mock_fmg.lock_adom("root")
        mock_fmg._lock_ctx.lock_adom.assert_called_once_with("root")

        # Test unlock_adom delegation
        code, response = mock_fmg.unlock_adom("root")
        mock_fmg._lock_ctx.unlock_adom.assert_called_once_with("root")

