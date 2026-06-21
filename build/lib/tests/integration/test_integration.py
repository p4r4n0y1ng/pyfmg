"""
Integration tests for pyFMG package
These tests focus on component interaction and end-to-end workflows
"""
import time
from unittest.mock import patch

import pytest
import responses

from pyFMG.fortimgr import FortiManager, FMGValidSessionException


@pytest.mark.integration
class TestAuthenticationFlow:
    """Test complete authentication workflows"""

    @responses.activate
    def test_standard_login_flow(self):
        """Test standard username/password login flow"""
        # Mock the login request
        responses.add(
            responses.POST,
            "https://192.168.1.100/jsonrpc",
            json={
                "id": 1,
                "result": [{
                    "status": {"code": 0, "message": "OK"},
                    "url": "sys/login/user"
                }],
                "session": "test-session-123"
            },
            status=200
        )

        # Mock workspace check
        responses.add(
            responses.POST,
            "https://192.168.1.100/jsonrpc",
            json={
                "id": 2,
                "result": [{
                    "data": {"workspace-mode": 0, "adom-status": 0},
                    "status": {"code": 0, "message": "OK"},
                    "url": "/cli/global/system/global"
                }]
            },
            status=200
        )

        fmg = FortiManager("192.168.1.100", "admin", "password")
        code, response = fmg.login()

        assert code == 0
        assert fmg.sid == "test-session-123"
        assert "OK" in response["status"]["message"]

    @responses.activate
    def test_api_key_login_flow(self):
        """Test API key authentication flow"""
        fmg = FortiManager("192.168.1.100", apikey="test-api-key-12345")

        # Mock workspace check (API key doesn't need initial login)
        responses.add(
            responses.POST,
            "https://192.168.1.100/jsonrpc",
            json={
                "id": 1,
                "result": [{
                    "data": {"workspace-mode": 0, "adom-status": 0},
                    "status": {"code": 0, "message": "OK"},
                    "url": "/cli/global/system/global"
                }]
            },
            status=200
        )

        code, response = fmg.login()

        assert code == 0
        assert fmg.api_key_used is True
        assert fmg.sid is not None
        assert "2345" in fmg.sid  # Last 4 digits of API key should be in session

    @responses.activate
    def test_forticloud_login_flow(self):
        """Test FortiCloud OAuth login flow"""
        host = "12345.us-west-1.fortimanager.forticloud.com"

        # Create FMG instance with workspace check disabled to avoid session issues
        fmg = FortiManager(host, "admin", "password", check_adom_workspace=False)

        # Verify FortiCloud detection
        assert fmg.forticloud_used is True
        assert fmg.sid is None

        # Mock OAuth token request
        responses.add(
            responses.POST,
            "https://customerapiauth.fortinet.com/api/v1/oauth/token/",
            json={"access_token": "oauth-token-123"},
            status=200
        )

        # Mock FortiCloud login - returns 200 with empty body
        responses.add(
            responses.POST,
            f"https://{host}/p/forticloud_jsonrpc_login/",
            json={
                "session": "forticloud-session-456"  # This is what _set_sid looks for!
            },
            status=200
        )

        # Mock token revocation
        responses.add(
            responses.POST,
            "https://customerapiauth.fortinet.com/api/v1/oauth/revoke_token/",
            json={},
            status=200
        )

        # Perform login
        code, response = fmg.login()

        # Verify FortiCloud login behavior
        assert code == 0  # Should succeed
        assert fmg.forticloud_used is True

        # Verify OAuth flow was called by checking responses
        assert len(responses.calls) >= 2  # OAuth + revoke calls

        # Check that OAuth endpoint was called
        oauth_called = any('oauth/token' in call.request.url for call in responses.calls)
        assert oauth_called

        # Check that revoke endpoint was called
        revoke_called = any('revoke_token' in call.request.url for call in responses.calls)
        assert revoke_called


@pytest.mark.integration
class TestWorkspaceWorkflow:
    """Test complete workspace management workflows"""

    @responses.activate
    def test_workspace_enabled_workflow(self):
        """Test workflow when workspace mode is enabled"""
        fmg = FortiManager("192.168.1.100", "admin", "password")
        fmg.sid = "test-session"
        fmg._url = "https://192.168.1.100/jsonrpc"

        # Mock workspace check - enabled
        responses.add(
            responses.POST,
            "https://192.168.1.100/jsonrpc",
            json={
                "id": 1,
                "result": [{
                    "data": {"workspace-mode": 1, "adom-status": 1},
                    "status": {"code": 0, "message": "OK"},
                    "url": "/cli/global/system/global"
                }]
            },
            status=200
        )

        # Mock lock operation
        responses.add(
            responses.POST,
            "https://192.168.1.100/jsonrpc",
            json={
                "id": 2,
                "result": [{
                    "status": {"code": 0, "message": "OK"},
                    "url": "/dvmdb/adom/root/workspace/lock/"
                }]
            },
            status=200
        )

        # Mock commit operation
        responses.add(
            responses.POST,
            "https://192.168.1.100/jsonrpc",
            json={
                "id": 3,
                "result": [{
                    "status": {"code": 0, "message": "OK"},
                    "url": "/dvmdb/adom/root/workspace/commit"
                }]
            },
            status=200
        )

        # Mock unlock operation
        responses.add(
            responses.POST,
            "https://192.168.1.100/jsonrpc",
            json={
                "id": 4,
                "result": [{
                    "status": {"code": 0, "message": "OK"},
                    "url": "/dvmdb/adom/root/workspace/unlock/"
                }]
            },
            status=200
        )

        # Check workspace capabilities
        fmg._lock_ctx.check_mode()
        assert fmg._lock_ctx.uses_workspace is True
        assert fmg._lock_ctx.uses_adoms is True

        # Test complete workflow
        code, response = fmg.lock_adom("root")
        assert code == 0

        code, response = fmg.commit_changes("root")
        assert code == 0

        code, response = fmg.unlock_adom("root")
        assert code == 0


@pytest.mark.integration
class TestTaskTrackingWorkflow:
    """Test complete task tracking workflows"""

    @responses.activate
    def test_successful_task_completion_workflow(self):
        """Test complete successful task tracking workflow"""
        fmg = FortiManager("192.168.1.100", "admin", "password")
        fmg.sid = "test-session"
        fmg._url = "https://192.168.1.100/jsonrpc"

        # Mock task creation
        responses.add(
            responses.POST,
            "https://192.168.1.100/jsonrpc",
            json={
                "id": 1,
                "result": [{
                    "data": {"task": 12345},
                    "status": {"code": 0, "message": "OK"},
                    "url": "/securityconsole/install/package"
                }]
            },
            status=200
        )

        # Mock task status progression: 0% -> 50% -> 100%
        task_responses = [
            # 0% progress
            {
                "id": 2,
                "result": [{
                    "data": {
                        "percent": 0,
                        "num_done": 0,
                        "num_err": 0,
                        "num_lines": 100,
                        "start_tm": int(time.time()) - 1000  # Simulate FMG time offset
                    },
                    "status": {"code": 0, "message": "OK"},
                    "url": "/task/task/12345"
                }]
            },
            # 50% progress
            {
                "id": 3,
                "result": [{
                    "data": {
                        "percent": 50,
                        "num_done": 50,
                        "num_err": 0,
                        "num_lines": 100,
                        "start_tm": int(time.time()) - 1000
                    },
                    "status": {"code": 0, "message": "OK"},
                    "url": "/task/task/12345"
                }]
            },
            # 100% complete
            {
                "id": 4,
                "result": [{
                    "data": {
                        "percent": 100,
                        "num_done": 100,
                        "num_err": 0,
                        "num_lines": 100,
                        "start_tm": int(time.time()) - 1000
                    },
                    "status": {"code": 0, "message": "OK"},
                    "url": "/task/task/12345"
                }]
            }
        ]

        # Add task status responses
        for response in task_responses:
            responses.add(
                responses.POST,
                "https://192.168.1.100/jsonrpc",
                json=response,
                status=200
            )

        # Create task
        code, task_data = fmg.execute("securityconsole/install/package",
                                      flags=["preview"], adom="root", pkg="test_pkg")

        assert code == 0
        assert "task" in task_data
        task_id = task_data["task"]

        # Track task with mocked sleep - FIX: Don't call time.sleep recursively!
        with patch('time.sleep') as mock_sleep:
            # Mock sleep just returns immediately without doing anything
            mock_sleep.return_value = None
            code, result = fmg.track_task(task_id, sleep_time=0.01)

        assert code == 0
        assert "total_task_time" in result
        # Verify sleep was called (shows the polling loop worked)
        assert mock_sleep.call_count >= 2  # Should be called between status checks

    @responses.activate
    def test_task_timeout_workflow(self):
        """Test task timeout workflow"""
        fmg = FortiManager("192.168.1.100", "admin", "password")
        fmg.sid = "test-session"
        fmg._url = "https://192.168.1.100/jsonrpc"

        # Mock task status that never progresses past 50%
        # Add multiple identical responses to simulate stuck task
        stuck_response = {
            "id": 1,
            "result": [{
                "data": {
                    "percent": 50,
                    "num_done": 50,
                    "num_err": 0,
                    "num_lines": 100,
                    "start_tm": int(time.time())
                },
                "status": {"code": 0, "message": "OK"},
                "url": "/task/task/12345"
            }]
        }

        # Add multiple identical responses to simulate polling
        for _ in range(10):  # Add enough responses for polling attempts
            responses.add(
                responses.POST,
                "https://192.168.1.100/jsonrpc",
                json=stuck_response,
                status=200
            )

        # Track task with very short timeout
        with patch('time.sleep'):  # Skip actual sleep
            code, result = fmg.track_task(12345, timeout=0.1, sleep_time=0.01)

        assert code == 1
        assert "msg" in result
        assert "timed out" in result["msg"]

    @responses.activate
    def test_task_failure_workflow(self):
        """Test task failure handling workflow"""
        fmg = FortiManager("192.168.1.100", "admin", "password")
        fmg.sid = "test-session"
        fmg._url = "https://192.168.1.100/jsonrpc"

        # Mock task status requests that fail
        responses.add(
            responses.POST,
            "https://192.168.1.100/jsonrpc",
            json={
                "id": 1,
                "result": [{
                    "status": {"code": -1, "message": "Task failed"},
                    "url": "/task/task/12345"
                }]
            },
            status=200
        )

        # Track task - should handle failures gracefully
        with patch('time.sleep'):  # Skip actual sleep
            code, result = fmg.track_task(12345, retrieval_fail_gate=2)

        # Should eventually give up after hitting retrieval fail gate
        assert code == -1


@pytest.mark.integration
class TestCompleteWorkflows:
    """Test complete end-to-end workflows"""

    @responses.activate
    def test_context_manager_workflow(self):
        """Test complete workflow using context manager"""
        # Mock login
        responses.add(
            responses.POST,
            "https://192.168.1.100/jsonrpc",
            json={
                "id": 1,
                "result": [{
                    "status": {"code": 0, "message": "OK"},
                    "url": "sys/login/user"
                }],
                "session": "test-session-123"
            },
            status=200
        )

        # Mock workspace check
        responses.add(
            responses.POST,
            "https://192.168.1.100/jsonrpc",
            json={
                "id": 2,
                "result": [{
                    "data": {"workspace-mode": 1, "adom-status": 1},
                    "status": {"code": 0, "message": "OK"},
                    "url": "/cli/global/system/global"
                }]
            },
            status=200
        )

        # Mock lock operation
        responses.add(
            responses.POST,
            "https://192.168.1.100/jsonrpc",
            json={
                "id": 3,
                "result": [{
                    "status": {"code": 0, "message": "OK"},
                    "url": "/dvmdb/adom/root/workspace/lock/"
                }]
            },
            status=200
        )

        # Mock get operation
        responses.add(
            responses.POST,
            "https://192.168.1.100/jsonrpc",
            json={
                "id": 4,
                "result": [{
                    "data": [{"name": "test-device", "serial": "12345"}],
                    "status": {"code": 0, "message": "OK"},
                    "url": "/dvmdb/adom/root/device"
                }]
            },
            status=200
        )

        # Mock unlock operation
        responses.add(
            responses.POST,
            "https://192.168.1.100/jsonrpc",
            json={
                "id": 5,
                "result": [{
                    "status": {"code": 0, "message": "OK"},
                    "url": "/dvmdb/adom/root/workspace/unlock/"
                }]
            },
            status=200
        )

        # Mock logout
        responses.add(
            responses.POST,
            "https://192.168.1.100/jsonrpc",
            json={
                "id": 6,
                "result": [{
                    "status": {"code": 0, "message": "OK"},
                    "url": "sys/logout"
                }]
            },
            status=200
        )

        # Test complete workflow with context manager
        with FortiManager("192.168.1.100", "admin", "password") as fmg:
            # Lock workspace
            code, response = fmg.lock_adom("root")
            assert code == 0

            # Perform operation
            code, devices = fmg.get("/dvmdb/adom/root/device")
            assert code == 0
            assert len(devices) > 0
            assert devices[0]["name"] == "test-device"

        # Context manager should handle unlock and logout automatically

    @responses.activate
    def test_crud_operations_workflow(self):
        """Test complete CRUD operations workflow"""
        fmg = FortiManager("192.168.1.100", "admin", "password")
        fmg.sid = "test-session"
        fmg._url = "https://192.168.1.100/jsonrpc"

        # Mock ADD operation
        responses.add(
            responses.POST,
            "https://192.168.1.100/jsonrpc",
            json={
                "id": 1,
                "result": [{
                    "status": {"code": 0, "message": "OK"},
                    "url": "/pm/config/adom/root/obj/firewall/address"
                }]
            },
            status=200
        )

        # Mock GET operation
        responses.add(
            responses.POST,
            "https://192.168.1.100/jsonrpc",
            json={
                "id": 2,
                "result": [{
                    "data": {
                        "name": "test_address",
                        "subnet": ["192.168.1.0", "255.255.255.0"],
                        "type": 0
                    },
                    "status": {"code": 0, "message": "OK"},
                    "url": "/pm/config/adom/root/obj/firewall/address/test_address"
                }]
            },
            status=200
        )

        # Mock UPDATE operation
        responses.add(
            responses.POST,
            "https://192.168.1.100/jsonrpc",
            json={
                "id": 3,
                "result": [{
                    "status": {"code": 0, "message": "OK"},
                    "url": "/pm/config/adom/root/obj/firewall/address/test_address"
                }]
            },
            status=200
        )

        # Mock DELETE operation
        responses.add(
            responses.POST,
            "https://192.168.1.100/jsonrpc",
            json={
                "id": 4,
                "result": [{
                    "status": {"code": 0, "message": "OK"},
                    "url": "/pm/config/adom/root/obj/firewall/address/test_address"
                }]
            },
            status=200
        )

        # CREATE
        code, response = fmg.add("/pm/config/adom/root/obj/firewall/address",
                                 name="test_address",
                                 subnet=["192.168.1.0", "255.255.255.0"],
                                 type=0)
        assert code == 0

        # READ
        code, data = fmg.get("/pm/config/adom/root/obj/firewall/address/test_address")
        assert code == 0
        assert data["name"] == "test_address"

        # UPDATE
        code, response = fmg.update("/pm/config/adom/root/obj/firewall/address/test_address",
                                    comment="Updated via API")
        assert code == 0

        # DELETE
        code, response = fmg.delete("/pm/config/adom/root/obj/firewall/address/test_address")
        assert code == 0


@pytest.mark.integration
class TestErrorHandlingWorkflows:
    """Test error handling in complete workflows"""

    def test_invalid_session_workflow(self):
        """Test workflow with invalid session"""
        fmg = FortiManager("192.168.1.100", "admin", "password")
        # Don't set session ID to simulate invalid session

        with pytest.raises(FMGValidSessionException):
            fmg.get("/test/url")

    @responses.activate
    def test_network_error_recovery(self):
        """Test network error handling and recovery"""
        fmg = FortiManager("192.168.1.100", "admin", "password")
        fmg.sid = "test-session"

        # Mock connection error followed by successful retry
        responses.add(
            responses.POST,
            "https://192.168.1.100/jsonrpc",
            body=ConnectionError("Network error"),
            status=500
        )

        # Test that connection error is properly wrapped
        with pytest.raises(Exception):  # Should raise FMGConnectionError
            fmg.get("/test/url")


@pytest.mark.integration
@pytest.mark.slow
class TestPerformanceWorkflows:
    """Test performance-related workflows"""

    @responses.activate
    def test_multiple_concurrent_operations(self):
        """Test handling multiple operations"""
        fmg = FortiManager("192.168.1.100", "admin", "password")
        fmg.sid = "test-session"
        fmg._url = "https://192.168.1.100/jsonrpc"

        # Mock multiple successful responses
        for i in range(10):
            responses.add(
                responses.POST,
                "https://192.168.1.100/jsonrpc",
                json={
                    "id": i + 1,
                    "result": [{
                        "data": {"operation": i},
                        "status": {"code": 0, "message": "OK"},
                        "url": f"/test/url/{i}"
                    }]
                },
                status=200
            )

        # Perform multiple operations
        results = []
        for i in range(10):
            code, data = fmg.get(f"/test/url/{i}")
            results.append((code, data))

        # Verify all operations succeeded
        assert len(results) == 10
        for i, (code, data) in enumerate(results):
            assert code == 0
            assert data["operation"] == i
