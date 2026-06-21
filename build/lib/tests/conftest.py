"""
Test configuration and fixtures for pyFMG tests
"""
import time
from unittest.mock import Mock

import pytest

from pyFMG.fortimgr import FortiManager


@pytest.fixture
def mock_fmg():
    """Create a mock FortiManager instance for testing"""
    fmg = FortiManager(host="192.168.1.100", user="admin", passwd="password")
    fmg._session = Mock()
    fmg.sid = "test-session-id"
    return fmg


@pytest.fixture
def mock_fmg_api_key():
    """Create a mock FortiManager instance with API key authentication"""
    fmg = FortiManager(host="192.168.1.100", apikey="test-api-key")
    fmg._session = Mock()
    fmg.sid = "test-session-id-1234"
    return fmg


@pytest.fixture
def mock_fmg_forticloud():
    """Create a mock FortiManager instance for FortiCloud"""
    fmg = FortiManager(host="12345.us-west-1.fortimanager.forticloud.com",
                       user="admin", passwd="password")
    fmg._session = Mock()
    fmg.sid = "test-session-id"
    return fmg


@pytest.fixture
def standard_response():
    """Standard successful FortiManager response"""
    return {
        "id": 1,
        "result": [
            {
                "data": {"test": "data"},
                "status": {"code": 0, "message": "OK"},
                "url": "/test/url"
            }
        ],
        "session": "test-session-id"
    }


@pytest.fixture
def error_response():
    """Standard error FortiManager response"""
    return {
        "id": 1,
        "result": [
            {
                "status": {"code": -1, "message": "Error occurred"},
                "url": "/test/url"
            }
        ],
        "session": "test-session-id"
    }


@pytest.fixture
def task_response():
    """FortiManager task creation response"""
    return {
        "id": 1,
        "result": [
            {
                "data": {"task": 12345},
                "status": {"code": 0, "message": "OK"},
                "url": "/test/url"
            }
        ],
        "session": "test-session-id"
    }


@pytest.fixture
def task_status_responses():
    """Series of task status responses for track_task testing"""
    return [
        # Initial task status - 0%
        {
            "id": 1,
            "result": [
                {
                    "data": {
                        "percent": 0,
                        "num_done": 0,
                        "num_err": 0,
                        "num_lines": 100,
                        "start_tm": int(time.time()) - 1000  # FMG time, should be ignored
                    },
                    "status": {"code": 0, "message": "OK"},
                    "url": "/task/task/12345"
                }
            ],
            "session": "test-session-id"
        },
        # Mid-progress - 50%
        {
            "id": 1,
            "result": [
                {
                    "data": {
                        "percent": 50,
                        "num_done": 50,
                        "num_err": 0,
                        "num_lines": 100,
                        "start_tm": int(time.time()) - 1000
                    },
                    "status": {"code": 0, "message": "OK"},
                    "url": "/task/task/12345"
                }
            ],
            "session": "test-session-id"
        },
        # Complete - 100%
        {
            "id": 1,
            "result": [
                {
                    "data": {
                        "percent": 100,
                        "num_done": 100,
                        "num_err": 0,
                        "num_lines": 100,
                        "start_tm": int(time.time()) - 1000
                    },
                    "status": {"code": 0, "message": "OK"},
                    "url": "/task/task/12345"
                }
            ],
            "session": "test-session-id"
        }
    ]


@pytest.fixture
def login_response():
    """FortiManager login response"""
    return {
        "id": 1,
        "result": [
            {
                "status": {"code": 0, "message": "OK"},
                "url": "sys/login/user"
            }
        ],
        "session": "new-session-id"
    }


@pytest.fixture
def workspace_status_response():
    """Workspace and ADOM status response"""
    return {
        "id": 1,
        "result": [
            {
                "data": {
                    "workspace-mode": 1,
                    "adom-status": 1
                },
                "status": {"code": 0, "message": "OK"},
                "url": "/cli/global/system/global"
            }
        ],
        "session": "test-session-id"
    }


@pytest.fixture
def mock_requests_response():
    """Mock requests.Response object"""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "id": 1,
        "result": [
            {
                "data": {"test": "data"},
                "status": {"code": 0, "message": "OK"},
                "url": "/test/url"
            }
        ],
        "session": "test-session-id"
    }
    return mock_response


class MockTaskTracker:
    """Helper class to simulate task progress over time"""

    def __init__(self, total_steps=3, fail_at_step=None):
        self.current_step = 0
        self.total_steps = total_steps
        self.fail_at_step = fail_at_step
        self.start_time = time.time()

    def get_next_response(self, task_id):
        """Return next task status response based on current step"""
        if self.fail_at_step and self.current_step >= self.fail_at_step:
            return {
                "id": self.current_step + 1,
                "result": [{
                    "status": {"code": -1, "message": "Task failed"},
                    "url": f"/task/task/{task_id}"
                }],
                "session": "test-session-id"
            }

        percent = min(int((self.current_step / self.total_steps) * 100), 100)
        self.current_step += 1

        return {
            "id": self.current_step,
            "result": [{
                "data": {
                    "percent": percent,
                    "num_done": self.current_step,
                    "num_err": 0,
                    "num_lines": self.total_steps,
                    "start_tm": int(self.start_time) - 1000  # Simulate FMG time offset
                },
                "status": {"code": 0, "message": "OK"},
                "url": f"/task/task/{task_id}"
            }],
            "session": "test-session-id"
        }


@pytest.fixture
def mock_task_tracker():
    """Fixture for MockTaskTracker"""
    return MockTaskTracker
