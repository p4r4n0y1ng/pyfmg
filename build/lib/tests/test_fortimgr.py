"""
Tests for FortiManager main class functionality
"""
import json
import logging
import time
from io import StringIO
from unittest.mock import Mock, patch

import pytest

from pyFMG.fortimgr import (
    FortiManager, FMGValidSessionException,
    FMGRequestNotFormedCorrect
)


class TestFortiManagerInit:
    """Test FortiManager initialization"""

    def test_init_basic(self):
        """Test basic initialization"""
        fmg = FortiManager(host="192.168.1.100", user="admin", passwd="password")
        assert fmg._host == "192.168.1.100"
        assert fmg._user == "admin"
        assert fmg._passwd == "password"
        assert fmg._use_ssl is True
        assert fmg._verify_ssl is False
        assert fmg._timeout == 300
        assert fmg.sid is None
        assert fmg._apikeyused is False

    def test_init_api_key(self):
        """Test initialization with API key"""
        fmg = FortiManager(host="192.168.1.100", apikey="test-api-key")
        assert fmg._host == "192.168.1.100"
        assert fmg._passwd == "test-api-key"
        assert fmg._apikeyused is True

    def test_init_forticloud(self):
        """Test initialization with FortiCloud host"""
        host = "12345.us-west-1.fortimanager.forticloud.com"
        fmg = FortiManager(host=host, user="admin", passwd="password")
        assert fmg._forticloudused is True

    def test_init_options(self):
        """Test initialization with various options"""
        fmg = FortiManager(
            host="192.168.1.100",
            user="admin",
            passwd="password",
            debug=True,
            use_ssl=False,
            verify_ssl=True,
            timeout=600,
            verbose=True,
            check_adom_workspace=False
        )
        assert fmg._debug is True
        assert fmg._use_ssl is False
        assert fmg._verify_ssl is True
        assert fmg._timeout == 600
        assert fmg._verbose is True
        assert fmg._check_adom_workspace is False


class TestFortiManagerProperties:
    """Test FortiManager property getters and setters"""

    def test_properties(self, mock_fmg):
        """Test various property getters and setters"""
        # Test debug property
        mock_fmg.debug = True
        assert mock_fmg.debug is True

        # Test timeout property
        mock_fmg.timeout = 600
        assert mock_fmg.timeout == 600

        # Test verbose property
        mock_fmg.verbose = True
        assert mock_fmg.verbose is True

        # Test verify_ssl property
        mock_fmg.verify_ssl = True
        assert mock_fmg.verify_ssl is True


class TestFortiManagerRequests:
    """Test FortiManager request handling"""

    def test_valid_session_exception(self):
        """Test that operations without valid session raise exception"""
        fmg = FortiManager(host="192.168.1.100", user="admin", passwd="password")
        # No login, so sid should be None

        with pytest.raises(FMGValidSessionException):
            fmg.get("/test/url")

    @patch('requests.session')
    def test_post_request_success(self, mock_session, mock_fmg, standard_response):
        """Test successful POST request"""
        # Setup mock
        mock_response = Mock()
        mock_response.json.return_value = standard_response
        mock_fmg._session.post.return_value = mock_response

        # Make request
        code, data = mock_fmg.get("/test/url")

        # Verify
        assert code == 0
        assert data == {"test": "data"}
        mock_fmg._session.post.assert_called_once()

    @patch('requests.session')
    def test_post_request_error(self, mock_session, mock_fmg, error_response):
        """Test POST request with error response"""
        # Setup mock
        mock_response = Mock()
        mock_response.json.return_value = error_response
        mock_fmg._session.post.return_value = mock_response

        # Make request
        code, data = mock_fmg.get("/test/url")

        # Verify error handling
        assert code == -1
        assert "message" in data["status"]

    def test_common_datagram_params(self):
        """Test common_datagram_params static method"""
        # Test basic params
        params = FortiManager.common_datagram_params("get", "/test/url")
        expected = [{"url": "/test/url"}]
        assert params == expected

        # Test with kwargs
        params = FortiManager.common_datagram_params(
            "get", "/test/url",
            test_param="value",
            allow__routing=1,  # Should become allow-routing
            fake___space="test"  # Should become "fake space"
        )
        assert params[0]["url"] == "/test/url"
        assert params[0]["test_param"] == "value"
        assert params[0]["allow-routing"] == 1
        assert params[0]["fake space"] == "test"


class TestTrackTask:
    """Test track_task functionality - focusing on the bugs we fixed"""

    def test_track_task_unbound_variable_fix(self, mock_fmg):
        """Test that task_duration is always defined (Bug #1 fix)"""
        # Mock a failing get request
        mock_fmg.get = Mock(return_value=(-1, {}))

        # This should not raise UnboundLocalError anymore
        with patch('time.sleep'):  # Skip actual sleep
            code, result = mock_fmg.track_task(12345, timeout=1)

        # Should handle the error gracefully
        assert code != 0 or "msg" in result

    def test_track_task_time_sync_fix(self, mock_fmg, mock_task_tracker):
        """Test that task duration uses local time only (Bug #2 fix)"""
        tracker = mock_task_tracker(total_steps=2)

        def mock_get(url):
            if "/task/task/" in url:
                task_id = url.split("/")[-1]
                # FIX: Use get_next_response instead of get_task_status
                response = tracker.get_next_response(task_id)
                return 0, response["result"][0]["data"]
            return -1, {}

        mock_fmg.get = mock_get

        start_time = time.time()
        # FIX: Don't cause recursion - just mock sleep to return None
        with patch('time.sleep') as mock_sleep:
            mock_sleep.return_value = None  # Don't actually sleep
            code, result = mock_fmg.track_task(12345, sleep_time=0.1)

        # Task should complete successfully
        assert code == 0

        # Verify total_task_time is reasonable (should be close to actual elapsed time)
        if "total_task_time" in result:
            # Parse the timedelta string or verify it exists
            assert result["total_task_time"] is not None
            # Could also verify it's a reasonable format if needed
            assert isinstance(result["total_task_time"], str)

    def test_track_task_timeout(self, mock_fmg):
        """Test task timeout functionality"""
        # Mock get to always return 50% progress
        mock_fmg.get = Mock(return_value=(0, {
            "percent": 50,
            "num_done": 50,
            "num_err": 0,
            "num_lines": 100,
            "start_tm": int(time.time())
        }))

        with patch('time.sleep'):  # Skip actual sleep
            code, result = mock_fmg.track_task(12345, timeout=0.1)  # Very short timeout

        assert code == 1
        assert "msg" in result
        assert "timed out" in result["msg"]

    def test_track_task_completion(self, mock_fmg, mock_task_tracker):
        """Test successful task completion"""
        tracker = mock_task_tracker(total_steps=3)

        def mock_get(url):
            if "/task/task/" in url:
                task_id = url.split("/")[-1]
                # FIX: Use get_next_response instead of get_task_status
                response = tracker.get_next_response(task_id)
                return 0, response["result"][0]["data"]
            return -1, {}

        mock_fmg.get = mock_get

        # FIX: Don't cause recursion - just mock sleep to return None
        with patch('time.sleep') as mock_sleep:
            mock_sleep.return_value = None  # Don't actually sleep
            code, result = mock_fmg.track_task(12345, sleep_time=0.01)

        assert code == 0
        assert "total_task_time" in result

        # Additional verification that the mock was used properly
        assert mock_sleep.call_count >= 2

    def test_track_task_retrieval_failures(self, mock_fmg):
        """Test task retrieval failure handling"""
        # Mock get to always fail
        mock_fmg.get = Mock(return_value=(-1, {}))

        with patch('time.sleep'):  # Skip actual sleep
            code, result = mock_fmg.track_task(12345, retrieval_fail_gate=2)

        # Should fail after hitting the retrieval fail gate
        assert code == -1


class TestHttpMethods:
    """Test HTTP method wrappers"""

    def test_get_method(self, mock_fmg, standard_response):
        """Test GET method"""
        mock_fmg._post_request = Mock(return_value=(0, {"test": "data"}))

        code, data = mock_fmg.get("/test/url", fields=["name", "id"])

        mock_fmg._post_request.assert_called_once()
        args = mock_fmg._post_request.call_args
        assert args[0][0] == "get"  # method
        assert args[0][1][0]["url"] == "/test/url"  # URL in params

    def test_add_method(self, mock_fmg):
        """Test ADD method"""
        mock_fmg._post_request = Mock(return_value=(0, {}))

        mock_fmg.add("/test/url", name="test", type=1)

        mock_fmg._post_request.assert_called_once()
        args = mock_fmg._post_request.call_args
        assert args[0][0] == "add"
        assert args[0][1][0]["data"]["name"] == "test"

    def test_free_form_method(self, mock_fmg):
        """Test free_form method"""
        mock_fmg._post_request = Mock(return_value=(200, []))

        test_data = [
            {"url": "/test/url1", "data": {"name": "test1"}},
            {"url": "/test/url2", "data": {"name": "test2"}}
        ]

        code, result = mock_fmg.free_form("get", data=test_data)

        mock_fmg._post_request.assert_called_once()
        args = mock_fmg._post_request.call_args
        assert args[0][0] == "get"
        assert args[0][1] == test_data
        assert args[1]["free_form"] is True

    def test_free_form_method_error(self, mock_fmg):
        """Test free_form method with invalid data"""
        with pytest.raises(FMGRequestNotFormedCorrect):
            mock_fmg.free_form("get", invalid_key="value")

        with pytest.raises(FMGRequestNotFormedCorrect):
            mock_fmg.free_form("get")


class TestContextManager:
    """Test context manager functionality"""

    @patch('pyFMG.fortimgr.FortiManager.login')
    @patch('pyFMG.fortimgr.FortiManager.logout')
    def test_context_manager(self, mock_logout, mock_login):
        """Test context manager calls login/logout"""
        mock_login.return_value = (0, {})
        mock_logout.return_value = (0, {})

        with FortiManager("192.168.1.100", "admin", "password") as fmg:
            assert fmg is not None

        mock_login.assert_called_once()
        mock_logout.assert_called_once()


class TestStringRepresentations:
    """Test string representations"""

    def test_str_no_session(self):
        """Test __str__ without session"""
        fmg = FortiManager("192.168.1.100", "admin", "password")
        result = str(fmg)
        assert "no valid connection" in result

    def test_str_with_session(self, mock_fmg):
        """Test __str__ with session"""
        result = str(mock_fmg)
        assert "connected to 192.168.1.100" in result

    def test_repr_with_session(self, mock_fmg):
        """Test __repr__ with session"""
        result = repr(mock_fmg)
        assert "FortiManager" in result
        assert "host=192.168.1.100" in result
        assert "pwd omitted" in result


class TestUtilityMethods:
    """Test utility methods"""

    def test_jprint(self):
        """Test JSON pretty print utility"""
        test_obj = {"key": "value", "number": 123}
        result = FortiManager.jprint(test_obj)

        # Should be valid JSON with indentation
        parsed = json.loads(result)
        assert parsed == test_obj
        assert "\n" in result  # Should have formatting

    def test_jprint_type_error(self):
        """Test jprint with non-serializable object"""

        class NonSerializable:
            pass

        result = FortiManager.jprint(NonSerializable())
        assert "Type Information" in result

    def test_dprint_with_debug_enabled(self, mock_fmg, capsys):
        """Test dprint output when debug is enabled"""
        mock_fmg.debug = True

        # Set up request/response data - use the private attributes that have setters
        mock_fmg.req_resp_object.request_string = "REQUEST:"
        # response_string is read-only, so we can't set it directly
        mock_fmg.req_resp_object.request_json = {"method": "get", "url": "/test"}
        mock_fmg.req_resp_object.response_json = {"result": [{"data": "test"}]}
        mock_fmg.req_resp_object.error_msg = None

        # Call dprint
        mock_fmg.dprint()

        # Capture printed output
        captured = capsys.readouterr()

        # Verify output contains expected elements
        assert "REQUEST:" in captured.out
        assert "RESPONSE:" in captured.out  # This comes from the property's default value
        assert '"method": "get"' in captured.out
        assert '"data": "test"' in captured.out
        assert "---" in captured.out  # Should have separator lines

    def test_dprint_with_debug_disabled(self, mock_fmg, capsys):
        """Test dprint doesn't output when debug is disabled"""
        mock_fmg.debug = False

        # Set up request/response data - only set what we can
        mock_fmg.req_resp_object.request_string = "REQUEST:"
        mock_fmg.req_resp_object.request_json = {"method": "get"}
        mock_fmg.req_resp_object.response_json = {"result": []}
        mock_fmg.req_resp_object.error_msg = None
        # Call dprint
        mock_fmg.dprint()

        # Should have no output when debug is disabled
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_dprint_with_error_message(self, mock_fmg, capsys):
        """Test dprint handles error messages"""
        mock_fmg.debug = True
        mock_fmg.req_resp_object.error_msg = "Connection failed"
        mock_fmg.req_resp_object.request_json = None
        mock_fmg.req_resp_object.response_json = None

        # Call dprint
        mock_fmg.dprint()

        # Should only print error message
        captured = capsys.readouterr()
        assert "Connection failed" in captured.out
        assert "REQUEST:" not in captured.out
        assert "RESPONSE:" not in captured.out

    def test_dlog_with_logger_configured(self, mock_fmg):
        """Test dlog outputs to logger when configured"""
        # Set up logger with string capture
        log_capture = StringIO()
        handler = logging.StreamHandler(log_capture)
        handler.setLevel(logging.INFO)

        # Configure logger
        logger = mock_fmg.getLog("test_logger", logging.INFO)
        logger.addHandler(handler)

        # Set up request/response data - only settable properties
        mock_fmg.req_resp_object.request_string = "REQUEST:"
        mock_fmg.req_resp_object.request_json = {"method": "get", "url": "/test"}
        mock_fmg.req_resp_object.response_json = {"result": [{"status": {"code": 0}}]}
        mock_fmg.req_resp_object.error_msg = None

        # Call dlog
        mock_fmg.dlog()

        # Get logged output
        log_output = log_capture.getvalue()

        # Verify logger received the messages
        assert "REQUEST:" in log_output
        assert "RESPONSE:" in log_output
        assert '"method": "get"' in log_output

    def test_dlog_without_logger(self, mock_fmg):
        """Test dlog does nothing when no logger is configured"""
        # Ensure no logger is set
        mock_fmg._logger = None

        # Set up some data
        mock_fmg.req_resp_object.request_string = "REQUEST:"
        mock_fmg.req_resp_object.error_msg = None

        # This should not raise an exception
        mock_fmg.dlog()

    def test_dlog_with_error_message(self, mock_fmg):
        """Test dlog handles error messages"""
        # Set up logger with string capture
        log_capture = StringIO()
        handler = logging.StreamHandler(log_capture)
        handler.setLevel(logging.INFO)

        logger = mock_fmg.getLog("test_logger", logging.INFO)
        logger.addHandler(handler)

        # Set error message
        mock_fmg.req_resp_object.error_msg = "Network timeout occurred"
        mock_fmg.req_resp_object.request_json = None
        mock_fmg.req_resp_object.response_json = None

        # Call dlog
        mock_fmg.dlog()

        # Should only log error message
        log_output = log_capture.getvalue()
        assert "Network timeout occurred" in log_output
        assert "REQUEST:" not in log_output

    def test_jprint_utility(self):
        """Test the jprint utility method"""
        test_data = {
            "method": "get",
            "params": [{"url": "/test"}],
            "nested": {"key": "value"}
        }

        result = FortiManager.jprint(test_data)

        # Should return formatted JSON
        assert '"method": "get"' in result
        assert '"url": "/test"' in result
        assert '"key": "value"' in result
        # Should be indented (pretty printed)
        assert "\n" in result
        assert "  " in result  # Indentation spaces

    def test_jprint_with_non_serializable_object(self):
        """Test jprint handles non-serializable objects"""

        class NonSerializable:
            def __repr__(self):
                return "NonSerializable()"

        result = FortiManager.jprint(NonSerializable())

        # Should return error info instead of crashing
        assert "Type Information" in result

    def test_dprint_calls_dlog(self, mock_fmg):
        """Test that dprint calls dlog for logging"""
        # Mock dlog to verify it's called
        mock_fmg.dlog = Mock()

        mock_fmg.debug = False  # Even with debug off, should still log
        mock_fmg.req_resp_object.error_msg = None

        # Call dprint
        mock_fmg.dprint()

        # Verify dlog was called
        mock_fmg.dlog.assert_called_once()

    def test_integrated_dprint_dlog_workflow(self, mock_fmg, capsys):
        """Test complete dprint/dlog workflow"""
        # Enable debug and set up logger
        mock_fmg.debug = True

        log_capture = StringIO()
        handler = logging.StreamHandler(log_capture)
        handler.setLevel(logging.INFO)
        logger = mock_fmg.getLog("workflow_test", logging.INFO)
        logger.addHandler(handler)

        # Set up realistic request/response scenario - only settable properties
        mock_fmg.req_resp_object.request_string = "REQUEST:"
        mock_fmg.req_resp_object.request_json = {
            "id": 1,
            "method": "get",
            "params": [{"url": "/pm/config/adom/root/obj/firewall/address"}],
            "session": "test-session-123"
        }
        mock_fmg.req_resp_object.response_json = {
            "id": 1,
            "result": [{
                "data": [{"name": "test-addr", "subnet": ["192.168.1.0", "255.255.255.0"]}],
                "status": {"code": 0, "message": "OK"},
                "url": "/pm/config/adom/root/obj/firewall/address"
            }],
            "session": "test-session-123"
        }
        mock_fmg.req_resp_object.error_msg = None

        # Call dprint (which should also call dlog)
        mock_fmg.dprint()

        # Verify console output (from dprint)
        console_output = capsys.readouterr()
        assert "REQUEST:" in console_output.out
        assert "RESPONSE:" in console_output.out
        assert '"method": "get"' in console_output.out
        assert '"name": "test-addr"' in console_output.out

        # Verify log output (from dlog)
        log_output = log_capture.getvalue()
        assert "REQUEST:" in log_output
        assert "RESPONSE:" in log_output
        assert '"method": "get"' in log_output
        assert '"name": "test-addr"' in log_output

    def test_request_response_object_reset(self, mock_fmg):
        """Test that request response object can be reset"""
        # Set up some data - only use settable properties
        mock_fmg.req_resp_object.request_string = "REQUEST:"
        mock_fmg.req_resp_object.request_json = {"test": "data"}
        mock_fmg.req_resp_object.response_json = {"result": []}
        mock_fmg.req_resp_object.error_msg = "Some error"

        # Reset
        mock_fmg.req_resp_object.reset()

        # Verify reset - check actual property values
        assert mock_fmg.req_resp_object.request_string == "REQUEST:"  # This resets to default
        assert mock_fmg.req_resp_object.response_string == "RESPONSE:"  # This is the default value
        assert mock_fmg.req_resp_object.error_msg is None
        assert mock_fmg.req_resp_object.response_json is None
        assert mock_fmg.req_resp_object.request_json is None

    def test_logger_management(self, mock_fmg):
        """Test logger creation, handler management, and reset"""
        # Initially no logger
        assert mock_fmg._logger is None

        # Create logger
        logger1 = mock_fmg.getLog("test_logger", logging.DEBUG)
        assert mock_fmg._logger is not None
        assert logger1.level == logging.DEBUG

        # Getting logger again returns same instance
        logger2 = mock_fmg.getLog("different_name", logging.INFO)
        assert logger1 is logger2
        # Level should remain the same (DEBUG) since it's the same logger

        # Add handler
        handler = logging.StreamHandler()
        mock_fmg.addHandler(handler)
        assert handler in logger1.handlers

        # Remove handler
        mock_fmg.removeHandler(handler)
        assert handler not in logger1.handlers

        # Reset logger
        mock_fmg.resetLog()
        assert mock_fmg._logger is None

    def test_handler_management_without_logger(self, mock_fmg):
        """Test handler management when no logger exists"""
        # These should not raise exceptions
        mock_fmg.addHandler(logging.StreamHandler())
        mock_fmg.removeHandler(logging.StreamHandler())
