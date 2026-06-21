"""
Tests for pyFMG custom exceptions
"""
import json
from unittest.mock import Mock, patch

import pytest
from requests.exceptions import ConnectionError as ReqConnError, ConnectTimeout as ReqConnTimeout

from pyFMG.fortimgr import (FortiManager,
                            FMGBaseException, FMGValidSessionException, FMGValueError,
                            FMGResponseNotFormedCorrect, FMGConnectionError, FMGConnectTimeout,
                            FMGRequestNotFormedCorrect, FMGOAuthTokenError
                            )


class TestFMGBaseException:
    """Test FMGBaseException"""

    def test_init_default_message(self):
        """Test initialization with default message"""
        exc = FMGBaseException()
        assert "An exception occurred within pyfmg" in str(exc)

    def test_init_custom_message(self):
        """Test initialization with custom message"""
        msg = "Custom error message"
        exc = FMGBaseException(msg)
        assert str(exc) == msg

    def test_inheritance(self):
        """Test that FMGBaseException inherits from Exception"""
        exc = FMGBaseException()
        assert isinstance(exc, Exception)


class TestFMGValidSessionException:
    """Test FMGValidSessionException"""

    def test_init_with_method_and_params(self):
        """Test initialization with method and params"""
        method = "get"
        params = [{"url": "/test/url"}]

        exc = FMGValidSessionException(method, params)
        exc_str = str(exc)

        assert method in exc_str
        assert "/test/url" in exc_str
        assert "no valid session" in exc_str

    def test_inheritance(self):
        """Test inheritance from FMGBaseException"""
        exc = FMGValidSessionException("get", [{"url": "/test"}])
        assert isinstance(exc, FMGBaseException)
        assert isinstance(exc, Exception)


class TestFMGValueError:
    """Test FMGValueError"""

    def test_init(self):
        """Test initialization"""
        msg = "Invalid value provided"
        exc = FMGValueError(msg)
        assert str(exc) == msg

    def test_inheritance(self):
        """Test inheritance from ValueError"""
        exc = FMGValueError("test")
        assert isinstance(exc, ValueError)


class TestFMGResponseNotFormedCorrect:
    """Test FMGResponseNotFormedCorrect"""

    def test_init(self):
        """Test initialization"""
        msg = "Response not formed correctly"
        exc = FMGResponseNotFormedCorrect(msg)
        assert str(exc) == f"'{msg}'"

    def test_inheritance(self):
        """Test inheritance from KeyError"""
        exc = FMGResponseNotFormedCorrect("test")
        assert isinstance(exc, KeyError)


class TestFMGConnectionError:
    """Test FMGConnectionError"""

    def test_init(self):
        """Test initialization"""
        msg = "Connection failed"
        exc = FMGConnectionError(msg)
        assert str(exc) == msg

    def test_inheritance(self):
        """Test inheritance from requests ConnectionError"""
        exc = FMGConnectionError("test")
        assert isinstance(exc, ReqConnError)


class TestFMGConnectTimeout:
    """Test FMGConnectTimeout"""

    def test_init(self):
        """Test initialization"""
        msg = "Connection timeout"
        exc = FMGConnectTimeout(msg)
        assert str(exc) == msg

    def test_inheritance(self):
        """Test inheritance from requests ConnectTimeout"""
        exc = FMGConnectTimeout("test")
        assert isinstance(exc, ReqConnTimeout)


class TestFMGRequestNotFormedCorrect:
    """Test FMGRequestNotFormedCorrect"""

    def test_init_default_message(self):
        """Test initialization with default message"""
        exc = FMGRequestNotFormedCorrect()
        assert "An exception occurred within pyfmg" in str(exc)

    def test_init_custom_message(self):
        """Test initialization with custom message"""
        msg = "Request not formed correctly"
        exc = FMGRequestNotFormedCorrect(msg)
        assert str(exc) == msg

    def test_inheritance(self):
        """Test inheritance from FMGBaseException"""
        exc = FMGRequestNotFormedCorrect()
        assert isinstance(exc, FMGBaseException)


class TestFMGOAuthTokenError:
    """Test FMGOAuthTokenError"""

    def test_init_default_message(self):
        """Test initialization with default message"""
        exc = FMGOAuthTokenError()
        assert "An exception occurred within pyfmg" in str(exc)

    def test_init_custom_message(self):
        """Test initialization with custom message"""
        msg = "OAuth token error"
        exc = FMGOAuthTokenError(msg)
        assert str(exc) == msg

    def test_inheritance(self):
        """Test inheritance from FMGBaseException"""
        exc = FMGOAuthTokenError()
        assert isinstance(exc, FMGBaseException)


class TestExceptionUsage:
    """Test exception usage in typical scenarios"""

    def test_catch_base_exception(self):
        """Test catching all pyFMG exceptions with FMGBaseException"""
        # Test that all custom exceptions can be caught with FMGBaseException
        exceptions_to_test = [
            FMGBaseException("test"),
            FMGValidSessionException("get", [{"url": "/test"}]),
            FMGRequestNotFormedCorrect("test"),
            FMGOAuthTokenError("test")
        ]

        for exc in exceptions_to_test:
            try:
                raise exc
            except FMGBaseException as caught:
                assert caught is exc
            except Exception:
                pytest.fail(f"Exception {type(exc)} not caught by FMGBaseException")

    def test_specific_exception_catching(self):
        """Test catching specific exceptions"""
        # ValueError types
        try:
            raise FMGValueError("test value error")
        except ValueError as e:
            assert isinstance(e, FMGValueError)

        # KeyError types
        try:
            raise FMGResponseNotFormedCorrect("test key error")
        except KeyError as e:
            assert isinstance(e, FMGResponseNotFormedCorrect)

        # Connection error types
        try:
            raise FMGConnectionError("test connection error")
        except ReqConnError as e:
            assert isinstance(e, FMGConnectionError)

        # Timeout error types
        try:
            raise FMGConnectTimeout("test timeout error")
        except ReqConnTimeout as e:
            assert isinstance(e, FMGConnectTimeout)


class TestWorkingExceptionHandling:
    """Exception tests that actually work"""

    def test_connection_error_handling(self):
        """Test ConnectionError is properly caught and re-raised as FMGConnectionError"""
        fmg = FortiManager("192.168.1.100", "admin", "password")
        fmg.sid = "test-session"

        # Create a fresh mock session
        mock_session = Mock()
        mock_session.post.side_effect = ReqConnError("Connection failed")
        fmg._session = mock_session

        with pytest.raises(FMGConnectionError) as exc_info:
            fmg._post_request("get", [{"url": "/test"}])

        assert "Connection error:" in str(exc_info.value)
        assert "Connection failed" in str(exc_info.value)


    def test_key_error_handling(self):
        """Test KeyError is properly caught and re-raised as FMGResponseNotFormedCorrect"""
        fmg = FortiManager("192.168.1.100", "admin", "password")
        fmg.sid = "test-session"

        # Create response missing required keys - this will cause KeyError in _handle_response
        mock_response = Mock()
        mock_response.json.return_value = {"missing_result_key": "value"}

        mock_session = Mock()
        mock_session.post.return_value = mock_response
        fmg._session = mock_session

        with pytest.raises(FMGResponseNotFormedCorrect) as exc_info:
            fmg._post_request("get", [{"url": "/test"}])

        assert "Key error in response:" in str(exc_info.value)

    def test_index_error_handling(self):
        """Test IndexError is properly caught and re-raised as FMGResponseNotFormedCorrect"""
        fmg = FortiManager("192.168.1.100", "admin", "password")
        fmg.sid = "test-session"

        # Create response with empty result array - causes IndexError when accessing [0]
        mock_response = Mock()
        mock_response.json.return_value = {"result": []}  # Empty array

        mock_session = Mock()
        mock_session.post.return_value = mock_response
        fmg._session = mock_session

        with pytest.raises(FMGResponseNotFormedCorrect) as exc_info:
            fmg._post_request("get", [{"url": "/test"}])

        assert "Index error in response:" in str(exc_info.value)



    def test_login_connection_error(self):
        """Test connection error during login"""
        fmg = FortiManager("192.168.1.100", "admin", "password")

        # Mock the session creation and post method
        with patch('requests.session') as mock_session_class:
            mock_session = Mock()
            mock_session.post.side_effect = ReqConnError("Network unreachable")
            mock_session_class.return_value = mock_session
            fmg._session = mock_session

            with pytest.raises(FMGConnectionError) as exc_info:
                fmg.login()

            assert "Connection error:" in str(exc_info.value)


    def test_error_message_formatting(self):
        """Test that error messages include all required information"""
        fmg = FortiManager("192.168.1.100", "admin", "password")
        fmg.sid = "test-session"

        test_error = ValueError("Test message")
        mock_response = Mock()
        mock_response.json.side_effect = test_error

        mock_session = Mock()
        mock_session.post.return_value = mock_response
        fmg._session = mock_session

        try:
            fmg._post_request("get", [{"url": "/test"}])
        except FMGValueError as e:
            error_str = str(e)
            # Check all components of the formatted error message
            assert "Value error:" in error_str
            assert "ValueError" in error_str  # type(err)
            assert "Test message" in error_str  # str(err)
            assert "\n\n" in error_str  # formatting

    def test_request_response_object_error_logging(self):
        """Test that errors are logged to request response object"""
        fmg = FortiManager("192.168.1.100", "admin", "password")
        fmg.sid = "test-session"

        mock_session = Mock()
        mock_session.post.side_effect = ReqConnError("Network error")
        fmg._session = mock_session

        try:
            fmg._post_request("get", [{"url": "/test"}])
        except FMGConnectionError:
            pass

        # Verify error was logged to request response object
        assert fmg.req_resp_object.error_msg is not None
        assert "Connection error:" in fmg.req_resp_object.error_msg

    def test_dprint_called_during_exception(self):
        """Test that dprint is called during exception handling"""
        fmg = FortiManager("192.168.1.100", "admin", "password")
        fmg.sid = "test-session"
        fmg.debug = True

        # Mock dprint to verify it's called
        original_dprint = fmg.dprint
        dprint_called = []

        def mock_dprint():
            dprint_called.append(True)
            return original_dprint()

        fmg.dprint = mock_dprint

        mock_session = Mock()
        mock_session.post.side_effect = ReqConnError("Test error")
        fmg._session = mock_session

        try:
            fmg._post_request("get", [{"url": "/test"}])
        except FMGConnectionError:
            pass

        # Verify dprint was called
        assert len(dprint_called) > 0


class TestRequestResponseErrorHandling:
    """Test error handling in request/response object"""

    def test_req_resp_object_error_logging(self, mock_fmg):
        """Test that request/response object properly handles error messages"""
        # Trigger an exception that sets error_msg
        mock_fmg._session.post.side_effect = ReqConnError("Network error")

        try:
            mock_fmg.get("/test/url")
        except FMGConnectionError:
            pass

        # Verify error message was set in request/response object
        assert mock_fmg.req_resp_object.error_msg is not None
        assert "Connection error:" in mock_fmg.req_resp_object.error_msg
        assert "Network error" in mock_fmg.req_resp_object.error_msg
