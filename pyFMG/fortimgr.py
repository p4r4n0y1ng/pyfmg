#!/usr/bin/env python

from datetime import datetime
import time
import logging
import json
import requests
from requests.exceptions import ConnectionError as ReqConnError, ConnectTimeout as ReqConnTimeout


class FMGBaseException(Exception):
    """Wrapper to catch the unexpected"""

    def __init__(self, msg=None, *args, **kwargs):
        if msg is None:
            msg = "An exception occurred within pyfmg"
        super(FMGBaseException, self).__init__(msg, *args)


class FMGValidSessionException(FMGBaseException):
    """Raised when a call is made, but there is no valid login instance"""

    def __init__(self, method, params, *args, **kwargs):
        msg = "A call using the {method} method was requested to {url} on a FortiManager instance that had no " \
              "valid session or was not connected. Paramaters were:\n{params}". \
            format(method=method, url=params[0]["url"], params=params)
        super(FMGValidSessionException, self).__init__(msg, *args, **kwargs)


class FMGValueError(ValueError):
    """Catch value errors such as bad timeout values"""

    def __init__(self, *args):
        super(FMGValueError, self).__init__(*args)


class FMGResponseNotFormedCorrect(KeyError):
    """Used only if a response does not have a standard format as based on FMG response guidelines"""

    def __init__(self, *args):
        super(FMGResponseNotFormedCorrect, self).__init__(*args)


class FMGConnectionError(ReqConnError):
    """Wrap requests Connection error so requests is not a dependency outside this module"""

    def __init__(self, *args, **kwargs):
        super(FMGConnectionError, self).__init__(*args, **kwargs)


class FMGConnectTimeout(ReqConnTimeout):
    """Wrap requests Connection timeout error so requests is not a dependency outside this module"""

    def __init__(self, *args, **kwargs):
        super(FMGConnectTimeout, self).__init__(*args, **kwargs)


class FMGRequestNotFormedCorrect(FMGBaseException):
    """Used only if a request does not have a standard format as based on FMG request guidelines"""

    def __init__(self, msg=None, *args, **kwargs):
        super(FMGRequestNotFormedCorrect, self).__init__(msg=msg, *args, **kwargs)


class FMGLockContext(object):

    def __init__(self, fmg):
        self._fmg = fmg
        self._locked_adom_list = list()
        self._uses_workspace = False
        self._uses_adoms = False

    @property
    def uses_workspace(self):
        return self._uses_workspace

    @uses_workspace.setter
    def uses_workspace(self, val):
        self._uses_workspace = val

    @property
    def uses_adoms(self):
        return self._uses_adoms

    @uses_adoms.setter
    def uses_adoms(self, val):
        self._uses_adoms = val

    def add_adom_to_lock_list(self, adom):
        if adom not in self._locked_adom_list:
            self._locked_adom_list.append(adom)

    def remove_adom_from_lock_list(self, adom):
        if adom in self._locked_adom_list:
            self._locked_adom_list.remove(adom)

    def check_mode(self):
        url = "/cli/global/system/global"
        code, resp_obj = self._fmg.get(url, fields=["workspace-mode", "adom-status"])
        try:
            if resp_obj["workspace-mode"] != 0:
                self.uses_workspace = True
        except KeyError:
            self.uses_workspace = False
        try:
            if resp_obj["adom-status"] == 1:
                self.uses_adoms = True
        except KeyError:
            self.uses_adoms = False

    def run_unlock(self):
        for adom_locked in self._locked_adom_list:
            self.unlock_adom(adom_locked)

    def lock_adom(self, adom=None, *args, **kwargs):
        if adom:
            if adom.lower() == "global":
                url = "/dvmdb/global/workspace/lock/"
            else:
                url = "/dvmdb/adom/{adom}/workspace/lock/".format(adom=adom)
        else:
            url = "/dvmdb/adom/root/workspace/lock"
        code, respobj = self._fmg.execute(url, {}, *args, **kwargs)
        if code == 0 and respobj["status"]["message"].lower() == "ok":
            self.add_adom_to_lock_list(adom)
        return code, respobj

    def unlock_adom(self, adom=None, *args, **kwargs):
        if adom:
            if adom.lower() == "global":
                url = "/dvmdb/global/workspace/unlock/"
            else:
                url = "/dvmdb/adom/{adom}/workspace/unlock/".format(adom=adom)
        else:
            url = "/dvmdb/adom/root/workspace/unlock"
        code, respobj = self._fmg.execute(url, {}, *args, **kwargs)
        if code == 0 and respobj["status"]["message"].lower() == "ok":
            self.remove_adom_from_lock_list(adom)
        return code, respobj

    def commit_changes(self, adom=None, aux=False, *args, **kwargs):
        if adom:
            if aux:
                url = "/pm/config/adom/{adom}/workspace/commit".format(adom=adom)
            else:
                if adom.lower() == "global":
                    url = "/dvmdb/global/workspace/commit/"
                else:
                    url = "/dvmdb/adom/{adom}/workspace/commit".format(adom=adom)
        else:
            url = "/dvmdb/adom/root/workspace/commit"
        return self._fmg.execute(url, {}, *args, **kwargs)


class RequestResponse(object):
    """Simple wrapper around the request response object so debugging and logging can be done with simplicity"""

    def __init__(self):
        self._request_string = "REQUEST:"
        self._response_string = "RESPONSE:"
        self._request_json = None
        self._response_json = None
        self._error_msg = None

    def reset(self):
        self._request_string = "REQUEST:"
        self.error_msg = None
        self.response_json = None
        self.request_json = None

    @property
    def request_string(self):
        return self._request_string

    @request_string.setter
    def request_string(self, val):
        self._request_string = val

    @property
    def response_string(self):
        return self._response_string

    @property
    def request_json(self):
        return self._request_json

    @request_json.setter
    def request_json(self, val):
        self._request_json = val

    @property
    def response_json(self):
        return self._response_json

    @response_json.setter
    def response_json(self, val):
        self._response_json = val

    @property
    def error_msg(self):
        return self._error_msg

    @error_msg.setter
    def error_msg(self, val):
        self._error_msg = val


class FortiManager(object):

    def __init__(self, host=None, user="", passwd="", debug=False, use_ssl=True, verify_ssl=False, timeout=300,
                 verbose=False, track_task_disable_connerr=False, disable_request_warnings=False):
        super(FortiManager, self).__init__()
        self._debug = debug
        self._host = host
        self._user = user
        self._passwd = passwd
        self._use_ssl = use_ssl
        self._verify_ssl = verify_ssl
        self._timeout = timeout
        self._verbose = verbose
        self._req_id = 0
        self._sid = None
        self._url = None
        self._lock_ctx = FMGLockContext(self)
        self._session = requests.session()
        self._req_resp_object = RequestResponse()
        self._logger = None
        self._track_task_disable_connerr = track_task_disable_connerr
        if disable_request_warnings:
            requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

    @property
    def debug(self):
        return self._debug

    @debug.setter
    def debug(self, val):
        self._debug = val

    @property
    def req_id(self):
        return self._req_id

    @req_id.setter
    def req_id(self, val):
        self._req_id = val

    def _update_request_id(self, reqid=0):
        self.req_id = reqid if reqid != 0 else self.req_id + 1

    @property
    def sid(self):
        return self._sid

    @sid.setter
    def sid(self, val):
        self._sid = val

    @property
    def verify_ssl(self):
        return self._verify_ssl

    @verify_ssl.setter
    def verify_ssl(self, val):
        self._verify_ssl = val

    @property
    def timeout(self):
        return self._timeout

    @timeout.setter
    def timeout(self, val):
        self._timeout = val

    @property
    def verbose(self):
        return self._verbose

    @verbose.setter
    def verbose(self, val):
        self._verbose = val

    @property
    def sess(self):
        return self._session
    
    @property
    def track_task_disable_connerr(self, val):
        self._track_task_disable_connerr = val

    @property
    def req_resp_object(self):
        return self._req_resp_object

    def getLog(self, loggername="fortinet", lvl=logging.INFO):
        if self._logger is not None:
            return self._logger
        else:
            self._logger = logging.getLogger(loggername)
            self._logger.setLevel(lvl)
            return self._logger

    def resetLog(self):
        self._logger = None

    def addHandler(self, handler):
        if self._logger is not None:
            self._logger.addHandler(handler)

    def removeHandler(self, handler):
        if self._logger is not None:
            self._logger.removeHandler(handler)

    @staticmethod
    def jprint(json_obj):
        try:
            return json.dumps(json_obj, indent=2, sort_keys=True)
        except TypeError as te:
            return json.dumps({"Type Information": te.message})

    def dlog(self):
        if self._logger is not None:
            if self.req_resp_object.error_msg is not None:
                self._logger.log(logging.INFO, self.req_resp_object.error_msg)
                return
            self._logger.log(logging.INFO, self.req_resp_object.request_string)
            if self.req_resp_object.request_json is not None:
                self._logger.log(logging.INFO, self.jprint(self.req_resp_object.request_json))
            self._logger.log(logging.INFO, self.req_resp_object.response_string)
            if self.req_resp_object.response_json is not None:
                self._logger.log(logging.INFO, self.jprint(self.req_resp_object.response_json))

    def dprint(self):
        self.dlog()
        if not self.debug:
            return
        if self.req_resp_object.error_msg is not None:
            print(self.req_resp_object.error_msg)
            return
        print("-" * 100 + "\n")
        print(self.req_resp_object.request_string)
        if self.req_resp_object.request_json is not None:
            print(self.jprint(self.req_resp_object.request_json))
        print("\n" + self.req_resp_object.response_string)
        if self.req_resp_object.response_json is not None:
            print(self.jprint(self.req_resp_object.response_json))
        print("\n" + "-" * 100 + "\n")

    def _set_sid(self, response):
        if self.sid is None and "session" in response:
            self.sid = response["session"]

    def lock_adom(self, adom=None, *args, **kwargs):
        return self._lock_ctx.lock_adom(adom, *args, **kwargs)

    def unlock_adom(self, adom=None, *args, **kwargs):
        return self._lock_ctx.unlock_adom(adom, *args, **kwargs)

    def commit_changes(self, adom=None, aux=False, *args, **kwargs):
        return self._lock_ctx.commit_changes(adom, aux, *args, **kwargs)

    def _handle_response(self, resp):
        try:
            response = resp.json()
        except:
            # response is not able to be decoded into json return 100 as a code and the entire response object
            return 100, resp

        self._set_sid(response)
        self.req_resp_object.response_json = response
        self.dprint()
        if type(response["result"]) is list:
            result = response["result"][0]
        else:
            result = response["result"]
        if "data" in result:
            return result["status"]["code"], result["data"]
        else:
            return result["status"]["code"], result

    def _freeform_response(self, resp):
        try:
            response = resp.json()
        except:
            # response is not able to be decoded into json return 100 as a code and the entire response object
            return 100, resp

        self._set_sid(response)
        self.req_resp_object.response_json = response
        self.dprint()

        # Result is always a list and with free form will include an entry for each URL requested
        # in the POST request. Setting result to the full result portion of the reponse
        result = response["result"]

        # Return the full result data set along with 200 as the response code
        return 200, result

    def _post_request(self, method, params, login=False, free_form=False, create_task=None):
        self.req_resp_object.reset()

        if self.sid is None and not login:
            raise FMGValidSessionException(method, params)
        self._update_request_id()
        headers = {"content-type": "application/json"}
        json_request = {}
        if create_task:
            json_request["create task"] = create_task
            json_request["method"] = method
            json_request["params"] = params
            json_request["session"] = self.sid
            json_request["id"] = self.req_id
        else:
            json_request["method"] = method
            json_request["params"] = params
            if method is "get" and self._verbose is True:
                json_request["verbose"] = 1
            json_request["session"] = self.sid
            json_request["id"] = self.req_id
        self.req_resp_object.request_json = json_request
        try:
            response = self.sess.post(self._url, data=json.dumps(json_request), headers=headers, verify=self.verify_ssl,
                                      timeout=self.timeout)
            if free_form:
                # If free_from is set then process using custom response handler
                return self._freeform_response(response)
            else:
                return self._handle_response(response)
        except ReqConnError as err:
            msg = "Connection error: {err_type} {err}\n\n".format(err_type=type(err), err=err)
            self.req_resp_object.error_msg = msg
            self.dprint()
            raise FMGConnectionError(msg)
        except ValueError as err:
            msg = "Value error: {err_type} {err}\n\n".format(err_type=type(err), err=err)
            self.req_resp_object.error_msg = msg
            self.dprint()
            raise FMGValueError(msg)
        except KeyError as err:
            msg = "Key error in response: {err_type} {err}\n\n".format(err_type=type(err), err=err)
            self.req_resp_object.error_msg = msg
            self.dprint()
            raise FMGResponseNotFormedCorrect(msg)
        except IndexError as err:
            msg = "Index error in response: {err_type} {err}\n\n".format(err_type=type(err), err=err)
            self.req_resp_object.error_msg = msg
            self.dprint()
            raise FMGResponseNotFormedCorrect(msg)
        except Exception as err:
            msg = "Response parser error: {err_type} {err}".format(err_type=type(err), err=err)
            self.req_resp_object.error_msg = msg
            self.dprint()
            raise FMGBaseException(msg)

    def track_task(self, task_id, sleep_time=3, retrieval_fail_gate=10, timeout=120):
        self.req_resp_object.reset()
        begin_task_time = datetime.now()
        start = time.time()
        self.req_resp_object.error_msg = "Task begins at {time}".format(time=str(begin_task_time))
        self.dprint()
        percent = 0
        code_fail = 0
        code = 1
        task_info = ""
        while percent != 100:
            try:
                code, task_info = self.get("/task/task/{taskid}".format(taskid=task_id))
            except FMGConnectionError as err:
                # If the option is enabled in the config to disable connection
                # errors on the track_task function, then catch the FMGConnectionError
                # and try again as the bug does not close the socket
                if self._track_task_disable_connerr:
                    # Set code value to -99 to ensure any future logic is skipped in this failure loop
                    code == -99
                    self.req_resp_object.error_msg = "RemoteDisconnect Issue (FMG BugID: 0703585) occured at " \
                        "{timestamp}".format(timestamp=datetime.now())
                    self.dprint()
                    code_fail += 1
                else:
                    # If the option is not enabled just re-raise the exception
                    raise
            if code == 0:
                percent = int(task_info["percent"])
                num_done = int(task_info["num_done"])
                num_err = int(task_info["num_err"])
                num_lines = int(task_info["num_lines"])
                self.req_resp_object.task_msg = "At timestamp {timestamp}:\nTask {taskid} is at {percent}% " \
                                                "completion.\n{num_err} tasks have returned an error.".\
                    format(timestamp=datetime.now(), taskid=str(task_id), percent=str(percent),
                           num_done=str(num_done), num_lines=str(num_lines), num_err=str(num_err))
                self.dprint()
            else:
                code_fail += 1
            if code_fail == retrieval_fail_gate:
                self.req_resp_object.error_msg = "Task info retrieval failed over {fail_gate} times. Something has " \
                                                 "caused issues with task {taskid}.".\
                    format(taskid=task_id, fail_gate=retrieval_fail_gate)
                self.dprint()
                return code, task_info
            if percent != 100:
                if time.time() - start >= timeout:
                    msg = "Task did not complete in efficient time. The timeout value was {}".format(timeout)
                    self.req_resp_object.error_msg = msg
                    self.dprint()
                    return 1, {"msg": msg}
                else:
                    time.sleep(sleep_time)
        self.req_resp_object.reset()
        end_task_time = datetime.now()
        task_info["total_task_time"] = str(end_task_time - begin_task_time)
        self.req_resp_object.error_msg = "Task completion is at {time}".format(time=str(end_task_time))
        self.dprint()
        self.req_resp_object.error_msg = "Total time to complete is {time}".\
            format(time=str(end_task_time - begin_task_time))
        self.dprint()
        return code, task_info

    def login(self):
        self._url = "{proto}://{host}/jsonrpc".format(proto="https" if self._use_ssl else "http", host=self._host)
        self.execute("sys/login/user", login=True, passwd=self._passwd, user=self._user, )
        self._lock_ctx.check_mode()
        if self.__str__() == "FortiManager instance connnected to {host}.".format(host=self._host):
            return 0, {"status": {"message": "OK", "code": 0}, "url": "sys/login/user"}
        else:
            return -1, {"status": {"message": self, "code": -1}, "url": "sys/login/user"}

    def logout(self):
        if self.sid is not None:
            if self._lock_ctx.uses_workspace:
                self._lock_ctx.run_unlock()
            ret_code, response = self.execute("sys/logout")
            self.sid = None
            return ret_code, response

    def __enter__(self):
        self.login()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.logout()

    @staticmethod
    def common_datagram_params(method_type, url, *args, **kwargs):
        params = [{"url": url}]
        if args:
            for arg in args:
                params[0].update(arg)
        if kwargs:
            keylist = list(kwargs)
            for k in keylist:
                kwargs[k.replace("___", " ").replace("__", "-")] = kwargs.pop(k)
            if method_type == "get" or method_type == "clone":
                params[0].update(kwargs)
            else:
                if kwargs.get("data", False):
                    params[0]["data"] = kwargs["data"]
                else:
                    params[0]["data"] = kwargs
        return params

    def get(self, url, *args, **kwargs):
        return self._post_request("get", self.common_datagram_params("get", url, *args, **kwargs))

    def add(self, url, *args, **kwargs):
        return self._post_request("add", self.common_datagram_params("add", url, *args, **kwargs))

    def update(self, url, *args, **kwargs):
        return self._post_request("update", self.common_datagram_params("update", url, *args, **kwargs))

    def set(self, url, *args, **kwargs):
        return self._post_request("set", self.common_datagram_params("set", url, *args, **kwargs))

    def delete(self, url, *args, **kwargs):
        return self._post_request("delete", self.common_datagram_params("delete", url, *args, **kwargs))

    def replace(self, url, *args, **kwargs):
        return self._post_request("replace", self.common_datagram_params("replace", url, *args, **kwargs))

    def clone(self, url, *args, **kwargs):
        return self._post_request("clone", self.common_datagram_params("clone", url, *args, **kwargs))

    def execute(self, url, login=False, *args, **kwargs):
        return self._post_request("exec", self.common_datagram_params("execute", url, *args, **kwargs), login)

    def move(self, url, *args, **kwargs):
        return self._post_request("move", self.common_datagram_params("move", url, *args, **kwargs))

    def unset(self, url, *args, **kwargs):
        return self._post_request("unset", self.common_datagram_params("unset", url, *args, **kwargs))

    def free_form(self, method, create_task=None, **kwargs):
        if kwargs:
            if kwargs.get("data", False):
                return self._post_request(method, kwargs["data"], free_form=True, create_task=create_task)
            else:
                raise FMGRequestNotFormedCorrect("Free Form Request was not formed correctly. A data key is required")
        else:
            raise FMGRequestNotFormedCorrect("Free Form Request was not formed correctly. A dictionary object with a "
                                             "data key is required")

    def __str__(self):
        if self.sid is not None:
            return "FortiManager instance connnected to {host}.".format(host=self._host)
        return "FortiManager object with no valid connection to a FortiManager appliance."

    def __repr__(self):
        if self.sid is not None:
            return "{classname}(host={host}, pwd omitted, debug={debug}, use_ssl={use_ssl}, " \
                   "verify_ssl={verify_ssl}, timeout={timeout})".format(classname=self.__class__.__name__,
                                                                        host=self._host, debug=self._debug,
                                                                        use_ssl=self._use_ssl, timeout=self._timeout,
                                                                        verify_ssl=self._verify_ssl)
        return "FortiManager object with no valid connection to a FortiManager appliance."
