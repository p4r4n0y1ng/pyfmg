#!/usr/bin/env python

from datetime import datetime
import time
import logging
import json
import requests
from requests.exceptions import ConnectionError as ReqConnError, ConnectTimeout as ReqConnTimeout


log = logging.getLogger("fortimanager")


class FMGBaseException(Exception):
    """Wrapper to catch the unexpected"""
    def __init__(self, msg=None, *args, **kwargs):
        if msg is None:
            msg = "An exception occurred within pyfmg"
        super(FMGBaseException, self).__init__(msg, *args, **kwargs)


class FMGValidSessionException(FMGBaseException):
    """Raised when a call is made, but there is no valid login instance"""
    def __init__(self, method, params, *args, **kwargs):
        msg = "A call using the {method} method was requested to {url} on a FortiManager instance that had no " \
              "valid session or was not connected. Paramaters were:\n{params}".\
            format(method=method, url=params[0]["url"], params=params)
        super(FMGValidSessionException, self).__init__(msg, *args, **kwargs)


class FMGValueError(ValueError):
    """Catch value errors such as bad timeout values"""
    def __init__(self, *args, **kwargs):
        super(FMGValueError, self).__init__(*args, **kwargs)


class FMGResponseNotFormedCorrect(KeyError):
    """Used only if a response does not have a standard format as based on FMG response guidelines"""
    def __init__(self, *args, **kwargs):
        super(FMGResponseNotFormedCorrect, self).__init__(*args, **kwargs)


class FMGConnectionError(ReqConnError):
    """Wrap requests Connection error so requests is not a dependency outside this module"""
    def __init__(self, *args, **kwargs):
        super(FMGConnectionError, self).__init__(*args, **kwargs)


class FMGConnectTimeout(ReqConnTimeout):
    """Wrap requests Connection timeout error so requests is not a dependency outside this module"""
    def __init__(self, *args, **kwargs):
        super(FMGConnectTimeout, self).__init__(*args, **kwargs)


class FMGLockContext(object):

    def __init__(self, fmg):
        self._fmg = fmg
        self._locked_adom_list = list()
        self._uses_workspace = False

    @property
    def uses_workspace(self):
        return self._uses_workspace

    @uses_workspace.setter
    def uses_workspace(self, val):
        self._uses_workspace = val

    def add_adom_to_lock_list(self, adom):
        if adom not in self._locked_adom_list:
            self._locked_adom_list.append(adom)

    def remove_adom_from_lock_list(self, adom):
        if adom in self._locked_adom_list:
            self._locked_adom_list.remove(adom)

    def check_mode(self):
        url = "/cli/global/system/global"
        code, resp_obj = self._fmg.get(url)
        try:
            if resp_obj["workspace-mode"] != 0:
                self.uses_workspace = True
        except KeyError:
            self.uses_workspace = False

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


class FortiManager(object):

    def __init__(self, host, user, passwd, debug=False, use_ssl=True, verify_ssl=False, timeout=300,
                 disable_request_warnings=False):
        super(FortiManager, self).__init__()
        self._debug = debug
        self._host = host
        self._user = user
        self._passwd = passwd
        self._use_ssl = use_ssl
        self._verify_ssl = verify_ssl
        self._timeout = timeout
        self._req_id = 0
        self._sid = None
        self._url = None
        self._lock_ctx = FMGLockContext(self)
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

    @staticmethod
    def jprint(json_obj):
        try:
            return json.dumps(json_obj, indent=2, sort_keys=True)
        except TypeError as te:
            return json.dumps({"Type Information": te.message})

    def dprint(self, msg, s=None):
        if self.debug:
            print(msg)
            if s is not None:
                print(self.jprint(s) + "\n")
        pass

    def _set_sid(self, response):
        if self.sid is None and "session" in response:
            self.sid = response["session"]

    def lock_adom(self, adom=None, *args, **kwargs):
        return self._lock_ctx.lock_adom(adom, *args, **kwargs)

    def unlock_adom(self, adom=None, *args, **kwargs):
        return self._lock_ctx.unlock_adom(adom, *args, **kwargs)

    def commit_changes(self, adom=None, aux=False, *args, **kwargs):
        return self._lock_ctx.commit_changes(adom, aux, *args, **kwargs)

    def _handle_response(self, response):
        self._set_sid(response)
        if type(response["result"]) is list:
            result = response["result"][0]
        else:
            result = response["result"]
        if "data" in result:
            return result["status"]["code"], result["data"]
        else:
            return result["status"]["code"], result

    def _post_request(self, method, params, login=False):
        if self.sid is None and not login:
            raise FMGValidSessionException(method, params)
        self._update_request_id()
        headers = {"content-type": "application/json"}
        json_request = {
            "method": method,
            "params": params,
            "session": self.sid,
            "id": self.req_id,
        }
        self.dprint("REQUEST:", json_request)
        try:
            response = requests.post(self._url, data=json.dumps(json_request), headers=headers, verify=self.verify_ssl,
                                     timeout=self.timeout).json()
            self.dprint("RESPONSE:", response)
            return self._handle_response(response)
        except ReqConnError as err:
            self.dprint("Connection error: {err_type} {err}\n\n".format(err_type=type(err), err=err))
            raise FMGConnectionError(err)
        except ValueError as err:
            self.dprint("Value error: {err_type} {err}\n\n".format(err_type=type(err), err=err))
            raise FMGValueError(err)
        except KeyError as err:
            self.dprint("Key error in response: {err_type} {err}\n\n".format(err_type=type(err), err=err))
            raise FMGResponseNotFormedCorrect(err)
        except IndexError as err:
            self.dprint("Index error in response: {err_type} {err}\n\n".format(err_type=type(err), err=err))
            raise FMGResponseNotFormedCorrect(err)
        except Exception as err:
            self.dprint("Response parser error: {err_type} {err}".format(err_type=type(err), err=err))
            raise FMGBaseException(err)

    def track_task(self, task_id, sleep_time=5, retrieval_fail_gate=10, timeout=120):
        begin_task_time = datetime.now()
        start = time.time()
        self.dprint("Task begins at {time}".format(time=str(begin_task_time)))
        percent = 0
        code_fail = 0
        code = 1
        task_info = ""
        while percent != 100:
            code, task_info = self.get("/task/task/{taskid}".format(taskid=task_id))
            if code == 0:
                percent = int(task_info["percent"])
                num_done = int(task_info["num_done"])
                num_err = int(task_info["num_err"])
                num_lines = int(task_info["num_lines"])
                self.dprint("At timestamp {timestamp}:\nTask {taskid} is at {percent}% completion.\n{num_err} "
                            "tasks have returned an error.".format(timestamp=datetime.now(),
                                                                   taskid=str(task_id), percent=str(percent),
                                                                   num_done=str(num_done), num_lines=str(num_lines),
                                                                   num_err=str(num_err)), task_info)
            else:
                code_fail += 1
            if code_fail == retrieval_fail_gate:
                self.dprint("Task info retrieval failed over {fail_gate} times. Something has caused issues "
                            "with task {taskid}.".format(taskid=task_id, fail_gate=retrieval_fail_gate))
                return code, task_info
            if percent != 100:
                if time.time() - start >= timeout:
                    self.dprint("Task did not complete in efficient time. The timeout value was {}".format(timeout))
                    return 1, {"msg": "Task did not complete in efficient time. "
                                      "The timeout value was {}".format(timeout)}
                else:
                    time.sleep(sleep_time)
        end_task_time = datetime.now()
        self.dprint("Task completion is at {time}".format(time=str(end_task_time)))
        self.dprint("Total time to complete is {time}".format(time=str(end_task_time-begin_task_time)))
        return code, task_info

    def login(self):
        self._url = "{proto}://{host}/jsonrpc".format(proto="https" if self._use_ssl else "http", host=self._host)
        self.execute("sys/login/user", login=True, passwd=self._passwd, user=self._user,)
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
            for k, _ in kwargs.iteritems():
                kwargs[k.replace("__", "-")] = kwargs.pop(k)
            if method_type == "get" or method_type == "clone":
                params[0].update(kwargs)
            else:
                data = kwargs
                params[0]["data"] = data
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
