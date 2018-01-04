#!/usr/bin/env python

import logging
import json
import requests

log = logging.getLogger("fortimanager")


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
            return json.dumps({'Type Information': te.message})

    def dprint(self, msg, s=None):
        if self.debug:
            print(msg)
            if s is not None:
                print(self.jprint(s) + '\n')
        pass

    def _set_sid(self, response):
        if self.sid is None and 'session' in response:
            self.sid = response['session']

    def _handle_response(self, response):
        try:
            self._set_sid(response)
            if type(response['result']) is list:
                result = response['result'][0]
            else:
                result = response['result']
            if 'data' in result:
                return result['status']['code'], result['data']
            else:
                return result['status']['code'], result
        except Exception as e:
            self.dprint('Response parser error: {err_type} {err}'.format(err_type=type(e), err=e))
            return 1, e

    def _post_request(self, method, params):
        self._update_request_id()
        headers = {'content-type': 'application/json'}
        json_request = {
            'method': method,
            'params': params,
            'session': self.sid,
            'id': self.req_id,
        }
        self.dprint('REQUEST:', json_request)
        try:
            response = requests.post(self._url, data=json.dumps(json_request), headers=headers, verify=self.verify_ssl,
                                     timeout=self.timeout).json()
        except requests.exceptions.ConnectionError as cerr:
            self.dprint('Connection error: {err_type} {err}'.format(err_type=type(cerr), err=cerr))
            return 1, cerr
        except Exception as err:
            self.dprint('Exception: {err_type} {err}'.format(err_type=type(err), err=err))
            return 1, err
        assert response['id'] == json_request['id']
        self.dprint('RESPONSE:', response)
        return self._handle_response(response)

    def login(self):
        self._url = '{proto}://{host}/jsonrpc'.format(proto='https' if self._use_ssl else 'http', host=self._host)
        self.execute('sys/login/user', passwd=self._passwd, user=self._user,)
        return self

    def logout(self):
        if self.sid is not None:
            ret_code, response = self.execute('sys/logout')
            self.sid = None
            return ret_code, response

    def __enter__(self):
        return self.login()

    def __exit__(self, exc_type, exc_val, exc_tb):
        return self.logout()

    @staticmethod
    def common_datagram_params(url, **kwargs):
        params = [{'url': url}]
        if kwargs:
            data = kwargs
            params[0]['data'] = data
        return params

    def get(self, url, *args, **kwargs):
        if kwargs:
            data = kwargs
            data['url'] = url
            params = [data]
        else:
            params = [{'url': url}]
        return self._post_request('get', params)

    def add(self, url, *args, **kwargs):
        return self._post_request('add', self.common_datagram_params(url, **kwargs))

    def update(self, url, *args, **kwargs):
        return self._post_request('update', self.common_datagram_params(url, **kwargs))

    def set(self, url, *args, **kwargs):
        return self._post_request('set', self.common_datagram_params(url, **kwargs))

    def delete(self, url, *args, **kwargs):
        return self._post_request('delete', self.common_datagram_params(url, **kwargs))

    def replace(self, url, *args, **kwargs):
        return self._post_request('replace', self.common_datagram_params(url, **kwargs))

    def clone(self, url, *args, **kwargs):
        return self._post_request('clone', self.common_datagram_params(url, **kwargs))

    def execute(self, url, *args, **kwargs):
        return self._post_request('exec', self.common_datagram_params(url, **kwargs))

    def move(self, url, *args, **kwargs):
        if kwargs:
            data = kwargs
            data['url'] = url
            params = [data]
            return self._post_request('move', params)

    def __str__(self):
        if self.sid is not None:
            return 'FortiManager instance connnected to {host}.'.format(host=self._host)
        return 'FortiManager object with no valid connection to a FortiManager appliance.'

    def __repr__(self):
        if self.sid is not None:
            return '{classname}(host={host}, pwd omitted, debug={debug}, use_ssl={use_ssl}, ' \
                   'verify_ssl={verify_ssl}, timeout={timeout})'.format(classname=self.__class__.__name__,
                                                                        host=self._host, debug=self._debug,
                                                                        use_ssl=self._use_ssl, timeout=self._timeout,
                                                                        verify_ssl=self._verify_ssl)
        return 'FortiManager object with no valid connection to a FortiManager appliance.'
