#!/usr/bin/env python

import logging
import json
import requests

log = logging.getLogger("fortimanager")


class FortiManager(object):

    def __init__(self, host, user, passwd, debug=False, use_ssl=True, verify_ssl=False, disable_request_warnings=False):
        super(FortiManager, self).__init__()
        self._debug = debug
        self._host = host
        self._user = user
        self._passwd = passwd
        self._use_ssl = use_ssl
        self._verify_ssl = verify_ssl
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
            print ('Response parser error: {err_type} {err}'.format(err_type=type(e), err=e))
            return 1, e

    @staticmethod
    def _append_querystrings(base_url, querystring_list):
        # remove last slash if one exists
        url_postfix = base_url[:-1] if base_url[-1] == '/' else base_url
        url_postfix += '?'
        url = url_postfix + '&'.join(querystring_list)
        return url

    def _post_request(self, method, data_dict, *args, **kwargs):
        self._update_request_id()
        headers = {'content-type': 'application/json'}
        json_request = dict()
        params = list()
        json_request['params'] = params
        json_request['method'] = method
        json_request['id'] = self.req_id
        json_request['session'] = self.sid
        json_request['data'] = data_dict
        url = self._url
        if kwargs:
            if kwargs.get('querystrings', default=None) is not None:
                url = self._append_querystrings(self._url, kwargs.get('querystrings'))
                del kwargs['querystrings']
            json_request['data'] = data_dict.update(kwargs)
        json_request['params'].append(json_request['data'])
        self.dprint('REQUEST:', json_request)
        response = requests.post(url, data=json.dumps(json_request), headers=headers, verify=self.verify_ssl,
                                 timeout=300).json()
        self.dprint('RESPONSE:', response)
        return self._handle_response(response)

    def login(self):
        protocol = 'https' if self._use_ssl else 'http'
        self._url = '{proto}://{host}/jsonrpc'.format(proto=protocol, host=self._host)
        params_dict = dict()
        params_dict['url'] = 'sys/login/user'
        # params_dict['data'] = [{'passwd': passwd, 'user': user}]
        params_dict['passwd'] = self._passwd
        params_dict['user'] = self._user
        ret_code, response = self.execute(params_dict)
        return self

    def logout(self):
        if self.sid is not None:
            params_dict = dict()
            params_dict['url'] = 'sys/logout'
            ret_code, response = self.execute(params_dict)
            self.sid = None
            return ret_code, response

    def __enter__(self):
        return self.login()

    def __exit__(self, exc_type, exc_val, exc_tb):
        return self.logout()

    def _clean_request(self, method, data_dict, *args, **kwargs):
        if method == 'get':
            ret_code, response = self._post_request(method, data_dict, *args, **kwargs)
        elif 'odd_request_form' in data_dict.keys():
            # option when data attribute different than the standard for that method
            # for instance, the exec method MOSTLY uses data within an array structured as:
            # 'params': [{'data': [{'stuff': 'to', 'set': 'here'}, {'other': 'stuff', 'set': 'here'}]}]
            # however, there are occasions where it needs to be structured as just the dictionary of items like this:
            # 'params': [{'data': {'stuff': 'to', 'set': 'here'}}]
            # providing an 'odd_request_form' attribute in data_dict that has a value of True allows this code to
            # modify that standard request.
            if data_dict['odd_request_form'] is True:
                new_data_dict = dict()
                new_data_dict['url'] = data_dict['url']
                del data_dict['url']
                del data_dict['odd_request_form']
                new_data_dict['data'] = data_dict
                ret_code, response = self._post_request(method, new_data_dict, *args, **kwargs)
            else:
                ret_code, response = (1, {'msg': 'format error'})
        elif method == 'update':
            # option when data attribute is simply a dictionary:
            # 'params': [{'data': {'stuff': 'to', 'set': 'here'}}]
            new_data_dict = dict()
            new_data_dict['url'] = data_dict['url']
            del data_dict['url']
            new_data_dict['data'] = data_dict
            ret_code, response = self._post_request(method, new_data_dict, *args, **kwargs)
        else:
            # option when data attribute is an array of dictionaries:
            # 'params': [{'data': [{'stuff': 'to', 'set': 'here'}, {'other': 'stuff', 'set': 'here'}]}]
            # if that fails, remove the array and attempt with just the dictionary
            new_data_dict = dict()
            new_data_dict['url'] = data_dict['url']
            del data_dict['url']
            data_array = list()
            data_array.append(data_dict)
            new_data_dict['data'] = data_array
            ret_code, response = self._post_request(method, new_data_dict, *args, **kwargs)
            # If all else fails, this will try again without the list encompassing the data.
            # so if format: 'params': [{'data': [{'stuff': 'to', 'set': 'here'}, {'other': 'stuff', 'set': 'here'}]}]
            # does not work, this will resubmit one last time like this:
            # 'params': [{'data': [{'stuff': 'to', 'set': 'here'}, {'other': 'stuff', 'set': 'here'}]}]
            if ret_code != 0:
                self.dprint('Initial run fail, attempt without list')
                new_data_dict['data'] = data_dict
                ret_code, response = self._post_request(method, new_data_dict, *args, **kwargs)
        return ret_code, response

    def get(self, data_dict, *args, **kwargs):
        return self._clean_request('get', data_dict, *args, **kwargs)

    def add(self, data_dict, *args, **kwargs):
        return self._clean_request('add', data_dict, *args, **kwargs)

    def update(self, data_dict, *args, **kwargs):
        return self._clean_request('update', data_dict, *args, **kwargs)

    def set(self, data_dict, *args, **kwargs):
        return self._clean_request('set', data_dict, *args, **kwargs)

    def delete(self, data_dict, *args, **kwargs):
        return self._clean_request('delete', data_dict, *args, **kwargs)

    def replace(self, data_dict, *args, **kwargs):
        return self._clean_request('replace', data_dict, *args, **kwargs)

    def clone(self, data_dict, *args, **kwargs):
        return self._clean_request('clone', data_dict, *args, **kwargs)

    def move(self, data_dict, *args, **kwargs):
        return self._clean_request('move', data_dict, *args, **kwargs)

    def execute(self, data_dict, *args, **kwargs):
        return self._clean_request('exec', data_dict, *args, **kwargs)

    def __str__(self):
        if self.sid is not None:
            return 'FortiManager instance connnected to {host}.'.format(host=self._host)
        return 'FortiManager object with no valid connection to a FortiManager appliance.'

    def __repr__(self):
        if self.sid is not None:
            return '{classname}(host={host}, pwd omitted, debug={debug}, use_ssl={use_ssl}, verify_ssl={verify_ssl})'.\
                format(classname=self.__class__.__name__, host=self._host, debug=self._debug, use_ssl=self._use_ssl,
                       verify_ssl=self._verify_ssl)
        return 'FortiManager object with no valid connection to a FortiManager appliance.'
