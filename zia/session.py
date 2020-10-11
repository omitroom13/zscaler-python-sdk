import json
import logging
import time
import os
import platform
import re
import requests
import sys
from http.cookiejar import Cookie

import yaml

from .defaults import *
from . import load_config

PROFILE_FILENAME = os.path.join(os.environ['HOME'], '.zscaler', 'profile.yaml')
PROFILE = 'default'

COOKIE_FILENAME = os.path.join(os.environ['HOME'], '.zscaler', 'cookie.yaml')

# constant
URL = 'url'
USERNAME = 'username'
PASSWORD = 'password'
APIKEY = 'apikey'

class RequestError(Exception):
    def __init__(self, method, path, body, error):
        self.method = method
        self.path = path
        self.body = body
        self.code = error['code']
        self.message = error['message']

class SessionTimeoutError(RequestError):
    pass

class Session(object):
    API_VERSION  = 'api/v1'
    USER_AGENT = 'zia api sdk'
    def __init__(self, profile='default'):
        self.profile = profile
        self._profile = None
        self.get_profile(name=profile)
        self.url = self._profile[URL]
        if self.url[-1] == '/':
            raise RuntimeError('url {} must not be end with "/".'.format(url))
        self.username = self._profile[USERNAME]
        self.password = self._profile[PASSWORD]
        (self.timestamp, self.obfuscated_api_key) = self._obfuscate_api_key(self._profile[APIKEY])
        self.session = requests.Session()
        self.load_cookie()
    def get_profile(self, filename=PROFILE_FILENAME, name=PROFILE, reread=False):
        if self._profile is None or reread:
            try:
                with open(filename) as file:
                    self._profile = yaml.safe_load(file)[name]
            except FileNotFoundError:
                raise RuntimeError('Cannot find profile file: {}'.format(filename))
        return self._profile
    def load_cookie(self, filename=COOKIE_FILENAME, name=PROFILE, reread=False):
        if len(self.session.cookies) == 0 or reread:
            try:
                y = None
                with open(filename) as file:
                    y = yaml.safe_load(file)
                for d in y[name].values():
                    c = Cookie(
                        d['version'],
                        d['name'],
                        d['value'],
                        d['port'],
                        d['port_specified'],
                        d['domain'],
                        d['domain_specified'],
                        d['domain_initial_dot'],
                        d['path'],
                        d['path_specified'],
                        d['secure'],
                        d['expires'],
                        d['discard'],
                        d['comment'],
                        d['comment_url'],
                        d['_rest'],
                        d['rfc2109'])
                    self.session.cookies.set_cookie(c)
            except FileNotFoundError:
                LOGGER.warning('Cannot find cookie file: {}'.format(filename))
            except KeyError:
                LOGGER.warning('Cannot find cookie profile: {}'.format(filename))
    def save_cookie(self, filename=COOKIE_FILENAME, name=PROFILE):
        y = {}
        try:
            with open(filename) as file:
                y = yaml.safe_load(file)
        except FileNotFoundError:
            pass
        if name not in y:
            y[name] = {}
        for c in self.session.cookies:
            y[name][c.name] = c.__dict__
        with open(filename, 'w') as file:
            yaml.dump(y, file)
    def _set_header(self, cookie=None):
        header = {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-cache',
            'User-Agent': self.USER_AGENT
        }
        LOGGER.debug("HTTP Header: {}".format(header))
        return header
    def _parse_jsessionid(self, cookie):
        jsessionid = re.sub(r';.*$', "", cookie)
        LOGGER.debug("JSESSION ID: {}".format(jsessionid))
        return jsessionid
    def _obfuscate_api_key(self, api_key):
        now = str(int(time.time() * 1000))
        n = now[-6:]
        r = str(int(n) >> 1).zfill(6)
        key = ""
        for i in range(0, len(n), 1):
            key += api_key[int(n[i])]
        for j in range(0, len(r), 1):
            key += api_key[int(r[j])+2]
        LOGGER.debug(
            "OBFUSCATED APY KEY / Time: ***** / {}".format(now))
        return (now, key)
    def authenticate(self):
        path = 'authenticatedSession'
        try:
            if self.session.cookies.get('JSESSIONID'):
                LOGGER.info("cookie authentication")
                res = self.get(path)
                # GET /authenticatedSession does not validate session(JSESSIONID cookie), so execute other method
                self.get_status()
                LOGGER.info("authenticated")
                return res
        except SessionTimeoutError:
            LOGGER.info("session timedout. trying re-authn")
        LOGGER.info("password authentication")
        body = {
            'username': self.username,
            'password': self.password,
            'apiKey': self.obfuscated_api_key,
            'timestamp': self.timestamp
        }
        LOGGER.debug("HTTP BODY: {}".format(body))
        res = self.post(path, body)
        LOGGER.debug(res)
        if not res['authType']:
            raise RuntimeError('not authenticated')
        LOGGER.info('authenticated')
        self.save_cookie()
    def get_status(self):
        path = 'status'
        return self.get(path)
    def activate(self):
        path = 'status/activate'
        return self.post(path)
    def request(self, method, path, body=None):
        header = self._set_header()
        uri = "/".join([self.url, self.API_VERSION, path])
        LOGGER.debug('method {} path {} body {}'.format(method.__name__, path, body))
        q = None
        kwargs = {
            'headers':header,
            'timeout':REQUEST_TIMEOUTS
        }
        if body:
            kwargs['json'] = body
        res_json = None
        error = None
        res = method(uri, **kwargs)
        code = {'code': res.text, 'message': res.text}
        try:
            res_json = res.json()
            error = res_json
        except json.decoder.JSONDecodeError:
            pass
        if res.ok:
            error = None
        if error:
            raise RequestError(method.__name__, path, body, error)
        if res_json:
            return res_json
        if len(res.text) == 0:
            return None
        if re.search(r'<title>Zscaler Maintenance Page</title>', res.text):
            error = {'code': 'MAINTENANCE', 'message': 'undergoing maintenance'}
            raise RequestError(method.__name__, path, body, error)
        elif re.search(r'var contentString = "Something has gone wrong while attempting to display this page.";', res.text):
            error = {'code': 'ERROR', 'message': 'Something has gone wrong'}
            raise SessionTimeoutError(method.__name__, path, body, error)
        elif res.text == 'SESSION_NOT_VALID':
            error = {'code': 'SESSION_NOT_VALID', 'message': 'maybe cookie timeout'}
            raise SessionTimeoutError(method.__name__, path, body, error)
        elif re.search(r'Request body is invalid', res.text):
            error = {'code': 'REQUEST_NOT_VALID', 'message': res.text}
            raise SessionTimeoutError(method.__name__, path, body, error)
        else:
            LOGGER.warning("text output might be error: {}".format(res.text))
        return res.text
    def get(self, path):
        return self.request(self.session.get, path)
    def post(self, path, body):
        return self.request(self.session.post, path, body)
    def put(self, path, body):
        return self.request(self.session.put, path, body)
    def delete(self, path):
        return self.request(self.session.delete, path)


LOGGER = logging.getLogger(__name__)

if __name__ == '__main__':
    load_config()
    LOGGER.setLevel(logging.INFO)
    session = Session()
    LOGGER.info(session.authenticate())
    LOGGER.info(session.session.cookies.get('JSESSIONID'))
    LOGGER.info(session.authenticate())
