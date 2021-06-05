import json
import logging
import time
import os
import re
import requests
from http.cookiejar import Cookie
from requests.exceptions import ConnectionError
from http.client import RemoteDisconnected
                
import yaml

from .defaults import load_config, RequestError, SessionTimeoutError, AuthenticationError

PROFILE = 'default'

# constant
URL = 'url'
USERNAME = 'username'
PASSWORD = 'password'
APIKEY = 'apikey'

class Session(object):
    API_VERSION = 'api/v1'
    USER_AGENT = 'zia api sdk'
    REQUEST_TIMEOUTS = (5, 25)

    def __init__(self, profile='default'):
        self.profile = profile
        self._profile = None
        self.session = requests.Session()
        self.profile_filename = os.path.join(os.environ['HOME'], '.zscaler', 'profile.yaml')
        self.cookie_filename = os.path.join(os.environ['HOME'], '.zscaler', 'cookie.yaml')

    def load_profile(self):
        try:
            with open(self.profile_filename) as file:
                self._profile = yaml.safe_load(file)[self.profile]
        except FileNotFoundError:
            raise RuntimeError(
                'Cannot find profile file: {}'.format(self.profile_filename))
        if self._profile[URL] == '/':
            raise RuntimeError('url {} must not be end with "/".'.format(self._profile[URL]))
        return self._profile

    def load_cookie(self):
        y = None
        with open(self.cookie_filename) as file:
            y = yaml.safe_load(file)
        for d in y[self.profile].values():
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
            if c.is_expired():
                LOGGER.warning('cookie expired : {}'.format(d['name']))
                continue
            d['expires'] = None
            self.session.cookies.set_cookie(c)

    def save_cookie(self):
        y = {}
        try:
            with open(self.cookie_filename) as file:
                y = yaml.safe_load(file)
        except FileNotFoundError:
            pass
        if self.profile not in y:
            y[self.profile] = {}
        for c in self.session.cookies:
            y[self.profile][c.name] = c.__dict__
            if c.name == 'JSESSIONID' and 'expires' in y[self.profile][c.name]:
                # 2 hours is no basis.
                y[self.profile][c.name]['expires'] = int(time.time()) + 2*60*60
        with open(self.cookie_filename, 'w') as file:
            yaml.dump(y, file)

    def _generate_static_kwargs(self):
        return {
            'headers': {
                'Content-Type': 'application/json',
                'Cache-Control': 'no-cache',
                'User-Agent': self.USER_AGENT
            },
            'timeout': self.REQUEST_TIMEOUTS
        }

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
        status = self.is_authenticated()
        if status:
            return {'code': 'OK', 'message': 'already authenticated'}
        if self._profile is None:
            self.load_profile()
        try:
            self.load_cookie()
        except FileNotFoundError:
            LOGGER.warning(
                'Cannot find cookie file: {}'.format(self.cookie_filename))
        except KeyError:
            LOGGER.warning(
                'Cannot find cookie profile: {}'.format(self.cookie_filename))
        LOGGER.info("password authentication")
        (timestamp, obfuscated_api_key) = self._obfuscate_api_key(self._profile[APIKEY])
        body = {
            'username': self._profile[USERNAME],
            'password': self._profile[PASSWORD],
            'apiKey': obfuscated_api_key,
            'timestamp': timestamp
        }
        LOGGER.debug("HTTP BODY: {}".format(body))
        res = self._request(self.session.post, path, body=body, authentication=False)
        LOGGER.debug(res)
        if 'authType' in res and res['authType'] == 'ADMIN_LOGIN':
            LOGGER.info('authenticated')
            self.save_cookie()
            res['code'] = 'OK'
            res['message'] = 'credential authenticated'
            return res
        raise RuntimeError('either credential or apikey are wrong')

    def is_authenticated(self):
        path = 'authenticatedSession'
        c = self.session.cookies.get('JSESSIONID')
        if c is None:
            return None
        LOGGER.debug("cookie authentication")
        # res = self.get(path)
        res = self._request(self.session.get, path, None, authentication=False)
        if 'authType' in res and res['authType'] == 'ADMIN_LOGIN':
            LOGGER.debug("authenticated")
            res['code'] = 'OK'
            res['message'] = 'cookie authenticated'
            return res
        return None

    def get_status(self):
        path = 'status'
        return self.get(path)

    def activate(self):
        path = 'status/activate'
        return self.post(path)

    def _retry_request(self, uri, method, kwargs, retry_count=3):
        # api ごとに limit が違い面倒なので、何秒待つべきか把握していない。retry の時だけ気持ち待つ
        api_rate_limit_seconds = 1
        res = None
        res_json = None
        error = None
        for count in range(retry_count):
            try:
                res = method(uri, **kwargs)
                res_json = res.json()
                error = res_json
                if 'code' in error and error['code'] == 'UNEXPECTED_ERROR' and 'message' in error and error['message'] == 'Data access error 0xf':
                    LOGGER.warning('UNEXPECTED_ERROR! retry {}/{}'.format(count, retry_count))
                    (res, res_json, error) = (None, None, None)
                    time.sleep(api_rate_limit_seconds)
                    continue
            except json.decoder.JSONDecodeError:
                pass
            except (ConnectionError, RemoteDisconnected) as exc:
                LOGGER.warning('ConnectionError/RemoteDisconnected {} retry {}/{}'.format(str(exc), count, retry_count))
            if count != 0:
                LOGGER.warning('UNEXPECTED_ERROR recovered by retry {}/{}'.format(count, retry_count))
            break
        return (res, res_json, error)

    def _request(self, method, path, body=None, authentication=True):
        if authentication:
            res = self.is_authenticated()
            if res is None or res['code'] != 'OK':
                LOGGER.warning('session timeout? reauth')
                self.authenticate()
        uri = "/".join([self._profile[URL], self.API_VERSION, path])
        LOGGER.debug('method {} path {} body {}'.format(
            method.__name__, path, body))
        kwargs = self._generate_static_kwargs()
        if body:
            kwargs['json'] = body
        # res_json = None
        # error = None
        # # -- ここから retry --
        # res = method(uri, **kwargs)
        # # code = {'code': res.text, 'message': res.text}
        # try:
        #     res_json = res.json()
        #     error = res_json
        #     # -- ここまで retry --
        # except json.decoder.JSONDecodeError:
        #     pass
        (res, res_json, error) = self._retry_request(uri, method, kwargs)
        if res.ok:
            error = None
        if error and 'code' in error:
            # よくわからんタイミングで {'code': 'UNEXPECTED_ERROR', 'message': 'Data access error 0xf'} が発生する? リトライすれば良い?
            if error['code'] == 'UNEXPECTED_ERROR' and 'message' in error and error['message'] == 'Data access error 0xf':
                LOGGER.warning('whooooa')
            raise RequestError(method.__name__, path, body, error)
        if error and re.match(r'Rate Limit', error['message']):
            # [API Rate Limit Summary | Zscaler](https://help.zscaler.com/zia/api-rate-limit-summary)
            # hint: ssl settings is very low limit(1/min and 4/hr)
            error['code'] = "RATELIMITEXCEEDED"
            error['message'] += ". Retry After {}".format(error['Retry-After'])
            raise RequestError(method.__name__, path, body, error)
        if res_json:
            return res_json
        if res.text == '[]':
            # /firewallFilteringRules returns [] as text?
            return []
        if len(res.text) == 0:
            return None
        if path == 'auditlogEntryReport/download':
            # csv download. text output is nothing wrong.
            pass
        elif re.search(r'<title>Zscaler Maintenance Page</title>', res.text):
            error = {'code': 'MAINTENANCE',
                     'message': 'undergoing maintenance'}
            raise RequestError(method.__name__, path, body, error)
        elif re.search(r'var contentString = "Something has gone wrong while attempting to display this page.";', res.text):
            error = {'code': 'ERROR', 'message': 'Something has gone wrong'}
            raise RequestError(method.__name__, path, body, error)
        elif res.text == 'SESSION_NOT_VALID':
            error = {'code': 'SESSION_NOT_VALID',
                     'message': 'maybe cookie timeout'}
            raise SessionTimeoutError(method.__name__, path, body, error)
        elif re.search(r'Request body is invalid', res.text):
            error = {'code': 'REQUEST_NOT_VALID', 'message': res.text}
            raise RequestError(method.__name__, path, body, error)
        else:
            LOGGER.warning("text output might be error: {}".format(res.text))
        # maybe it is bad because api did not return json.
        return res.text

    def get(self, path, body=None):
        return self._request(self.session.get, path, body)

    def post(self, path, body):
        return self._request(self.session.post, path, body)

    def put(self, path, body):
        return self._request(self.session.put, path, body)

    def delete(self, path):
        return self._request(self.session.delete, path)


LOGGER = logging.getLogger(__name__)

if __name__ == '__main__':
    load_config()
    LOGGER.setLevel(logging.INFO)
    session = Session()
    LOGGER.info(session.authenticate())
    LOGGER.info(session.session.cookies.get('JSESSIONID'))
    LOGGER.info(session.authenticate())
