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
                for d in y[name]:
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
            y[name] = []
        for c in self.session.cookies:
            y[name].append(c.__dict__)
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
        method = 'authenticatedSession'
        if self.session.cookies.get('JSESSIONID'):
            return self._perform_get_request(method)
        body = {
            'username': self.username,
            'password': self.password,
            'apiKey': self.obfuscated_api_key,
            'timestamp': self.timestamp
        }
        LOGGER.debug("HTTP BODY: {}".format(body))
        res = self._perform_post_request(method, body)
        LOGGER.debug(res)
        if not res['authType']:
            raise RuntimeError('not authenticated')
        LOGGER.info('authenticated')
        self.save_cookie()
    def _perform_get_request(self, method, header=None):
        cookies = None
        if header == None:
            header = self._set_header()
        uri = "/".join([self.url, self.API_VERSION, method])
        LOGGER.info(list(self.session.cookies))
        res = self.session.get(
            uri,
            headers=header,
            timeout=REQUEST_TIMEOUTS
        )
        res.raise_for_status()
        if len(res.text) == 0:
            return None
        try:
            j = res.json()
            return j
        except json.decoder.JSONDecodeError:
            pass
        if re.search(r'<title>Zscaler Maintenance Page</title>', res.text):
            LOGGER.error(res.is_redirect)
        return res.text
    def _perform_post_request(self, method, body, header=None):
        cookies = None
        if header == None:
            header = self._set_header()
        uri = "/".join([self.url, self.API_VERSION, method])
        attempt = json.dumps(body, sort_keys=True,
                             indent=4, separators=(',', ': '))
        LOGGER.debug("ATTEMPTING POST (URI): {}\nPOST BODY: {}".format(
            uri,
            attempt
        ))
        res = self.session.post(
            uri,
            json=body,
            headers=header,
            timeout=REQUEST_TIMEOUTS
        )
        res.raise_for_status()
        LOGGER.info(self.session.cookies)
        if len(res.text) == 0:
            return None
        return res.json()
    def _perform_put_request(self, method, body, header=None):
        cookies = None
        if header == None:
            header = self._set_header()
        uri = "/".join([self.url, self.API_VERSION, method])
        attempt = json.dumps(body, sort_keys=True,
                             indent=4, separators=(',', ': '))
        LOGGER.debug("ATTEMPTING PUT (URI): {}\nPUT BODY: {}".format(
            uri,
            attempt)
        )
        res = self.session.put(
            uri,
            json=body,
            headers=header,
            timeout=REQUEST_TIMEOUTS
        )
        res.raise_for_status()
        LOGGER.info(self.session.cookies)
        if len(res.text) == 0:
            return None
        return res.json()
    def _perform_delete_request(self, method, header=None):
        cookies = None
        if header == None:
            header = self._set_header()
        uri = "/".join([self.url, self.API_VERSION, method])
        res = self.session.delete(
            uri,
            headers=header,
            timeout=REQUEST_TIMEOUTS
        )
        res.raise_for_status()
        LOGGER.info(self.session.cookies)
        if len(res.text) == 0:
            return None
        return res.json()


LOGGER = logging.getLogger(__name__)

if __name__ == '__main__':
    load_config()
    LOGGER.setLevel(logging.INFO)
    session = Session()
    session.load_cookie()
    LOGGER.info(session.authenticate())
    LOGGER.info(session.session.cookies.get('JSESSIONID'))
    LOGGER.info(session.authenticate())
