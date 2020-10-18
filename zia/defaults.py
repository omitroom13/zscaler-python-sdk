import json
import pkgutil
import os
import logging
import logging.config

import yaml

global Z_CLOUDS, DEBUG_DEFAULT, MAX_FQDN_LEN, MAX_PSK_LEN, REQUEST_TIMEOUTS

DEBUG_DEFAULT = False
MAX_FQDN_LEN = 255


Z_CLOUDS = {
    'zscaler': 'https://admin.zscaler.net/',
    'zscloud': 'https://admin.zscloud.net/',
    'zscalerone': 'https://admin.zscalerone.net/',
    'zscalertwo': 'https://admin.zscalertwo.net/',
    'zscalerthree': 'https://admin.zscalerthree.net/',
    'betacloud': 'https://admin.zscalerbeta.net/'
}

USER_CONFIG_FILE = './config.yaml'


def load_config():
    global _CONFIG
    _CONFIG = yaml.safe_load(pkgutil.get_data(
        __package__, 'data/config.yaml').decode('utf-8'))
    if os.path.exists(USER_CONFIG_FILE):
        with open(USER_CONFIG_FILE) as configfile:
            _CONFIG = yaml.safe_load(configfile.read())
    if 'log' in _CONFIG:
        logging.config.dictConfig(_CONFIG['log'])


def get_config():
    if _CONFIG is None:
        load_config()
    return _CONFIG


class RequestError(Exception):
    def __init__(self, method, path, body, error):
        self.method = method
        self.path = path
        self.body = body
        self.code = error['code']
        self.message = error['message']


class SessionTimeoutError(RequestError):
    pass

class AuthenticationError(RequestError):
    pass

class ZiaApiBase(object):
    def __init__(self, session):
        self._session = session
