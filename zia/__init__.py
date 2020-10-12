import json
import logging
import logging.config
import os
import pkgutil
import sys

import yaml

USER_CONFIG_FILE = './config.yaml'

def load_config():
    global _CONFIG
    _CONFIG = yaml.safe_load(pkgutil.get_data(__package__, 'data/config.yaml').decode('utf-8'))
    if os.path.exists(USER_CONFIG_FILE):
        with open(USER_CONFIG_FILE) as configfile:
            _CONFIG = yaml.safe_load(configfile.read())
    if 'log' in _CONFIG:
        logging.config.dictConfig(_CONFIG['log'])

def get_config():
    if _CONFIG is None:
        load_config()
    return _CONFIG

class ZiaApiBase(object):
    def __init__(self, session, output_type='dict'):
        self._session = session
        self._output_type = output_type
    def _output(self, res):
        if self._output_type == 'dict':
            return res
        elif self._output_type == 'str':
            #for fire
            return json.dumps(res, indent=True, ensure_ascii=False)
        raise RuntimeError('unknown output_type {}'.format(self._output_type))


LOGGER = logging.getLogger(__name__)
_CONFIG = None
