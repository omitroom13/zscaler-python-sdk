import datetime
import logging
import json
import sys

import fire

from .defaults import *
from . import load_config, ZiaApiBase
from .session import Session, RequestError

class UrlFilteringPolicies(ZiaApiBase):
    def list(self):
        path = 'urlFilteringRules'
        return self._output(self._session.get(path))
    def create(self, rule):
        path = 'urlFilteringRules'
        return self._output(self._session.post(path, rule))
    def show(self, rule_id):
        path = 'urlFilteringRules/{}'.format(rule_id)
        return self._output(self._session.get(path))
    def update(self, rule_id, rule):
        path = 'urlFilteringRules/{}'.format(rule_id)
        return self._output(self._session.put(path, rule))
    def delete(self, rule_id):
        path = 'urlFilteringRules/{}'.format(rule_id)
        return self._output(self._session.delete(path))
    
LOGGER = logging.getLogger(__name__)
if __name__ == '__main__':
    try:
        load_config()
        LOGGER.setLevel(logging.DEBUG)
        session = Session()
        policies = UrlFilteringPolicies(session, 'str')
        session.authenticate()
        fire.Fire(policies)
    except RequestError as exc:
        fmt = 'method {} path {} code {} message {} body {}'
        LOGGER.error(fmt.format(exc.method, exc.path, exc.code, exc.message, exc.body))
