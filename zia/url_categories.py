import datetime
import logging
import json
import sys

import fire

from .defaults import *
from . import load_config
from .session import Session, RequestError

class UrlCategories(object):
    def __init__(self, session, output_type='dict'):
        self._session = session
        #json or string
        self._output_type = output_type
    def _output(self, res):
        if self._output_type == 'dict':
            return res
        return json.dumps(res, indent=True)
    def list(self, custom_only=False):
        path = 'urlCategories'
        if custom_only:
            path += '?customOnly=true'
        return self._output(self._session.get(path))
    def create(self, category):
        path = 'urlCategories'
        body = category
        return self._output(self._session.post(path, body))
    def list_lite(self):
        path = 'urlCategories/lite'
        return self._output(self._session.get(path))
    def get_quota(self):
        path = 'urlCategories/urlQuota'
        return self._output(self._session.get(path))
    def get(self, category_id):
        path = 'urlCategories/{}'.format(category_id)
        return self._output(self._session.get(path))
    def update(self, category_id, category):
        path = 'urlCategories/{}'.format(category_id)
        return self._output(self._session.put(path, category))
    def delete(self, category_id):
        path = 'urlCategories/{}'.format(category_id)
        return self._output(self._session.delete(path))
    def lookup(self, urls):
        path = 'urlLookup'
        return self._output(self._session.post(path, urls))

LOGGER = logging.getLogger(__name__)
if __name__ == '__main__':
    try:
        load_config()
        LOGGER.setLevel(logging.DEBUG)
        session = Session()
        categories = UrlCategories(session, 'str')
        session.authenticate()
        fire.Fire(categories)
    except RequestError as exc:
        fmt = 'method {} path {} code {} message {} body {}'
        LOGGER.error(fmt.format(exc.method, exc.path, exc.code, exc.message, exc.body))
