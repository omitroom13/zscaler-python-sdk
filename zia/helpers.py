import logging
import inspect
import json
from functools import wraps

from .defaults import ZiaApiBase


class Helpers(object):
    def extract_values(self, obj, key):
        """Recursively pull values of specified key from nested JSON."""
        arr = []

        def extract(obj, arr, key):
            """Return all matching values in an object."""
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if isinstance(v, (dict, list)):
                        extract(v, arr, key)
                    elif k == key:
                        arr.append(v)
            elif isinstance(obj, list):
                for item in obj:
                    extract(item, arr, key)
            return arr

        results = extract(obj, arr, key)
        return results


def decorate_for_fire(obj, exclude=None):
    """
    recursively decorate ZiaApiBase's object method for dict.__str__ on fire.
    """
    def wrapper(func):
        @wraps(func)
        def decorate(*args, **kwargs):
            result = func(*args, **kwargs)
            return json.dumps(result, indent=True, ensure_ascii=False)
        return decorate
    for name, member in inspect.getmembers(obj):
        if name.startswith('_'):
            continue
        if type(exclude) is list and name in exclude:
            continue
        if inspect.ismethod(member):
            LOGGER.debug('decorate method: {}'.format(member))
            setattr(obj, name, wrapper(member))
        if isinstance(member, ZiaApiBase):
            LOGGER.debug('recursively decorate ZiaApiBase object: {}'.format(member))
            setattr(obj, name, decorate_for_fire(member))
    return obj


LOGGER = logging.getLogger(__name__)
