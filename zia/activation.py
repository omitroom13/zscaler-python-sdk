import logging

from .defaults import ZiaApiBase


class Activation(ZiaApiBase):
    def get_status(self):
        """
        Gets the activation status for a configuration change
        """
        path = 'status'
        return self._session.get(path)

    def activate(self):
        """
        Activates configuration changes
        """
        path = 'status/activate'
        body = {}
        return self._session.post(path, body)


LOGGER = logging.getLogger(__name__)
