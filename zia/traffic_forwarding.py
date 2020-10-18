import random
import string
import json
import logging

from .defaults import load_config, get_config, RequestError, SessionTimeoutError, ZiaApiBase

class VpnCredentials(ZiaApiBase):
    MAX_PSK_LEN = 64
    def _randomize_psk(self):
        psk = ''.join(random.choices(
            string.ascii_letters + string.digits, k=self.MAX_PSK_LEN))
        LOGGER.debug("RANDOM PSK: {} (PSK Length: {})".format(
            psk,
            len(psk)
        ))
        return psk
    def list(self):
        path = 'vpnCredentials'
        return self._output(self._session.get(path))
    def create(self, credential):
        path = 'vpnCredentials'
        if 'preSharedKey' not in credential:
            credential['preSharedKey'] = self._randomize_psk()
        return self._output(self._session.post(path, credential))
    def show(self, vpn_id):
        path = 'vpnCredentials/{}'.format(vpn_id)
        return self._output(self._session.get(path))
    def update(self, vpn_id, credential):
        path = 'vpnCredentials/{}'.format(vpn_id)
        if 'preSharedKey' not in credential:
            credential['preSharedKey'] = self._randomize_psk()
        return self._output(self._session.put(path, credential))
    def delete(self, vpn_id):
        path = 'vpnCredentials/{}'.format(vpn_id)
        return self._output(self._session.delete(path))


LOGGER = logging.getLogger(__name__)
