import random
import string
import logging

from .defaults import ZiaApiBase


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
        return self._session.get(path)

    def create(self, credential):
        path = 'vpnCredentials'
        if 'preSharedKey' not in credential:
            credential['preSharedKey'] = self._randomize_psk()
        return self._session.post(path, credential)

    def show(self, vpn_id):
        path = 'vpnCredentials/{}'.format(vpn_id)
        return self._session.get(path)

    def update(self, vpn_id, credential):
        path = 'vpnCredentials/{}'.format(vpn_id)
        if 'preSharedKey' not in credential:
            credential['preSharedKey'] = self._randomize_psk()
        return self._session.put(path, credential)

    def delete(self, vpn_id):
        path = 'vpnCredentials/{}'.format(vpn_id)
        return self._session.delete(path)

class IpGreTunnelInfo(ZiaApiBase):
    def list(self):
        """
        Gets a list of IP addresses with GRE tunnel details
        """
        path = 'orgProvisioning/ipGreTunnelInfo'
        return self._session.get(path)

class Vips(ZiaApiBase):
    def list(self, include="all"):
        """
        Gets a paginated list of the virtual IP addresses (VIPs) available in the Zscaler cloud
        """
        if include not in ["all", "public", "private"]:
            RutimeError("include {} must be all, public or private.".format(include))
        path = 'vips?include={}'.format(include)
        return self._session.get(path)
    

LOGGER = logging.getLogger(__name__)
