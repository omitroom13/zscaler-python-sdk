import logging

from .defaults import ZiaApiBase


class Gre(ZiaApiBase):
    def get_gre_tunnel_details(self):
        path = 'orgProvisioning/ipGreTunnelInfo'
        return self._session.get(path)


LOGGER = logging.getLogger(__name__)
