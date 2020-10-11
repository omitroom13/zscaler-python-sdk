import requests
import platform
import logging
import time

from .activation import Activation
from .admin_audit_logs import AdminAuditLogs
from .datacenters import Datacenters
from .gre import Gre
from .helpers import Helpers
from .locations import Locations
from .security import Security
from .session import Session
from .sandbox import Sandbox
from .ssl import Ssl
from .user import User
from .vpn_credentials import VpnCredentials

__version_tuple__ = (0, 1, 0)
__version__ = '.'.join(map(str, __version_tuple__))
__email__ = 'NO EMAIL'
__author__ = "omitroom13 <{0}>".format(__email__)
__copyright__ = "{0}, {1}".format(time.strftime('%Y'), __author__)
__maintainer__ = __author__
__license__ = "MIT"
__status__ = "Alpha"

class ZscalerInternetAccess():
    def __init__(self, profile='default'):
        self.debug = False
        self.session = Session(profile=profile)
        self.user_agent = 'ZscalerSDK/%s Python/%s %s/%s' % (
            __version__,
            platform.python_version(),
            platform.system(),
            platform.release()
        )
        self.activation = Activation(self.session)
        self.admin_audit_logs = AdminAuditLogs(self.session)
        self.location = Locations(self.session)
        self.security = Security(self.session)
        self.datacenters = Datacenters(self.session)
        self.sandbox = Sandbox(self.session)
        self.ssl = Ssl(self.session)
        self.user = User(self.session)
        self.gre = Gre(self.session)
        self.vpn_credentials = VpnCredentials(self.session)
