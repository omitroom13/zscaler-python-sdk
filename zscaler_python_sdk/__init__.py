
from .vpn_credentials import VpnCredentials
from .user import User
from .ssl import Ssl
from .security import Security
from .session import Session
from .sandbox import Sandbox
from .locations import Locations
from .helpers import Helpers
from .gre import Gre
from .datacenters import Datacenters
from .auth import Auth
from .activation import Activation
import requests
import platform
import logging
import time

__version_tuple__ = (0, 0, 5)
__version__ = '.'.join(map(str, __version_tuple__))
__email__ = 'NO EMAIL'
__author__ = "Eddie Parra <{0}>".format(__email__)
__copyright__ = "{0}, {1}".format(time.strftime('%Y'), __author__)
__maintainer__ = __author__
__license__ = "BSD"
__status__ = "Alpha"

class zscaler(Activation, Auth, Datacenters, Gre, Helpers, Locations, Sandbox, Session, Security, Ssl, User, VpnCredentials):
    def __init__(self):
        self.session = requests.Session()
        self.user_agent = 'ZscalerSDK/%s Python/%s %s/%s' % (
            __version__,
            platform.python_version(),
            platform.system(),
            platform.release()
        )
