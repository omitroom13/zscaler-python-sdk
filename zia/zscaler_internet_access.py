from .defaults import load_config, get_config, RequestError, SessionTimeoutError, ZiaApiBase
from .session import Session

from .activation import Activation
from .admin_audit_logs import AdminAuditLogs
from .admin_role_management import AdminRoleManagement
from .cloud_sandbox_report import CloudSandboxReport
from .firewall import Firewall
from .datacenters import Datacenters
from .gre import Gre
from .locations import Locations
from .security import Security
from .sandbox import Sandbox
from .ssl_inspection_settings import SslSettings
from .user import User
from .traffic_forwarding import VpnCredentials
from .url_filtering_policies import UrlFilteringPolicies
from .url_categories import UrlCategories

class ZscalerInternetAccess(object):
    def __init__(self, profile='default'):
        self._session = Session(profile=profile)
        self.activation = Activation(self._session, 'str')
        self.admin_audit_logs = AdminAuditLogs(self._session, 'str')
        self.admin_role_management = AdminRoleManagement(self._session, 'str')
        self.sandbox = CloudSandboxReport(self._session, 'str')
        self.firewall = Firewall(self._session, 'str')
        self.locations = Locations(self._session, 'str')
        self.security = Security(self._session, 'str')
        # self.datacenters = Datacenters(self._session, 'str')
        # self.sandbox = Sandbox(self._session, 'str')
        self.ssl = SslSettings(self._session, 'str')
        # self.user = User(self._session, 'str')
        # self.gre = Gre(self._session, 'str')
        self.vpn = VpnCredentials(self._session, 'str')
        self.policies = UrlFilteringPolicies(self._session, 'str')
        self.categories = UrlCategories(self._session, 'str')
    def authenticate(self):
        self._session.authenticate()
