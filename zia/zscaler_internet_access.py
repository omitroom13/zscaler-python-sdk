from .defaults import load_config, get_config, RequestError, SessionTimeoutError, ZiaApiBase
from .session import Session

from .activation import Activation
from .admin_audit_logs import AdminAuditLogs
from .admin_role_management import AdminRoleManagement
from .cloud_sandbox_report import CloudSandboxReport
from .datacenters import Datacenters
from .gre import Gre
from .locations import Locations
from .security import Security
from .sandbox import Sandbox
from .ssl import Ssl
from .user import User
from .vpn_credentials import VpnCredentials
from .url_filtering_policies import UrlFilteringPolicies
from .url_categories import UrlCategories

class ZscalerInternetAccess(object):
    def __init__(self, profile='default'):
        self._session = Session(profile=profile)
        self.activation = Activation(self._session, 'str')
        self.admin_audit_logs = AdminAuditLogs(self._session, 'str')
        self.admin_role_management = AdminRoleManagement(self._session, 'str')
        self.sandbox = CloudSandboxReport(self._session, 'str')
        # self.location = Locations(self.session)
        # self.security = Security(self.session)
        # self.datacenters = Datacenters(self.session)
        # self.sandbox = Sandbox(self.session)
        # self.ssl = Ssl(self.session)
        # self.user = User(self.session)
        # self.gre = Gre(self.session)
        # self.vpn_credentials = VpnCredentials(self.session)
        self.policies = UrlFilteringPolicies(self._session, 'str')
        self.categories = UrlCategories(self._session, 'str')
    def authenticate(self):
        self._session.authenticate()
