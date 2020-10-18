from .helpers import decorate_for_fire
from .session import Session

from .activation import Activation
from .admin_audit_logs import AdminAuditLogs
from .admin_role_management import AdminRoleManagement
from .cloud_sandbox_report import CloudSandboxReport
from .firewall import Firewall
# from .datacenters import Datacenters
# from .gre import Gre
from .locations import Locations
from .security import Security
from .ssl_inspection_settings import SslSettings
from .user_management import Departments, Groups, Users
from .traffic_forwarding import VpnCredentials
from .url_filtering_policies import UrlFilteringPolicies
from .url_categories import UrlCategories
from .user_authentication_settings import AuthSettings


class ZscalerInternetAccess(object):
    def __init__(self, profile='default'):
        self._session = Session(profile=profile)
        self.activation = Activation(self._session)
        self.admin_audit_logs = AdminAuditLogs(self._session)
        self.admin_role_management = AdminRoleManagement(self._session)
        self.sandbox = CloudSandboxReport(self._session)
        self.firewall = Firewall(self._session)
        self.locations = Locations(self._session)
        self.security = Security(self._session)
        self.ssl = SslSettings(self._session)
        self.department = Departments(self._session)
        self.group = Groups(self._session)
        self.user = Users(self._session)
        self.vpn = VpnCredentials(self._session)
        self.policies = UrlFilteringPolicies(self._session)
        self.categories = UrlCategories(self._session)
        self.auth_settings = AuthSettings(self._session)
        # self.datacenters = Datacenters(self._session)
        # self.gre = Gre(self._session)
