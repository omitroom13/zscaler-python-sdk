import logging

from .defaults import ZiaApiBase


class FilteringRules(ZiaApiBase):
    def list(self):
        """
        Gets all rules in the firewall filtering policy
        """
        path = 'firewallFilteringRules'
        # '/firewallFilteringRules' does not have /lite API
        return self._session.get(path)

    def show(self, rule_id):
        """
        Gets the firewall filtering rule information for the specified ID
        """
        path = 'firewallFilteringRules/{}'.format(rule_id)
        return self._session.get(path)


class IpDestinationGroups(ZiaApiBase):
    def list(self, summary=False):
        """
        Gets a list of all IP destination groups
        --summary : Gets a name and ID dictionary of all IP destination groups
        """
        path = 'ipDestinationGroups'
        if summary:
            path += '/lite'
        return self._session.get(path)

    def show(self, ip_group_id):
        """
        Gets the IP destination group information for the specified ID
        """
        path = 'ipDestinationGroups/{}'.format(ip_group_id)
        return self._session.get(path)


class IpSourceGroups(ZiaApiBase):
    def list(self, summary=False):
        """
        Gets a list of all IP source groups
        --summary : Gets a name and ID dictionary of all IP source groups
        """
        path = 'ipSourceGroups'
        if summary:
            path += '/lite'
        return self._session.get(path)

    def show(self, ip_group_id):
        """
        Gets the IP source group information for the specified ID
        """
        path = 'ipSourceGroups/{}'.format(ip_group_id)
        return self._session.get(path)


class NetworkApplicationGroups(ZiaApiBase):
    def list(self, summary=False):
        """
        Gets a list of all network application groups
        --summary : Gets a name and ID dictionary of all network application groups
        """
        path = 'networkApplicationGroups'
        if summary:
            path += '/lite'
        return self._session.get(path)

    def show(self, group_id):
        """
        Gets the network application group information for the specified ID
        """
        path = 'networkApplicationGroups/{}'.format(group_id)
        return self._session.get(path)


class NetworkApplications(ZiaApiBase):
    def list(self, summary=False):
        """
        Gets a list of all predefined network applications
        """
        path = 'networkApplications'
        # '/networkAplications' does not have /lite API
        return self._session.get(path)

    def show(self, app_id):
        """
        Gets the network application information for the specified ID
        """
        path = 'networkApplications/{}'.format(app_id)
        return self._session.get(path)


class NetworkServiceGroups(ZiaApiBase):
    def list(self, summary=False):
        """
        Gets a list of all network service groups
        --summary : Gets a name and ID dictionary of all network service groups
        """
        path = 'networkServiceGroups'
        if summary:
            path += '/lite'
        return self._session.get(path)

    def show(self, service_group_id):
        """
        Gets the network service group information for the specified ID
        """
        path = 'networkServiceGroups/{}'.format(service_group_id)
        return self._session.get(path)


class NetworkServices(ZiaApiBase):
    def list(self, summary=False):
        """
        Gets a list of all network services
        --summary : Gets a name and ID dictionary of all network services
        """
        path = 'networkServices'
        if summary:
            path += '/lite'
        return self._session.get(path)

    def show(self, service_id):
        """
        Gets the network service for the specified ID
        """
        path = 'networkServices/{}'.format(service_id)
        return self._session.get(path)


class TimeWindows(ZiaApiBase):
    def list(self, summary=False):
        """
        Gets a list of time intervals used by the firewall filtering policy
        --summary : Gets a name and ID dictionary of time intervals used by the firewall filtering policy
        """
        path = 'timeWindows'
        if summary:
            path += '/lite'
        return self._session.get(path)


class Firewall(ZiaApiBase):
    def __init__(self, _session):
        super().__init__(_session)
        self.rules = FilteringRules(self._session)
        self.destination = IpDestinationGroups(self._session)
        self.source = IpSourceGroups(self._session)
        self.application_groups = NetworkApplicationGroups(self._session)
        self.applications = NetworkApplications(self._session)
        self.service_groups = NetworkServiceGroups(self._session)
        self.services = NetworkServices(self._session)
        self.timewindows = TimeWindows(self._session)


LOGGER = logging.getLogger(__name__)
