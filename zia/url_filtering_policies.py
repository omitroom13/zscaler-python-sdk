import logging

from .defaults import ZiaApiBase


class UrlFilteringPolicies(ZiaApiBase):
    def list(self):
        """
        Gets a list of all of URL Filtering Policy rules
        """
        path = 'urlFilteringRules'
        return self._session.get(path)

    def create(self, rule):
        """
        Adds a URL Filtering Policy rule
        """
        path = 'urlFilteringRules'
        return self._session.post(path, rule)

    def show(self, rule_id):
        """
        Gets the URL Filtering Policy rule for the specified ID
        """
        path = 'urlFilteringRules/{}'.format(rule_id)
        return self._session.get(path)

    def update(self, rule_id, rule):
        """
        Updates the URL Filtering Policy rule for the specified ID
        """
        path = 'urlFilteringRules/{}'.format(rule_id)
        return self._session.put(path, rule)

    def delete(self, rule_id):
        """
        Deletes the URL Filtering Policy rule for the specified ID
        """
        path = 'urlFilteringRules/{}'.format(rule_id)
        return self._session.delete(path)


LOGGER = logging.getLogger(__name__)
