import logging

from .defaults import ZiaApiBase


class UrlCategories(ZiaApiBase):
    def list(self, custom_only=False, summary=False):
        """
        Gets information about all or custom URL categories
        --summary : Gets a lightweight key-value list of all or custom URL categories
        """
        path = 'urlCategories'
        if summary:
            path += '/lite'
        if custom_only:
            path += '?customOnly=true'
        return self._session.get(path)

    def create(self, category):
        """
        Adds a new custom URL category
        """
        path = 'urlCategories'
        return self._session.post(path, category)

    def get_quota(self):
        """
        Gets the URL quota information for your organization
        """
        path = 'urlCategories/urlQuota'
        return self._session.get(path)

    def get(self, category_id):
        """
        Gets the URL category information for the specified ID
        """
        path = 'urlCategories/{}'.format(category_id)
        return self._session.get(path)

    def update(self, category_id, category):
        """
        Updates the URL category for the specified ID
        """
        path = 'urlCategories/{}'.format(category_id)
        return self._session.put(path, category)

    def delete(self, category_id):
        """
        Deletes the custom URL category for the specified ID
        """
        path = 'urlCategories/{}'.format(category_id)
        return self._session.delete(path)

    def lookup(self, urls):
        """
        Look up the categorization of the given set of URLs, e.g., ['abc.com', 'xyz.com']
        """
        path = 'urlLookup'
        return self._session.post(path, urls)


LOGGER = logging.getLogger(__name__)
