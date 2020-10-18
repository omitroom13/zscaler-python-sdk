import logging

from .defaults import ZiaApiBase


class ExemptedUrls(ZiaApiBase):
    def list(self):
        """
        Gets a list of URLs that were exempted from cookie authentication
        """
        path = "authSettings/exemptedUrls"
        return self._session.get(path)

    def add(self, urls):
        """
        Adds URLs to the cookie authentication exempt list
        """
        path = "authSettings/exemptedUrls?action=ADD_TO_LIST"
        return self._session.post(path, urls)

    def remove(self, urls):
        """
        Removes URLs from the cookie authentication exempt list
        """
        path = "authSettings/exemptedUrls?action=REMOVE_FROM_LIST"
        return self._session.post(path, urls)


class AuthSettings(ZiaApiBase):
    def __init__(self, _session):
        super().__init__(_session)
        self.exempted_urls = ExemptedUrls(self._session)


LOGGER = logging.getLogger(__name__)
