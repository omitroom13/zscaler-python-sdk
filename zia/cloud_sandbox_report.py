import logging
from .defaults import ZiaApiBase


class CloudSandboxReport(ZiaApiBase):
    def get_quota(self):
        """
        Gets the Sandbox Report API quota information for your organization
        """
        path = 'sandbox/report/quota'
        return self._session.get(path)

    def get_report(self, md5hash, details="summary"):
        """
        Gets a full (i.e., complete) or summary detail report for an MD5 hash of a file that was analyzed by Sandbox
        """
        if details not in ['summary', 'full']:
            raise RuntimeError('details must be summary or full')
        path = 'sandbox/report/{}?details={}'.format(md5hash, details)
        return self._session.get(path)


LOGGER = logging.getLogger(__name__)
