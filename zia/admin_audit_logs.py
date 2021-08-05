import datetime
import json
import logging

import isodate

from .defaults import ZiaApiBase


class AdminAuditLogs(ZiaApiBase):
    def get(self):
        """
        Gets the status of a request for an audit log report
        """
        path = 'auditlogEntryReport'
        # status complete
        # download
        return self._session.get(path)

    def create(self, start, duration):
        """
        Creates an audit log report for the specified time period and saves it as a CSV file
        start : iso8601 format (yyyy-mm-ddThh:mm:ss, ex. 2020-10-17T19:13:00)
        duration : iso8601 duration (PdDThHmMsS, ex. P7DT23H59M59S)
        * start/output log timezone is determined by admin account setting *
        """
        s = isodate.parse_datetime(start)
        e = s + isodate.parse_duration(duration)
        path = 'auditlogEntryReport'
        body = {
            'startTime': int(s.timestamp()*1000),
            'endTime': int(e.timestamp()*1000),
        }
        LOGGER.debug(body)
        return self._session.post(path, body)

    def wait(self, timeout=600):
        """
        Waits for generating report.
        """
        s = datetime.datetime.now()
        status = json.loads(self.get())
        while status['status'] != 'COMPLETE':
            status = self.get()
            e = datetime.datetime.now()
            if (e - s).seconds > timeout:
                raise RuntimeError('timeout')
        return status

    def cancel(self):
        """
        Cancels the request to create an audit log report
        """
        path = 'auditlogEntryReport'
        return self._session.delete(path)

    def download(self, output):
        """
        Downloads the most recently created audit log report.
        output : csv filename
        """
        self.wait()
        path = 'auditlogEntryReport/download'
        with open(output, 'w') as f:
            f.write(self._session.get(path))
            LOGGER.info('log downloaded: {}'.format(output))


LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.DEBUG)
