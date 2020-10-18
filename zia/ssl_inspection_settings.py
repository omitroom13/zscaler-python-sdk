import logging
from .defaults import *

from zia import ZiaApiBase

class Ssl(ZiaApiBase):
    def delete_ssl_certchain(self):
        raise NotImplementedError()
    def download_csr(self):
        raise NotImplementedError()
    def generate_csr(self):
        raise NotImplementedError()
    def show_cert(self):
        raise NotImplementedError()
    def upload_signed_cert(self):
        raise NotImplementedError()
    def upload_cert_chain(self):
        raise NotImplementedError()


LOGGER = logging.getLogger(__name__)
