import logging
from .defaults import *


class Ssl(object):
    def delete_ssl_certchain(self):
        pass
    def download_csr(self):
        pass
    def generate_csr(self):
        pass
    def show_cert(self):
        pass
    def upload_signed_cert(self):
        pass
    def upload_cert_chain(self):
        pass


LOGGER = logging.getLogger(__name__)
