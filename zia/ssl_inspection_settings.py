import logging
from .defaults import ZiaApiBase


class CertificateSigningRequest(ZiaApiBase):
    def download(self, csr):
        """
        Downloads a Certificate Signing Request (CSR)
        """
        path = "sslSettings/downloadcsr"
        return self._session.get(path, csr)

    def generate(self, csr):
        """
        Generates a Certificate Signing Request (CSR)
        """
        path = "sslSettings/generatecsr"
        return self._session.post(path, csr)


class Certificate(ZiaApiBase):
    def show(self):
        """
        Shows information about the signed intermediate root certificate
        """
        path = "sslSettings/showcert"
        return self._session.get(path)

    def upload(self):
        """
        Uploads a signed intermediate root certificate for clients that use iframe-based uploads whose content type is text/plain
        """
        path = "sslSettings/uploadcert/text"
        return self._session.post(path)


class CertificateChain(ZiaApiBase):
    def upload(self):
        """
        Uploads the Intermediate Certificate Chain (PEM) for clients that use iframe-based uploads whose content type is text/plain
        """
        path = "sslSettings/uploadcertchain/text"
        return self._session.post(path)

    def delete(self):
        """
        Deletes the intermediate certificate chain
        """
        path = "sslSettings/certchain"
        return self._session.delete(path)


class ExemptedUrls(ZiaApiBase):
    def get(self):
        """
        Gets a list of URLs that were exempted from SSL Inpection and policy evaluation
        """
        path = "sslSettings/exemptedUrls"
        return self._session.get(path)

    def add(self):
        """
        Adds URLs to the exempted from SSL Inspection and policy evaluation list or removes URLs from the list
        """
        path = "sslSettings/exemptedUrls"
        return self._session.post(path)


class SslSettings(ZiaApiBase):
    def __init__(self, _session):
        super().__init__(_session)
        self.csr = CertificateSigningRequest(self._session)
        self.certificate = Certificate(self._session)
        self.chain = CertificateChain(self._session)
        self.exempted_urls = ExemptedUrls(self._session)


LOGGER = logging.getLogger(__name__)
