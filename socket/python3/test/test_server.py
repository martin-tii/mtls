import pytest
from unittest.mock import MagicMock
from authServer import authServer, CertificateExpiredError, CertificateHostnameError, CertificateIssuerError


class TestAuthServer:
    @pytest.fixture(autouse=True)
    def setup(self, tmpdir):
        self.cert_path = tmpdir.mkdir("certificates")
        self.server_key_path = self.cert_path / "server.key"
        self.server_crt_path = self.cert_path / "server.crt"
        self.ca_crt_path = self.cert_path / "ca.crt"

        # Create some fake certificate files
        with open(self.server_key_path, "w") as f:
            f.write("fake_server_key_content")
        with open(self.server_crt_path, "w") as f:
            f.write("fake_server_crt_content")
        with open(self.ca_crt_path, "w") as f:
            f.write("fake_ca_crt_content")

    def test_verify_cert_success(self):
        # Arrange
        cert_data = {
            "subject": ((("commonName", "client"),),),
            "issuer": ((("commonName", "TII"),),),
            "notAfter": "Jan 01 00:00:00 2030 GMT",
        }
        server = authServer()
        server.verify_cert = MagicMock(return_value=None)

        # Act & Assert
        server.verify_cert(cert_data)

    def test_verify_cert_expired_certificate(self):
        # Arrange
        cert_data = {
            "subject": ((("commonName", "client"),),),
            "issuer": ((("commonName", "TII"),),),
            "notAfter": "Jan 01 00:00:00 2000 GMT",  # Expired certificate
        }
        server = authServer()

        # Act & Assert
        with pytest.raises(CertificateExpiredError):
            server.verify_cert(cert_data)

    def test_verify_cert_hostname_mismatch(self):
        # Arrange
        cert_data = {
            "subject": ((("commonName", "wrong_hostname"),),),  # Mismatched common name
            "issuer": ((("commonName", "TII"),),),
            "notAfter": "Jan 01 00:00:00 2030 GMT",
        }
        server = authServer()

        # Act & Assert
        with pytest.raises(CertificateHostnameError):
            server.verify_cert(cert_data)

# Add more tests as needed

