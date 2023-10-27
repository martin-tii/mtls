from unittest.mock import MagicMock
from authServer import authServer
from verification_tools import *
import pytest
import asyncio
import ssl
import threading


CERT_PATH = '../../certificates/'

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

    def start_server(self):
        server = authServer()
        server.run()

    def create_ssl_context(self):
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_verify_locations(f'{CERT_PATH}/ca.crt')
        context.verify_mode = ssl.CERT_REQUIRED
        return context

    @pytest.fixture
    def server(self):
        # Create and start the server in a separate thread
        server_thread = threading.Thread(target=self.start_server)
        server_thread.start()
        yield
        # Clean up after the test is done
        server_thread.join()

    @pytest.fixture
    def ssl_context(self):
        return self.create_ssl_context()

    @pytest.fixture
    async def ssl_connection(self, event_loop, ssl_context):
        # Create an SSL connection to the server
        reader, writer = await asyncio.open_connection('127.0.0.1', '12345', ssl=ssl_context)
        yield reader, writer
        writer.close()
        await writer.wait_closed()

    @pytest.mark.asyncio
    async def test_multiple_clients(self, server, ssl_context):
        num_clients = 5

        async def simulate_client(client_id):
            reader, writer = await asyncio.open_connection('127.0.0.1', '12345', ssl=ssl_context)
            message = f"Hello, server! This is client {client_id}"
            writer.write(message.encode())
            await writer.drain()

            response = await reader.read(1024)
            assert response.decode() == "Hello, client! This is the server."

            writer.close()
            await writer.wait_closed()

        # Start multiple client connections concurrently
        tasks = [simulate_client(i) for i in range(num_clients)]
        await asyncio.gather(*tasks)
