import pytest
import socket
import ssl
from authClient import authClient

# Constants for testing
TEST_SERVER_IP = '127.0.0.1'
TEST_SERVER_PORT = 12345
TEST_CERT_PATH = '../../certificates/'
FAKE_PATH = f"{TEST_CERT_PATH}fake/"
print(FAKE_PATH)
def test_successful_connection():
    # Start the server for testing (in this case, a mock server is not required)
    # Ensure that the server is running and listening on the specified address and port

    # Create the client instance
    client = authClient()

    # Define the message to be sent to the server
    message = "Hello, server!"

    # Run the client with the server address, port, certificate path, and message
    client.run(TEST_SERVER_IP, TEST_SERVER_PORT, TEST_CERT_PATH, message)



# def test_invalid_certificate():
#     # This test simulates the case where the client certificate is not trusted by the server
#     # In this case, the server should reject the client connection
#
#     # Start a mock server that does not trust the client's certificate
#     server_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
#     server_context.load_cert_chain(certfile=f'{FAKE_PATH}/server.crt', keyfile=f'{FAKE_PATH}/server.key')
#     server_context.verify_mode = ssl.CERT_REQUIRED
#     server_context.load_verify_locations(f'{FAKE_PATH}/ca.crt')  # An invalid CA certificate
#
#     # Create a socket to listen for client connections
#     with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
#         communication(server_socket)
#
#
#
# def communication(server_socket):
#     server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#     server_address = (TEST_SERVER_IP, TEST_SERVER_PORT)
#     server_socket.bind(server_address)
#     server_socket.listen(1)
#
#     # Create the client instance
#     client = authClient()
#
#     # Define the message to be sent to the server
#     message = "Hello, server!"
#
#     # Run the client with the server address, port, certificate path, and message
#     # The client should raise an SSL error (CERTIFICATE_VERIFY_FAILED)
#     with pytest.raises(socket.error):
#         client.run(TEST_SERVER_IP, TEST_SERVER_PORT, FAKE_PATH, message)



def test_server_unreachable():
    # This test simulates the case where the server is unreachable
    # The client should raise a socket error when attempting to connect to the server

    # Set the socket timeout to 5 seconds
    socket.setdefaulttimeout(5)

    # Create the client instance
    client = authClient()

    # Define a non-existent server address and port
    invalid_server_ip = '192.168.0.100'
    invalid_server_port = 12345

    # Define the message to be sent to the server
    message = "Hello, server!"

    # Run the client with the invalid server address, port, certificate path, and message
    # The client should raise a socket error (ConnectionRefusedError or socket.timeout)
    with pytest.raises(socket.error):
        client.run(invalid_server_ip, invalid_server_port, TEST_CERT_PATH, message)

    # Reset the socket timeout to its default value (None)
    socket.setdefaulttimeout(None)


def test_invalid_certificate_path():
    # This test simulates the case where the client provides an invalid certificate path
    # The client should raise a file not found error when loading the client certificate and key

    # Create the client instance
    client = authClient()

    # Define an invalid certificate path
    invalid_cert_path = '/path/to/invalid/certificates/'

    # Define the message to be sent to the server
    message = "Hello, server!"

    # Run the client with the invalid certificate path, server address, port, and message
    # The client should raise a FileNotFoundError
    with pytest.raises(FileNotFoundError) as excinfo:
        client.run(TEST_SERVER_IP, TEST_SERVER_PORT, invalid_cert_path, message)
    assert excinfo.value.arg[0] == "FileNotFoundError: [Errno 2] No such file or directory"


