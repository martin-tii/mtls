import contextlib
import socket
import ssl
import logging
from datetime import datetime

# Constants
SERVER_PORT = 12345
CERT_PATH = '../../certificates/'  # Change this to the actual path of your certificates

# Logging configuration
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(message)s')


def create_server_socket(server_ip):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server_address = (server_ip, SERVER_PORT)

    server_socket.bind(server_address)
    server_socket.listen(1)

    return server_socket


def verify_cert(cert):
    # Perform custom certificate verification here
    # For example, you can check the certificate's expiration date, subject, issuer, etc.

    # Get the certificate expiration date
    expiration_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
    current_date = datetime.now()

    # Check if the certificate has expired
    if expiration_date < current_date:
        raise ValueError("Certificate has expired.")

    # Check if the certificate's common name (CN) matches the expected hostname or IP address
    common_name = cert['subject'][0][0][1]
    expected_hostname = 'client'  # Replace this with the expected hostname or IP address
    if common_name != expected_hostname:
        raise ValueError(f"Certificate common name '{common_name}' does not match the expected hostname.")

    # Check if the certificate is issued by a trusted CA
    issuer = cert['issuer'][0][0][1]
    trusted_ca = 'TII'  # Replace this with the trusted CA's distinguished name (DN)
    if issuer != trusted_ca:
        raise ValueError(f"Certificate issuer '{issuer}' is not a trusted CA.")

    # Optionally, you can check other certificate properties like the key usage, extended key usage, etc.

    # If the client certificate has passed all verifications, you can print or log a success message
    print("Certificate verification successful.")


def handle_client(connection):
    ssl_connection = None
    try:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(
            certfile=f'{CERT_PATH}/server.crt',
            keyfile=f'{CERT_PATH}/server.key',
        )

        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(f'{CERT_PATH}/ca.crt')

        # Uncomment to enable Certificate Revocation List (CRL) check
        # context.verify_flags = ssl.VERIFY_CRL_CHECK_LEAF

        ssl_connection = context.wrap_socket(connection, server_side=True, do_handshake_on_connect=True)

        cert = ssl_connection.getpeercert()
        verify_cert(cert)

        # Perform any desired communication with the client
        data = ssl_connection.recv(1024)
        logging.info(f"Received from client: {data.decode()}")

        ssl_connection.sendall(b"Hello, client! This is the server.")

    except ssl.SSLError as e:
        logging.error("SSL error:", exc_info=True)

    except ValueError as e:
        logging.error("Certificate verification failed:", exc_info=True)

    except socket.error as e:
        logging.error("Socket error:", exc_info=True)

    finally:
        if ssl_connection:
            with contextlib.suppress(socket.error):
                ssl_connection.shutdown(socket.SHUT_RDWR)
            ssl_connection.close()
            logging.info("Client connection closed.")


def main(server_ip):
    server_socket = create_server_socket(server_ip)

    try:
        logging.info("Server is running. Listening for connections...")
        while True:
            connection, client_address = server_socket.accept()
            logging.info(f"Connection from: {client_address}")
            handle_client(connection)
    except KeyboardInterrupt:
        logging.info("Server is shutting down.")
    finally:
        server_socket.close()


if __name__ == '__main__':
    main(server_ip='127.0.0.1')  # Replace 'your_server_ip' with your server's IP address
