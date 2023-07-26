import ssl
import socket
from verification_tools import *
import sys
import logging

ROLE="Server"

# Create a custom logger
logger = logging.getLogger(f"Auth{ROLE}")
logger.setLevel(logging.INFO)

# Create file handler
file_handler = logging.FileHandler(f'auth{ROLE}.log', encoding='utf-8')
file_handler.setLevel(logging.INFO)

# Create console handler
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)

# Create a formatter
formatter = logging.Formatter(
    f'[%(asctime)s] [{ROLE}] %(levelname)s %(message)s'
)
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

# Add the handlers to the logger
logger.addHandler(file_handler)
logger.addHandler(console_handler)


class AuthServer:
    def __init__(self, ip_address, port, cert_path):
        self.ipAddress = ip_address
        self.port = port
        self.CERT_PATH = cert_path

    def start_server(self):
        # Create a server socket
        serverSocket = socket.socket()
        serverSocket.bind((self.ipAddress, self.port))

        # Listen for incoming connections
        serverSocket.listen()
        logger.info("Server listening")

        # Create an SSL context
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        context.verify_mode = ssl.CERT_REQUIRED

        # Uncomment to enable Certificate Revocation List (CRL) check
        # context.verify_flags = ssl.VERIFY_CRL_CHECK_LEAF

        # Load CA certificate with which the server will validate the client certificate
        context.load_verify_locations(f'{self.CERT_PATH}/ca.crt')

        # Load server certificate and key
        context.load_cert_chain(certfile=f'{self.CERT_PATH}/server.crt', keyfile=f'{self.CERT_PATH}/server.key')

        while True:
            # Keep accepting connections from clients
            (clientConnection, clientAddress) = serverSocket.accept()

            # Make the socket connection to the clients secure through SSLSocket
            secureClientSocket = context.wrap_socket(clientConnection, server_side=True)

            try:
                # Obtain the certificate from the client
                client_cert = secureClientSocket.getpeercert()
                if not client_cert:
                    logger.error("Unable to get the certificate from the client", exc_info=True)
                    raise CertificateNoPresentError("Unable to get the certificate from the client")

                verify_cert(client_cert, "client", logger)

                # Send current server time to the client
                serverTimeNow = f"{datetime.now()}"
                secureClientSocket.send(serverTimeNow.encode())
                logger.info(f"Securely sent {serverTimeNow} to {clientAddress}")

            finally:
                # Close the connection to the client
                secureClientSocket.close()

if __name__ == "__main__":
    # IP address and the port number of the server
    ipAddress = "127.0.0.1"
    port = 15001
    CERT_PATH = '../../certificates'  # Change this to the actual path of your certificates

    auth_server = AuthServer(ipAddress, port, CERT_PATH)
    auth_server.start_server()