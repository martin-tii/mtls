import socket
import ssl
import sys
from verification_tools import *
import logging

ROLE="Client"


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



class AuthClient:
    def __init__(self, server_ip, server_port, cert_path):
        self.sslServerIP = server_ip
        self.sslServerPort = server_port
        self.CERT_PATH = cert_path

    def establish_connection(self):
        # Create an SSL context
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        context.verify_mode = ssl.CERT_REQUIRED

        # Uncomment to enable Certificate Revocation List (CRL) check
        # context.verify_flags = ssl.VERIFY_CRL_CHECK_LEAF

        # Load CA certificate with which the client will validate the server certificate
        context.load_verify_locations(f'{self.CERT_PATH}/ca.crt')

        # Load client certificate and key
        context.load_cert_chain(certfile=f'{self.CERT_PATH}/client.crt', keyfile=f'{self.CERT_PATH}/client.key')

        # Create a client socket
        clientSocket = socket.socket()

        # Make the client socket suitable for secure communication
        secureClientSocket = context.wrap_socket(clientSocket)

        try:
            self.connection(secureClientSocket)
        finally:
            # Close the socket
            secureClientSocket.close()

    def connection(self, secureClientSocket):
        # Connect to the server
        secureClientSocket.connect((self.sslServerIP, self.sslServerPort))

        # Obtain the server certificate
        server_cert = secureClientSocket.getpeercert()
        if not server_cert:
            logger.error("Unable to get the server certificate", exc_info=True)
            raise CertificateNoPresentError("Unable to get the server certificate")

        verify_cert(server_cert, "server", logger)

        # Safe to proceed with the communication
        msgReceived = secureClientSocket.recv(1024)
        logger.info(f"Secure communication received from server: {msgReceived.decode()}")

if __name__ == "__main__":
    # IP address and the port number of the server
    sslServerIP = "127.0.0.1"
    sslServerPort = 15001
    CERT_PATH = '../../certificates'  # Change this to the actual path of your certificates

    auth_client = AuthClient(sslServerIP, sslServerPort, CERT_PATH)
    auth_client.establish_connection()
