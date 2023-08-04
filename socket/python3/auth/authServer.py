import ssl
import socket
#from socket.python3.tools.verification_tools import *
import logging
import threading
from datetime import datetime
import sys
sys.path.insert(0, '../')
from tools.verification_tools import *
import glob

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

        # Create the SSL context here and set it as an instance variable
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        self.context.verify_mode = ssl.CERT_REQUIRED
        self.context.load_verify_locations(glob.glob(f'{self.CERT_PATH}/ca.crt')[0])
        self.context.load_cert_chain(
            certfile=glob.glob(f'{self.CERT_PATH}/csl*.crt')[0],
            keyfile=glob.glob(f'{self.CERT_PATH}/csl*.key')[0],
        )
        self.client_auth_results = {}


    def handle_client(self, secure_client_socket, client_address):
        try:
            # Obtain the certificate from the client
            client_cert = secure_client_socket.getpeercert()
            if not client_cert:
                logger.error("Unable to get the certificate from the client", exc_info=True)
                raise CertificateNoPresentError("Unable to get the certificate from the client")

            auth = verify_cert(client_cert, "client", logger)

            # Send current server time to the client
            serverTimeNow = f"{datetime.now()}"
            secure_client_socket.send(serverTimeNow.encode())
            logger.info(f"Securely sent {serverTimeNow} to {client_address}")
            # Store the auth result in the instance variable
            self.client_auth_results[client_address] = auth

        finally:
            # Close the connection to the client
            secure_client_socket.close()

    def get_client_auth_result(self, client_address):
        return self.client_auth_results.get(client_address, None)

    def start_server(self):
        # Create a server socket
        serverSocket = socket.socket()
        serverSocket.bind((self.ipAddress, self.port))

        # Listen for incoming connections
        serverSocket.listen()
        logger.info("Server listening")

        while True:
            # Keep accepting connections from clients
            (client_connection, client_address) = serverSocket.accept()

            # Make the socket connection to the clients secure through SSLSocket
            secure_client_socket = self.context.wrap_socket(client_connection, server_side=True)

            # Start a new thread to handle the client
            client_thread = threading.Thread(target=self.handle_client, args=(secure_client_socket, client_address))
            client_thread.start()

if __name__ == "__main__":
    # IP address and the port number of the server
    ipAddress = "127.0.0.1"
    port = 15001
    CERT_PATH = '../../../certificates'  # Change this to the actual path of your certificates

    auth_server = AuthServer(ipAddress, port, CERT_PATH)
    auth_server.start_server()

    # Access the authentication result for a specific client
    client_address = ("127.0.0.1", 12345)  # Replace with the actual client address you want to check
    auth_result = auth_server.get_client_auth_result(client_address)
    print(f"Authentication result for {client_address}: {auth_result}")
