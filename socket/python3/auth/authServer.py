import socket
import ssl
import threading
from tools.utils import is_ipv4, is_ipv6
import sys

sys.path.insert(0, '../')
from tools.verification_tools import *
from tools.custom_logger import CustomLogger
import glob

logger_instance = CustomLogger("Server")
logger = logger_instance.get_logger()


class AuthServer:
    def __init__(self, ip_address, port, cert_path):
        threading.Thread.__init__(self)
        self.running = True
        self.ipAddress = ip_address
        self.port = port
        self.CERT_PATH = cert_path
        self.ca = f'{self.CERT_PATH}/ca.crt'
        self.interface = "wlp1s0"
        # Create the SSL context here and set it as an instance variable
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        self.context.verify_mode = ssl.CERT_REQUIRED
        self.context.load_verify_locations(glob.glob(self.ca)[0])
        self.context.load_cert_chain(
            certfile=glob.glob(f'{self.CERT_PATH}/macsec*.crt')[0],
            keyfile=glob.glob(f'{self.CERT_PATH}/macsec*.key')[0],
        )
        self.client_auth_results = {}
        self.active_sockets = {}

    def handle_client(self, secure_client_socket, client_address):
        try:
            client_cert = secure_client_socket.getpeercert(binary_form=True)
            if not client_cert:
                logger.error("Unable to get the certificate from the client", exc_info=True)
                raise CertificateNoPresentError("Unable to get the certificate from the client")

            auth = verify_cert(client_cert, self.ca, client_address[0], logger)
            self.client_auth_results[client_address[0]] = auth
            if auth:
                self.active_sockets[client_address[0]] = secure_client_socket
            else:
                # Handle the case when authentication fails, maybe send an error message
                secure_client_socket.send(b"Authentication failed.")
        except Exception as e:
            logger.error("An error occurred while handling the client.", exc_info=True)
        # finally:
        #     secure_client_socket.close()

    def get_secure_socket(self, client_address):
        return self.active_sockets.get(client_address)

    def get_client_auth_result(self, client_address):
        return self.client_auth_results.get(client_address, None)

    def start_server(self):
        if is_ipv4(self.ipAddress):
            self.serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.serverSocket.bind((self.ipAddress, self.port))
        elif is_ipv6(self.ipAddress):
            self.serverSocket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            scope_id = socket.if_nametoindex(self.interface)
            self.serverSocket.bind((self.ipAddress, int(self.port), 0, scope_id))
        else:
            raise ValueError("Invalid IP address")

        self.serverSocket.listen()
        self.serverSocket.settimeout(60)  # timeout of 60 seconds
        logger.info("Server listening")

        while self.running:
            try:
                client_connection, client_address = self.serverSocket.accept()
                secure_client_socket = self.context.wrap_socket(client_connection, server_side=True)
                threading.Thread(target=self.handle_client, args=(secure_client_socket, client_address)).start()
            except socket.timeout:  # In case we add a timeout later.
                continue
            except Exception as e:
                if self.running:
                    logger.error("Unexpected error in server loop.", exc_info=True)

    def stop_server(self):
        self.running = False
        if is_ipv4(self.ipAddress):
            serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            serverSocket.bind((self.ipAddress, self.port))
        elif is_ipv6(self.ipAddress):
            serverSocket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            scope_id = socket.if_nametoindex(self.interface)
            serverSocket.bind((self.ipAddress, int(self.port), 0, scope_id))
        if hasattr(self, "serverSocket"):
            self.serverSocket.close()
            for sock in auth_server.active_sockets.values():
                sock.close()


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
