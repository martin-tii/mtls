import socket
import ssl
import sys
sys.path.insert(0, '../')
from tools.verification_tools import *
from tools.custom_logger import CustomLogger
from tools.utils import mac_to_ipv6
import glob
import random
import time

MAX_RETRIES = 5
MIN_WAIT_TIME = 1  # seconds
MAX_WAIT_TIME = 3  # seconds




class AuthClient:
    def __init__(self, server_mac, server_port, cert_path):
        self.sslServerIP = mac_to_ipv6(server_mac)
        self.sslServerPort = server_port
        self.CERT_PATH = cert_path
        self.interface = "wlp1s0"
        self.secure_client_socket = None
        self.logger = self._setup_logger()

    @staticmethod
    def _setup_logger():
        logger_instance = CustomLogger("authClient")
        return logger_instance.get_logger()

    def establish_connection(self):
        # Create an SSL context
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        context.verify_mode = ssl.CERT_REQUIRED

        # Uncomment to enable Certificate Revocation List (CRL) check
        # context.verify_flags = ssl.VERIFY_CRL_CHECK_LEAF

        context.load_verify_locations(glob.glob(f'{self.CERT_PATH}/ca.crt')[0])
        context.load_cert_chain(
            certfile=glob.glob(f'{self.CERT_PATH}/csl*.crt')[0],
            keyfile=glob.glob(f'{self.CERT_PATH}/csl*.key')[0],
        )

        # Detect if the server IP is IPv4 or IPv6 and create a socket accordingly
        if ":" in self.sslServerIP:
            clientSocket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        else:
            clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Make the client socket suitable for secure communication
        self.secure_client_socket = context.wrap_socket(clientSocket)
        try:
            result = self.connection(self.secure_client_socket)
            if result['authenticated']:
                return result
        except Exception as e:
            self.logger.error("Define better this exception.", exc_info=True)
        # finally:
        #     # Close the socket
        #     secureClientSocket.close()

    def connection(self, secureClientSocket):
        result = {
            'IP': self.sslServerIP,
            'authenticated': False
        }

        try:
            self.to_validate(secureClientSocket, result)
        except Exception as e:
            self.logger.error("An error occurred during the connection process.", exc_info=True)

        finally:
            return result

    def to_validate(self, secureClientSocket, result):
        # If the IP is a link-local IPv6 address, connect it with the interface index
        retries = 0
        while retries < MAX_RETRIES:
            try:
                if self.sslServerIP.startswith("fe80"):
                    secureClientSocket.connect(
                        (self.sslServerIP, self.sslServerPort, 0, socket.if_nametoindex(self.interface)))
                else:
                    secureClientSocket.connect((self.sslServerIP, self.sslServerPort))
                break  # break out of loop if connection is successful
            except ConnectionRefusedError:
                retries += 1
                if retries < MAX_RETRIES:
                    wait_time = random.uniform(MIN_WAIT_TIME, MAX_WAIT_TIME)
                    self.logger.info(f"Connection refused. Retrying in {wait_time:.2f} seconds...")
                    time.sleep(wait_time)
                else:
                    self.logger.error("Exceeded maximum retry attempts. Unable to connect to server.")
                    raise

        server_cert = secureClientSocket.getpeercert(binary_form=True)
        if not server_cert:
            self.logger.error("Unable to get the server certificate", exc_info=True)
            raise CertificateNoPresentError("Unable to get the server certificate")

        result['authenticated'] = verify_cert(server_cert, self.logger)

        # # Safe to proceed with the communication, even if the certificate is not authenticated
        # msgReceived = secureClientSocket.recv(1024)
        # logger.info(f"Secure communication received from server: {msgReceived.decode()}")


if __name__ == "__main__":
    # IP address and the port number of the server
    sslServerIP = "127.0.0.1"
    sslServerPort = 15001
    CERT_PATH = '../../../certificates'  # Change this to the actual path of your certificates

    auth_client = AuthClient(sslServerIP, sslServerPort, CERT_PATH)
    auth_client.establish_connection()



