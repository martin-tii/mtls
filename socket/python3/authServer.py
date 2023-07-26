import ssl
import socket
from verification_tools import *

# Logging configuration
logging.basicConfig(filename='authServer.log', encoding='utf-8', level=logging.INFO, format='[%(asctime)s] %(message)s')

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
        print("Server listening:")

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
                    logging.error("Unable to get the certificate from the client", exc_info=True)
                    raise CertificateNoPresentError("Unable to get the certificate from the client")

                verify_cert(client_cert, "client")

                # Send current server time to the client
                serverTimeNow = f"{datetime.now()}"
                secureClientSocket.send(serverTimeNow.encode())
                print(f"Securely sent {serverTimeNow} to {clientAddress}")
                logging.info(f"Securely sent {serverTimeNow} to {clientAddress}")

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
