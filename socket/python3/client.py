import contextlib
import socket
import ssl
import sys
import logging

# Constants
SERVER_PORT = 12345

# Logging configuration
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(message)s')


def create_client_socket(server_ip):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_address = (server_ip, SERVER_PORT)

    client_socket.connect(server_address)

    return client_socket


def main(server_ip):
    client_socket = create_client_socket(server_ip)
    ssl_socket = None

    try:
        # Wrap the socket in an SSL context with client-side certificate and key
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.load_cert_chain(
            certfile=f'{cert_path}/client.crt',
            keyfile=f'{cert_path}/client.key',
        )

        # Set mTLS options
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(f'{cert_path}/ca.crt')

        # Wrap the socket in an SSL socket
        ssl_socket = context.wrap_socket(client_socket, server_hostname="server")

        # Send a message to the server
        ssl_socket.sendall(b"Hello, server! This is the client.")

        # Receive the response from the server
        response = ssl_socket.recv(1024)
        logging.info(f"Received from server: {response.decode()}")

    except ssl.SSLError as e:
        logging.error("SSL error:", exc_info=True)

    except ConnectionRefusedError:
        logging.error("Connection refused: Please check if the server is running and reachable.")

    except Exception:
        logging.error("Error connecting to server:", exc_info=True)

    finally:
        if ssl_socket:
            with contextlib.suppress(socket.error):
                ssl_socket.shutdown(socket.SHUT_RDWR)
            ssl_socket.close()
            logging.info("SSL socket closed.")
        client_socket.close()


if __name__ == '__main__':
    cert_path = '../../certificates/'  # Change this to the actual path of your certificates
    server_ip = sys.argv[1] if len(
        sys.argv) > 1 else '127.0.0.1'  # Get the server IP from command line or use 'your_server_ip'
    main(server_ip)
