import socket
import ssl

def create_client_socket(server_ip, server_port):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_address = (server_ip, server_port)

    client_socket.connect(server_address)

    return client_socket

def send_message(ssl_socket, message):
    ssl_socket.sendall(message.encode())

def receive_response(ssl_socket):
    return ssl_socket.recv(1024).decode()

def main(server_ip, server_port, cert_path, message):
    client_socket = create_client_socket(server_ip, server_port)
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

        send_message(ssl_socket, message)
        response = receive_response(ssl_socket)
        print(f"Received from server: {response}")

    except ssl.SSLError as e:
        print("SSL error:", e)

    except Exception as e:
        print("Error connecting to server:", e)

    finally:
        if ssl_socket:
            ssl_socket.close()
        client_socket.close()
