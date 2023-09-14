import queue
import ssl
import socket
from tools.custom_logger import CustomLogger

logger_instance = CustomLogger("SecChannel")


class SecMessageHandler:
    def __init__(self, socket):
        self.socket = socket
        self.logger = logger_instance.get_logger()
        self.callback = None

    def set_callback(self, callback):
        """Set the callback function to be executed when a message is received."""
        self.callback = callback

    def _is_socket_active(self):
        """Check if the socket is active."""
        try:
            # Just a simple check; will rely on recv() in receive_message() for more detailed check.
            return self.socket.fileno() != -1
        except socket.error:
            return False

    def _is_ssl_socket(self):
        return isinstance(self.socket, ssl.SSLSocket)

    def send_message(self, message):
        """Send a message through the socket."""
        if not self._is_ssl_socket():
            self.logger.error("Socket is not SSL enabled.")
            return

        if not self._is_socket_active():
            self.logger.error("Socket is not active.")
            return

        try:
            self.socket.send(message.encode())
            self.logger.info(f"Sent: {message}")
        except Exception as e:
            self.logger.error("Error sending message.", exc_info=True)

    def receive_message(self, macsec_key_q=queue.Queue()):
        """Continuously receive messages from the socket."""
        if not self._is_ssl_socket():
            self.logger.error("Socket is not SSL enabled.")
            return
        try:
            while True:
                # No need to check _is_socket_active here, rely on recv's result.
                data = self.socket.recv(1024).decode()
                if not data:
                    self.logger.warning("Connection closed or socket not active.")
                    break
                elif data == "GOODBYE": # trigger to close it
                    self.logger.info("Other end signaled end of communication.")
                    break
                else:
                    self.logger.info(f"Received: {data}")
                    if self.callback:
                        self.callback(data)  # Execute the callback with the received data
                    if "macsec_key_" in data: # if received data is the macsec key, put it in queue
                        macsec_key = data.split('macsec_key_')[1]
                        macsec_key_q.put(macsec_key)

        except socket.timeout:
            self.logger.warning("Connection timed out. Ending communication.")
        except Exception as e:
            self.logger.error("Error receiving message.", exc_info=True)