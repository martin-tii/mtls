import subprocess
import sys
import os
import random
import threading

script_dir = os.path.dirname(__file__) # path to macsec directory
sys.path.insert(0, f'{script_dir}/../')
from tools.custom_logger import CustomLogger

logger_instance = CustomLogger("macsec")
class Macsec:
    '''
    from macsec.macsec import *
    mascec_obj = Macsec(my_macsec_key="1111111111111111111111111111111111111111111111111111111111111111")
    mascec_obj.set_macsec_tx()
    mascec_obj.set_macsec_rx(client_mac="04:f0:21:9e:6b:39",  client_macsec_key="1111111111111111111111111111111111111111111111111111111111111112")
    mascec_obj.set_macsec_rx(client_mac="04:f0:21:45:d5:29",  client_macsec_key="1111111111111111111111111111111111111111111111111111111111111113")
    '''
    def __init__(self, interface="wlp1s0", macsec_encryption="off"):
        self.interface = interface
        self.available_ports = set(range(1, 2**16)) # 1 to 2^16-1
        self.used_ports = {} # client_mac: port
        self.available_ports_lock = threading.Lock()
        #self.my_macsec_key = my_macsec_key
        self.macsec_encryption = macsec_encryption  # Flag to set macsec encrypt on or off
        self.logger = logger_instance.get_logger()

    def set_macsec_tx(self, client_mac, my_macsec_key, my_port):
        # Sets up macsec link and adds tx channel
        macsec_interface = self.get_macsec_interface_name(client_mac)
        try:
            subprocess.run(["ip", "link", "add", "link", self.interface, macsec_interface, "type", "macsec", "port", str(my_port), "encrypt", self.macsec_encryption, "cipher", "gcm-aes-256"], check=True)
            subprocess.run(["ip", "macsec", "add", macsec_interface, "tx", "sa", "0", "pn", "1", "on", "key", "01", my_macsec_key], check=True)
            subprocess.run(["ip", "link", "set", macsec_interface, "up"], check=True)
            subprocess.run(["ip", "macsec", "show"], check=True)
            self.logger.info(f'Macsec tx channel set with {client_mac}')
        except Exception as e:
            self.logger.error(f'Error setting up macsec tx channel: {e}')
            sys.exit(1)

    def set_macsec_rx(self, client_mac, client_macsec_key, client_port):
        # Adds a rx channel with client_mac, with key id = client mac without ":"
        macsec_interface = self.get_macsec_interface_name(client_mac)
        try:
            subprocess.run(["ip", "macsec", "add", macsec_interface, "rx", "port", str(client_port), "address", client_mac], check=True)
            subprocess.run(["ip", "macsec", "add", macsec_interface, "rx", "port", str(client_port), "address", client_mac, "sa", "0", "pn", "1", "on", "key", client_mac.replace(":", ""), client_macsec_key], check=True)
            subprocess.run(["ip", "macsec", "show"], check=True)
            self.logger.info(f'Macsec rx channel set with {client_mac}')
        except Exception as e:
            self.logger.error(f'Error setting up macsec with {client_mac}: {e}')

    def add_macsec_interface_to_batman(self, client_mac):
        # Add interface to batman
        macsec_interface = self.get_macsec_interface_name(client_mac)
        try:
            subprocess.run(["batctl", "if", "add", macsec_interface], check=True)
            self.logger.info(f'Added macsec interface for {client_mac} to batman')
        except Exception as e:
            self.logger.error(f'Error adding macsec interface for {client_mac} to batman: {e}')

    @staticmethod
    def get_macsec_interface_name(client_mac):
        return f"ms{client_mac.replace(':', '')}"


    def assign_unique_port(self, client_mac):
        with self.available_ports_lock:
            if client_mac in self.used_ports:
                return self.used_ports[client_mac]
            if not self.available_ports:
                raise ValueError("No available ports.")
            port = random.sample(list(self.available_ports), 1)[0]
            self.available_ports.remove(port)
            self.used_ports[client_mac] = port
            return port

    def release_port(self, client_mac):
        with self.available_ports_lock:
            if client_mac not in self.used_ports:
                raise ValueError(f"Client {client_mac} is not in the list of used ports.")
            self.available_ports.add(self.used_ports[client_mac])
            del self.used_ports[client_mac]