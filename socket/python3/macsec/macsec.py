import subprocess
import sys
import os

script_dir = os.path.dirname(__file__) # path to macsec directory
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
    def __init__(self, my_macsec_key, interface="wlp1s0", macsec_encryption="off"):
        self.interface = interface
        self.my_macsec_key = my_macsec_key
        self.macsec_encryption = macsec_encryption  # Flag to set macsec encrypt on or off
        self.logger = logger_instance.get_logger()

    def set_macsec_tx(self):
        # Sets up macsec link and adds tx channel
        try:
            subprocess.run(["ip", "link", "set", self.interface, "up"], check=True)
            subprocess.run(["ip", "link", "add", "link", self.interface, "macsec0", "type", "macsec", "encrypt", self.macsec_encryption, "cipher", "gcm-aes-256"], check=True)
            subprocess.run(["ip", "macsec", "add", "macsec0", "tx", "sa", "0", "pn", "1", "on", "key", "01", self.my_macsec_key], check=True)
            subprocess.run(["ip", "link", "set", "macsec0", "up"], check=True)
            subprocess.run(["ip", "macsec", "show"], check=True)
            self.logger.info('Macsec tx channel set')
        except Exception as e:
            self.logger.error(f'Error setting up macsec tx channel: {e}')
            sys.exit(1)

    def set_macsec_rx(self, client_mac, client_macsec_key):
        # Adds a rx channel with client_mac, with key id = client mac without ":"
        try:
            subprocess.run(["ip", "macsec", "add", "macsec0", "rx", "port", "1", "address", client_mac], check=True)
            subprocess.run(["ip", "macsec", "add", "macsec0", "rx", "port", "1", "address", client_mac, "sa", "0", "pn", "1", "on", "key", client_mac.replace(":", ""), client_macsec_key], check=True)
            subprocess.run(["ip", "macsec", "show"], check=True)
            self.logger.info(f'Macsec rx channel set with {client_mac}')
        except Exception as e:
            self.logger.error(f'Error setting up macsec with {client_mac}: {e}')