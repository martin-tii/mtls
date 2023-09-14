import subprocess
import sys
import os

script_dir = os.path.dirname(__file__) # path to macsec directory
class Macsec:
    def __init__(self, role, key1, key2, mac_prim, mac_seco, interface='wlp1s0', status='up'):
        self.interface = interface
        self.status = status
        self.role = role
        self.key1 = key1
        self.key2 = key2
        self.mac_prim = mac_prim
        self.mac_seco = mac_seco
        self.macsec_encryption = "off" # Flag to set macsec encrypt on or off

    def run_macsec(self):
        try:
            # Replace 'run_macsec.sh' with the actual path to your bash script
            script_path = f'{script_dir}/setmacsec.sh'
            subprocess.run([script_path] + [self.interface, self.status, self.macsec_encryption, self.role, self.key1, self.key2, self.mac_prim, self.mac_seco], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error executing the script: {e}")
            sys.exit(1)