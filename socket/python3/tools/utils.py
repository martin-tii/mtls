import subprocess
import configparser
import sys
import os
import time
import shutil
import queue
import socket
import ipaddress
from .custom_logger import CustomLogger

logger_instance = CustomLogger("utils")
logger = logger_instance.get_logger()

class UniqueQueue:
    def __init__(self):
        self._queue = queue.Queue()
        self._seen = set()

    def put(self, item):
        if item not in self._seen:
            self._queue.put(item)
            self._seen.add(item)

    def get(self, *args, **kwargs):
        item = self._queue.get(*args, **kwargs)
        self._seen.remove(item)
        return item

    def empty(self):
        return self._queue.empty()


def is_wpa_supplicant_running():
    try:
        # Running the command and decoding the output
        output = subprocess.check_output(['ps', 'ax']).decode('utf-8')
        # Check for wpa_supplicant in the output
        processes = [line for line in output.splitlines() if 'wpa_supplicant' in line]
        # Filter out any lines containing 'grep'
        processes = [proc for proc in processes if 'grep' not in proc]
        return len(processes) > 0
    except Exception as e:
        # Handle exceptions based on your requirements
        return False


def run_wpa_supplicant(wifidev):
    '''
     maybe this should be executed from the mesh-11s.sh
     but we will need to modify the batmat part
    '''
    conf_file = "/var/run/wpa_supplicant-11s.conf"
    log_file = "/tmp/wpa_supplicant_11s.log"
    shutil.copy("tools/wpa_supplicant-11s.conf", conf_file) # this is only for testing

    # Build the command with all the arguments
    command = [
        "wpa_supplicant",
        "-i", wifidev,
        "-c", conf_file,
        "-D", "nl80211",
        "-C", "/var/run/wpa_supplicant/",
        "-B",
        "-f", log_file
    ]

    try:
        # Run the wpa_supplicant command as a subprocess
        result = subprocess.run(command, check=True)
        if result.returncode != 0:
            logger.info(f"Error executing command: {result.args}. Return code: {result.returncode}")
        else:
            logger.info("wpa_supplicant process started successfully.")
    except subprocess.CalledProcessError as e:
        logger.info(f"Error starting wpa_supplicant process: {e}")

def mesh_service():
    # Check if mesh provisioning is done
    # we are assuming that the file exists on /opt/mesh.conf
    if os.path.exists("/opt/S9011sMesh"):
        # Start Mesh service
        try:
            logger.info("starting 11s mesh service")
            result = subprocess.run(["/opt/S9011sMesh", "start"], check=True, capture_output=True, text=True)
            time.sleep(2)
        except subprocess.CalledProcessError as e:
            logger.info(f"Error executing command: {e.cmd}. Return code: {e.returncode}")
            logger.info(f"Error output: {e.stderr}")

# Call the function


def killall(interface):
    try:
        # Kill wpa_supplicant
        result = subprocess.run(['killall', 'wpa_supplicant'], capture_output=True, text=True)
        if result.returncode != 0:
            if "no process killed" in result.stderr:
                print("wpa_supplicant process was not running.")
            else:
                print(f"Error executing command: {result.args}. Return code: {result.returncode}")

        # Bring the interface down
        subprocess.run(['ifconfig', interface, 'down'], check=True)

        # Bring the interface back up
        subprocess.run(['ifconfig', interface, 'up'], check=True)

    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e.cmd}. Return code: {e.returncode}")

def apply_nft_rules(rules_file="firewall.nft"):
    try:
        # Run the nft command to apply the rules from the specified file
        subprocess.run(['nft', '-f', rules_file], check=True)
        print("nftables rules applied successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error applying nftables rules: {e}")


def modify_conf_file(conf_file_path, new_values):
    config = configparser.ConfigParser()
    config.read(conf_file_path)

    for section, options in new_values.items():
        for option, value in options.items():
            config.set(section, option, value)

    with open(conf_file_path, 'w') as configfile:
        config.write(configfile)


def set_macsec(role, mesh_iface, key1, key2, mac_server, mac_client):
    conf_file_path = "../macsec/variables.conf"
    new_values = {
        'DEFAULT': {
            'INTERFACE': mesh_iface,
            'STATUS': 'up',
            'ROLE': role,
            'KEY1': key1,
            'KEY2': key2,
            'MACPRIM': mac_server,
            'MACSECO': mac_client
        }
    }

    modify_conf_file(conf_file_path, new_values)


def run_macsec(args):
    try:
        # Replace 'run_macsec.sh' with the actual path to your bash script
        script_path = './run_macsec.sh'
        subprocess.run([script_path] + args, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error executing the script: {e}")
        sys.exit(1)

def batman_exec(routing_algo, wifidev, ip_address, netmask):
    if routing_algo != "batman-adv":
        #TODO here should be OLSR
        return
    try:
        run_batman(wifidev, ip_address, netmask)
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")


def run_batman(wifidev, ip_address, netmask):
    # Run the batctl if add command
    subprocess.run(["batctl", "if", "add", wifidev], check=True)

    print("bat0 up..")
    # Run the ifconfig bat0 up command
    subprocess.run(["ifconfig", "bat0", "up"], check=True)

    print("bat0 ip address..")
    # Run the ifconfig bat0 <ip_address> netmask <netmask> command
    subprocess.run(["ifconfig", "bat0", ip_address, "netmask", netmask], check=True)

    print("bat0 mtu size")
    # Run the ifconfig bat0 mtu 1460 command
    subprocess.run(["ifconfig", "bat0", "mtu", "1460"], check=True)

    print()
    # Run the ifconfig bat0 command to show the interface information
    subprocess.run(["ifconfig", "bat0"], check=True)
            # Handle the error if any of the commands fail


def mac_to_ipv6(mac_address):
    # Remove any separators from the MAC address (e.g., colons, hyphens)
    mac_address = mac_address.replace(":", "").replace("-", "").lower()

    # Split the MAC address into two equal halves
    first_half = mac_address[:6]

    # Convert the first octet from hexadecimal to binary
    binary_first_octet = bin(int(first_half[:2], 16))[2:].zfill(8)


    # Invert the seventh bit (change 0 to 1 or 1 to 0)
    inverted_seventh_bit = "1" if binary_first_octet[6] == "0" else "0"


    # Convert the modified binary back to hexadecimal
    modified_first_octet = hex(int(binary_first_octet[:6] + inverted_seventh_bit + binary_first_octet[7:], 2))[2:]


    # Replace the original first octet with the modified one
    modified_mac_address = modified_first_octet + mac_address[2:]


    line = f"{modified_mac_address[:5]}fffe{modified_mac_address[5:]}"

    # Add "ff:fe:" to the middle of the new MAC address
#    mac_with_fffe = ":".join(a + b for a, b in zip(a[::2], a[1::2]))
    mac_with_fffe = ":".join([line[:3], line[3:7], line[7:11], line[11:]])

    return f"fe80::{mac_with_fffe}"


def extract_mac_from_ipv6(ipv6_address): #assuming link local address
    # Parse and expand the IPv6 address to its full form
    full_ipv6_address = ipaddress.IPv6Address(ipv6_address).exploded

    # Extract the EUI-64 identifier from the IPv6 address
    eui_64_parts = full_ipv6_address.split(":")[4:8]

    # Join them together into a single hex string
    eui_64_hex = "".join(eui_64_parts)

    # Separate the bytes that make up the EUI-64 identifier
    eui_64_bytes = bytes.fromhex(eui_64_hex)

    # Extract the MAC address from the EUI-64 identifier
    mac_bytes = bytearray(6)
    mac_bytes[0] = eui_64_bytes[0] ^ 0x02  # Flip the universal/local bit
    mac_bytes[1:3] = eui_64_bytes[1:3]
    mac_bytes[3:5] = eui_64_bytes[5:7]
    mac_bytes[5] = eui_64_bytes[7]

    return ":".join(f"{byte:02x}" for byte in mac_bytes)


def get_mac_addr(EXPECTED_INTERFACE):
    """
    got it from common/tools/field_test_logger/wifi_info.py
    """
    try:
        with open(f"/sys/class/net/{EXPECTED_INTERFACE}/address", 'r') as f:
            value = f.readline()
            return value.strip()
    except Exception:
        return "NaN"


def set_ipv6(interface, ipv6):
    command = ["ip", "-6", "addr", "add", f"{ipv6}/64", "dev", interface]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Command failed with error: {e.stderr}")

def is_ipv4(ip):
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except socket.error:
        return False

def is_ipv6(ip):
    try:
        socket.inet_pton(socket.AF_INET6, ip)
        return True
    except socket.error:
        return False

def generate_session_key():
    rand = os.urandom(32)
    return int.from_bytes(rand, 'big')