import psutil
import subprocess
import configparser
import sys


def is_wpa_supplicant_running():
    return any(
        proc.info['name'] == 'wpa_supplicant'
        for proc in psutil.process_iter(['pid', 'name'])
    )

def run_wpa_supplicant(wifidev):
    '''
     maybe this should be executed from the mesh-11s.sh
     but we will need to modify the batmat part
    '''
    conf_file = "/var/run/wpa_supplicant-11s.conf"
    log_file = "/tmp/wpa_supplicant_11s.log"

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
        subprocess.run(command, check=True)
        print("wpa_supplicant process started successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error starting wpa_supplicant process: {e}")

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


# TODO Rename this here and in `run_batman_adv_commands`
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


    line = f"{modified_mac_address[:6]}fffe{modified_mac_address[6:]}"

    # Add "ff:fe:" to the middle of the new MAC address
#    mac_with_fffe = ":".join(a + b for a, b in zip(a[::2], a[1::2]))
    mac_with_fffe = ":".join([line[i:i+4] for i in range(0, len(line), 4)])

    return f"fe80::{mac_with_fffe}"


def get_mac_addr(EXPECTED_INTERFACE):
    '''
    got it from common/tools/field_test_logger/wifi_info.py
    '''
    try:
        with open(f"/sys/class/net/{EXPECTED_INTERFACE}/address", 'r') as f:
            value = f.readline()
            return value.strip()
    except:
        return "NaN"


