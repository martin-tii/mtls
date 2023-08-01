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