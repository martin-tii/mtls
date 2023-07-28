'''
the supplicant must be run as
wpa_supplicant -i wlp1s0 -c wpa_supplicant-11s.conf -B -f /tmp/wpa_supplicant.log
'''

import pyinotify
import threading
import logging
import time
import contextlib
import sys

# Create a custom logger
ROLE = "wpa_monitor"
logger = logging.getLogger(f"{ROLE}")
logger.setLevel(logging.INFO)

# Create file handler
file_handler = logging.FileHandler(f'{ROLE}.log', encoding='utf-8')
file_handler.setLevel(logging.INFO)

# Create console handler
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)

# Create a formatter
formatter = logging.Formatter(f'[%(asctime)s] [{ROLE}] %(levelname)s %(message)s')
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

# Add the handlers to the logger
logger.addHandler(file_handler)
logger.addHandler(console_handler)


class LogEventHandler(pyinotify.ProcessEvent):
    def __init__(self, *args, **kwargs):
        super(LogEventHandler, self).__init__(*args, **kwargs)
        self.peer_connected_mac = kwargs.get('peer_connected_mac', {})
        self.processed_macs = set()  # Set to store already processed MAC addresses

    def process_IN_MODIFY(self, event):
        if "wpa_supplicant.log" in event.pathname:
            self.parse_log_file(event.pathname)

    def parse_log_file(self, log_file_path):
        with open(log_file_path, 'r') as log_file:
            for line in log_file:
                if "MESH-PEER-CONNECTED" in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        interface = parts[0].rstrip(':')  # Removing the trailing colon from the interface name
                        mac_address = parts[2]
                        self.peer_connected_mac[interface] = mac_address

                        # Use the custom logger to print the MAC address and log it to the file
                        if mac_address not in self.processed_macs:
                            logger.info(f"New MAC address detected on interface {interface}: {mac_address}")
                            self.processed_macs.add(mac_address)

class LogMonitoringThread(threading.Thread):
    def __init__(self, log_file_path, peer_connected_mac):
        super(LogMonitoringThread, self).__init__()
        self.log_file_path = log_file_path
        self.peer_connected_mac = peer_connected_mac

    def run(self):
        handler = LogEventHandler(peer_connected_mac=self.peer_connected_mac)
        wm = pyinotify.WatchManager()
        notifier = pyinotify.Notifier(wm, handler)
        wm.add_watch(self.log_file_path, pyinotify.IN_MODIFY)

        logger.info("Monitoring the log file in the monitoring thread.")
        notifier.loop()

def main():
    log_file_path = "/tmp/"
    peer_connected_mac = {}

    monitoring_thread = LogMonitoringThread(log_file_path, peer_connected_mac)
    monitoring_thread.start()

    try:
        with contextlib.suppress(KeyboardInterrupt):
            while True:
                # Sleep for a short interval to allow time for the monitoring thread to update the dictionary
                time.sleep(1)

    except KeyboardInterrupt:
        pass

    logger.info("Stopping the monitoring thread.")
    monitoring_thread.join()

if __name__ == "__main__":
    main()
