import os
import logging
import sys
import contextlib
#from socket.python3.tools.wpactrl import WpaCtrl
from tools.wpactrl import WpaCtrl
import time

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


def create_wpa_ctrl_instance(ctrl_path):
    waiting_message_printed = False

    while not os.path.exists(ctrl_path):
        if not waiting_message_printed:
            logger.info("Waiting for the wpa_supplicant control interface file to be created...")
            waiting_message_printed = True

        time.sleep(1)

    return WpaCtrl(ctrl_path)

def process_events(ctrl, queue):
     with contextlib.suppress(KeyboardInterrupt):
        while True:
            if ctrl.pending():
                response = ctrl.recv()
                decoded_response = response.decode().strip()

                # Check for the MESH-PEER-CONNECTED event
                if "MESH-PEER-CONNECTED" in decoded_response:
                    mac_address = decoded_response.split()[-1]
                    event = f"MESH-PEER-CONNECTED {mac_address}"
                    logger.info(event)
                    queue.put(mac_address)

                # Check for the MESH-PEER-DISCONNECTED event
                if "MESH-PEER-DISCONNECTED" in decoded_response:
                    mac_address = decoded_response.split()[-1]
                    event = f"MESH-PEER-DISCONNECTED {mac_address}"
                    logger.info(event)

                #print("<", decoded_response)
