from auth.authServer import AuthServer
from auth.authClient import AuthClient
import threading
from multicast.multicast import MulticastHandler
from tools.monitoring_wpa import *
from tools.custom_logger import CustomLogger
from tools.utils import *
from macsec import macsec
import queue
import random
import json
from secure_channel.secchannel import SecMessageHandler
BEACON_TIME = 10
MAX_CONSECUTIVE_NOT_RECEIVED = 2
MULTICAST_ADDRESS = 'ff02::1'
TIMEOUT = 3 * BEACON_TIME


class mutAuth():
    def __init__(self, in_queue, out_queue, shutdown_event):
        self.meshiface = "wlp1s0"
        self.mymac = get_mac_addr(self.meshiface)
        self.ipAddress = mac_to_ipv6(self.mymac)
        self.port = 15001
        self.CERT_PATH = 'cert_generation/certificates'  # Change this to the actual path of your certificates
        self.server = False
        self.server_event = threading.Event()
        self.wpa_supplicant_ctrl_path = f"/var/run/wpa_supplicant/{self.meshiface}"
        self.message_received = False
        self.in_queue = in_queue
        self.out_queue = out_queue
        self.logger = self._setup_logger()
        self.multicast_handler = MulticastHandler(self.in_queue, MULTICAST_ADDRESS, self.port)
        self.stop_event = threading.Event()
        self.sender_thread = threading.Thread(target=self._periodic_sender, args=(self.stop_event,))
        self.shutdown_event = shutdown_event  # Add this to handle graceful shutdown
        self.macs_in_queue = set()  # A set to keep track of MACs in the queue.
        self.server_lock = threading.Lock()  # Lock for thread-safe access to `self.server`
        self.is_server_running = False  # Initial value
        self.macsec_lower = macsec.Macsec(level="lower", interface="wlp1s0", macsec_encryption="off")  # Initialize lower macsec object
        self.connected_peers_status = {} # key = client mac address, value = [status : ("ongoing", "authenticated", "not connected"), no of failed attempts]}
        self.connected_peers_status_lock = threading.Lock()
        self.maximum_num_failed_attempts = 3 # Maximum number of failed attempts for mutual authentication (can be changed)
        self.lower_batman_interface = "bat0"

    @staticmethod
    def _setup_logger():
        logger_instance = CustomLogger("mutAuth")
        return logger_instance.get_logger()

    def check_mesh(self):
        if not is_wpa_supplicant_running():
            logger.info("wpa_supplicant process is not running.")
            run_wpa_supplicant(self.meshiface)
            set_ipv6(self.meshiface, self.ipAddress)
        else:
            logger.info("wpa_supplicant process is running.")

    @staticmethod
    def set_firewall():
        apply_nft_rules()

    def _setup_server_event(self):
        with self.server_lock:
            self.logger.info("Setting server_event")
            self.server_event.set()
            self.is_server_running = True
            self.server = True  # Explicitly set this too

    def _clear_server_event(self):
        with self.server_lock:
            self.logger.info("Clearing server_event")
            self.server_event.clear()
            self.is_server_running = False
            self.server = False  # Explicitly clear this too

    def _periodic_sender(self, stop_event):
        while not stop_event.is_set() and not self.shutdown_event.is_set():
            if self.server:
                self.multicast_handler.send_multicast_message(f"{self.mymac}_server")
                self._setup_server_event()  # Use the centralized method
            else:
                self.multicast_handler.send_multicast_message(self.mymac)
            time.sleep(BEACON_TIME)

    def monitor_wpa(self):
        #muthread = threading.Thread(target=self.multicast_handler.receive_multicast)
        #muthread.start()

        while not self.shutdown_event.is_set():
            source, message = self.in_queue.get()
            if source == "WPA":
                self.logger.info("External node_connect event triggered!")
                self.logger.info(f"Received MAC from WPA event: {message}")
                handle_peer_connected_thread = threading.Thread(target=self.handle_peer_connected_event, args=(message,))
                handle_peer_connected_thread.start()

    def handle_peer_connected_event(self, mac):
        if mac not in self.connected_peers_status:
            # There is no ongoing connection with peer yet
            # Wait for random seconds
            random_wait = random.uniform(0.5,3)  # Wait between 0.5 to 3 seconds. Random waiting to avoid race condition
            time.sleep(random_wait)
            if mac not in self.connected_peers_status:
                # Start as client
                print("------------------client ---------------------")
                with self.connected_peers_status_lock:
                    self.connected_peers_status[mac] = ["ongoing", 0] # Update status as ongoing, num of failed attempts = 0
                self.start_auth_client(mac)
        elif self.connected_peers_status[mac][0] not in ["ongoing"]:
            # If node does not have ongoing authentication or is not already authenticated or has not been blacklisted
            # Wait for random seconds
            random_wait = random.uniform(0.5,3)  # Wait between 0.5 to 3 seconds. Random waiting to avoid race condition
            time.sleep(random_wait)
            if self.connected_peers_status[mac][0] not in ["ongoing"]:
                # Start as client
                print("------------------client ---------------------")
                with self.connected_peers_status_lock:
                    self.connected_peers_status[mac][0] = "ongoing"  # Update status as ongoing, num of failed attempts = same as before
                self.start_auth_client(mac)

    def multicast_message(self):
        CHECK_INTERVAL = 0.1  # Check every 0.1 seconds for a new message
        last_received = time.time()
        stop_sender_event = threading.Event()
        muthread = threading.Thread(target=self.multicast_handler.receive_multicast)
        muthread.start()

        while not self.shutdown_event.is_set():  # We'll check for the shutdown signal here
            try:
                source, message = self.in_queue.get(timeout=TIMEOUT)
                if message.endswith("_server"):
                    # This is a server beacon. Reset the timeout and don't attempt to become a server.
                    self.server = False
                    last_received = time.time()
                elif message == self.mymac:
                    continue
                if source == "MULTICAST":
                    self.logger.info(f"Received MAC on multicast: {message}")
                    last_received = time.time()
                elif source == "WPA":
                    self.logger.info("External node_connect event triggered!")
                    self.logger.info(f"Received MAC from WPA event: {message}")
                    self.multicast_handler.send_multicast_message(self.mymac)
                    last_received = time.time()  # update the last_received time here as well

                # Check if the MAC is already in the queue
                if message not in self.macs_in_queue:
                    self.out_queue.put((source, message))
                    self.macs_in_queue.add(message)

            except queue.Empty:  # <-- Timeout event
                if time.time() - last_received > TIMEOUT and not self.server:
                    self.logger.info(f"No message received for {TIMEOUT} seconds. Contemplating becoming a server...")
                    random_wait = random.uniform(0.5,
                                                 3)  # Wait between 0.5 to 3 seconds. Random waiting to avoid race condition

                    end_time = time.time() + random_wait
                    while time.time() < end_time:
                        try:
                            source, message = self.in_queue.get(timeout=CHECK_INTERVAL)
                            if message != self.mymac:
                                last_received = time.time()  # update the last_received time
                                # Check if the MAC is already in the queue
                                if message not in self.macs_in_queue:
                                    self.out_queue.put((source, message))
                                    self.macs_in_queue.add(message)
                                break  # break out of the waiting loop
                        except queue.Empty:
                            continue
                    if time.time() - last_received > TIMEOUT and not self.is_server_running:
                        try:
                            self.logger.info("Attempting to become a server.")
                            sender_thread = threading.Thread(target=self._periodic_sender, args=(stop_sender_event,))
                            sender_thread.start()
                            self._setup_server_event()  # Use the centralized method
                            self.logger.info("Successfully became a server.")
                        except Exception as e:
                            self.logger.error(f"Failed to become a server. Error: {e}")

    def start_auth_server(self):
        auth_server = AuthServer(self.ipAddress, self.port, self.CERT_PATH, self)
        auth_server_thread = threading.Thread(target=auth_server.start_server)
        auth_server_thread.start()
        return auth_server_thread, auth_server

    def start_auth_client(self, server_mac):
        cli = AuthClient(server_mac, self.port, self.CERT_PATH, self)
        cli.establish_connection()  # TODO: check if secchan should be established only if server certificate is verified
        #self.setup_macsec(secure_client_socket=cli.secure_client_socket, client_mac=server_mac)

    """
    def start_auth_client(self, ServerIP):
        return AuthClient(ServerIP, self.port, self.CERT_PATH)
    """
    def batman(self, batman_interface):
        try:
            batman_exec(batman_interface,"batman-adv")
        except Exception as e:
            logger.error(f'Error setting up bat0: {e}')
            sys.exit(1)

    def setup_secchannel(self, secure_client_socket, my_macsec_param):
        # Establish secure channel and exchange macsec key
        secchan = SecMessageHandler(secure_client_socket)
        macsec_param_q = queue.Queue()  # queue to store macsec parameters: macsec_key, port from client_secchan.receive_message
        receiver_thread = threading.Thread(target=secchan.receive_message, args=(macsec_param_q,))
        receiver_thread.start()
        print(f"Sending my macsec parameters: {my_macsec_param} to {secure_client_socket.getpeername()[0]}")
        secchan.send_message(json.dumps(my_macsec_param))
        client_macsec_param = json.loads(macsec_param_q.get())
        return secchan, client_macsec_param

    def setup_macsec(self, secure_client_socket, client_mac):
        # Setup macsec
        # Compute macsec parameters
        bytes_for_my_key = generate_random_bytes() # bytes for my key
        bytes_for_client_key = generate_random_bytes() # bytes for client key
        my_port = self.macsec_lower.assign_unique_port(client_mac)
        my_macsec_param = {'bytes_for_my_key': bytes_for_my_key.hex(), 'bytes_for_client_key': bytes_for_client_key.hex(), 'port': my_port} # Bytes conveted into hex strings so that they can be dumped into json later

        # Establish secure channel and exchange bytes for macsec keys and port
        secchan, client_macsec_param = self.setup_secchannel(secure_client_socket, my_macsec_param)

        # Compute keys by XORing bytes
        my_macsec_key = xor_bytes(bytes_for_my_key, bytes.fromhex(client_macsec_param['bytes_for_client_key'])).hex() # XOR my bytes_for_my_key with client's bytes_for_client_key
        client_macsec_key = xor_bytes(bytes_for_client_key, bytes.fromhex(client_macsec_param['bytes_for_my_key'])).hex() # XOR my bytes_for_client_key with client's bytes_for_my_key

        self.macsec_lower.set_macsec_tx(client_mac, my_macsec_key, my_port) # setup macsec tx channel
        self.macsec_lower.set_macsec_rx(client_mac, client_macsec_key, client_macsec_param['port'])  # setup macsec rx channel
        # Add lower macsec interface to lower batman interface
        add_interface_to_batman(interface_to_add=self.macsec_lower.get_macsec_interface_name(client_mac), batman_interface=self.lower_batman_interface)
        if not is_interface_up(self.lower_batman_interface): # Turn lower batman interface up if not up already
            self.batman(self.lower_batman_interface)

    def start(self):
        # ... other starting procedures
        self.sender_thread.start()

    def stop(self):
        # Use this method to stop the periodic sender and other threads
        self.stop_event.set()
        self.sender_thread.join()
