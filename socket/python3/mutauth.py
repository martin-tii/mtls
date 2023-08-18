from auth.authServer import AuthServer
from auth.authClient import AuthClient
import threading
from multicast.multicast import MulticastHandler
from tools.monitoring_wpa import *
from tools.custom_logger import CustomLogger
from tools.utils import  *
import queue

BEACON_TIME = 50
MAX_CONSECUTIVE_NOT_RECEIVED = 2
MULTICAST_ADDRESS = 'ff02::1'
TIMEOUT = 3 * BEACON_TIME
class mutAuth():
    def __init__(self, in_queue, out_queue):
        self.meshiface = "wlp1s0"
        self.mymac = get_mac_addr(self.meshiface)
        self.ipAddress = mac_to_ipv6(self.mymac)
        self.port = 15001
        self.CERT_PATH = 'cert_generation/certificates'  # Change this to the actual path of your certificates
        self.server = False
        self.wpa_supplicant_ctrl_path = f"/var/run/wpa_supplicant/{self.meshiface}"
        self.message_received = False
        self.in_queue = in_queue
        self.out_queue = out_queue
        self.logger = self._setup_logger()
        self.multicast_handler = MulticastHandler(self.in_queue, MULTICAST_ADDRESS, self.port)

    def _setup_logger(self):
        logger_instance = CustomLogger("mutAuth")
        return logger_instance.get_logger()

    def check_mesh(self):
        if not is_wpa_supplicant_running():
            logger.info("wpa_supplicant process is not running.")
            run_wpa_supplicant(self.meshiface)
            set_ipv6(self.meshiface, self.ipAddress)
        else:
            logger.info("wpa_supplicant process is running.")

    def set_firewall(self):
        apply_nft_rules()

    def _periodic_sender(self,  stop_event):
        while not stop_event.is_set():
            self.multicast_handler.send_multicast_message(self.mymac)
            time.sleep(BEACON_TIME)
            self.server = True

    def multicast_message(self):
        last_received = time.time()
        stop_sender_event = threading.Event()
        muthread = threading.Thread(target=self.multicast_handler.receive_multicast) #check how to close it
        muthread.start()
        while True:
            try:
                source, message = self.in_queue.get(timeout=TIMEOUT)
                if source == "MULTICAST":
                    self.logger.info(f"Received MAC on multicast: {message}")
                    last_received = time.time()
                elif source == "WPA":
                    self.logger.info("External node_connect event triggered!")
                    self.logger.info(f"Received MAC from WPA event: {message}")
                    self.multicast_handler.send_multicast_message(self.mymac)
                self.out_queue.put((source, message))
            except queue.Empty:  # <--
                if time.time() - last_received > TIMEOUT:
                    self.logger.info(f"No message received for {TIMEOUT} seconds. Acting as a server now.")
                    sender_thread = threading.Thread(target=self._periodic_sender, args=(stop_sender_event,))
                    sender_thread.start()

    def start_auth_server(self):
        auth_server = AuthServer(self.ipAddress, self.port, self.CERT_PATH)
        auth_server_thread = threading.Thread(target=auth_server.start_server)
        auth_server_thread.start()
        self.server = True
        return auth_server_thread, auth_server

    def start_auth_client(self, ServerIP):
        return AuthClient(ServerIP, self.port, self.CERT_PATH)

    def macsec(self, mac_client, key1, key2):
        if self.server:
            role = "primary"
            set_macsec(role, self.meshiface, key1, key2, self.mymac, mac_client)
        else:
            role = "secondary"
            set_macsec(role, self.meshiface, key2, key1, mac_client, self.mymac)
        # Call the function to run the bash script
        run_macsec(["up", self.meshiface, role])

    def batman(self):
        # todo check the interface
        ipv6 = mac_to_ipv6(self.meshiface)
        batman_exec("batman-adv", "wlp1s0", ipv6,  "/64")