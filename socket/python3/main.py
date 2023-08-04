import multiprocessing
from tools.monitoring_wpa import *
from auth.authServer import AuthServer
from auth.authClient import AuthClient
from tools.utils import  *
import os

BEACON_TIME = 10
MAX_CONSECUTIVE_NOT_RECEIVED = 2
class mutAuth():
    def __init__(self):
        self.meshiface = "wlp1s0"
        self.mymac = get_mac_addr(self.meshiface)
        self.ipAddress = mac_to_ipv6(self.mymac)
        self.port = 15001
        self.CERT_PATH = '../../certificates'  # Change this to the actual path of your certificates
        self.server = False
        self.wpa_supplicant_ctrl_path = f"/var/run/wpa_supplicant/{self.meshiface}"
        self.message_received = False

    def check_mesh(self):
        if not is_wpa_supplicant_running():
            print("wpa_supplicant process is not running.")
            run_wpa_supplicant(self.meshiface)

    def set_firewall(self):
        apply_nft_rules()


    def check_message(self):
        #TODO get ip from message
        serverIP = "127.0.0.1"
        self.message_received = True  # Set this to False if the message is not received
        return serverIP

    def other_module(self, queue):
        consecutive_not_received_count = 0
        while True:
            mac_address = queue.get()
            # Perform actions in the other module based on the received MAC address
            print(f"Received MAC address from monitoring module: {mac_address}")
            if self.message_received:
                # Reset the count if a message is received
                consecutive_not_received_count = 0
                self.start_auth_client(self.check_message())  # Start the client
            else:
                consecutive_not_received_count += 1

                if consecutive_not_received_count >= MAX_CONSECUTIVE_NOT_RECEIVED:
                    self.start_auth_server()  # Start the process

            # Wait for the specified interval before checking again
            time.sleep(BEACON_TIME)

    def start_auth_server(self):
        auth_server = AuthServer(self.ipAddress, self.port, self.CERT_PATH)
        auth_server.start_server()
        self.server = True


    def start_auth_client(self, ServerIP):
        auth_client = AuthClient(ServerIP, self.port, self.CERT_PATH)
        return auth_client.establish_connection()

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

    def get_session_key(self):
        rand = os.urandom(32)
        return int.from_bytes(rand, 'big')






if __name__ == "__main__":
    mua = mutAuth()
    mua.check_mesh() # start mesh

    # Wait for the wpa_supplicant control interface file to be created
    with contextlib.suppress(KeyboardInterrupt):
        wpa_ctrl_instance = create_wpa_ctrl_instance(mua.wpa_supplicant_ctrl_path)

    #monitor wpa
    with wpa_ctrl_instance as ctrl:
        ctrl.attach()
        # Create a Queue for communication between the processes
        event_queue = multiprocessing.Queue()

        # Start the monitoring module as a separate process
        event_process = multiprocessing.Process(target=process_events, args=(ctrl, event_queue))
        event_process.start()

        # Start the other module as a separate process
        other_module_process = multiprocessing.Process(target=mua.other_module, args=(event_queue,))
        other_module_process.start()

        # beacon
        #TODO define beacon
        # OpenSSL.SSL.Context(DTLS_METHOD, or DTLS_CLIENT_METHOD and DTLS_SERVER_METHOD) then
        # bio_read() and bio_write()
        # for using DTLS with Scapy instead of a socket


        # TODO define the logic for the auth verification
        #
        # # authenticated is coming from authServer/client
        # # this is only for the server
        # # Access the authentication result for a specific client
        # client_address = ("127.0.0.1", 12345)  # Replace with the actual client address you want to check
        # auth_result = auth_server.get_client_auth_result(client_address)
        # print(f"Authentication result for {client_address}: {auth_result}")
        if auth_result:
            rand = mua.get_session_key()
            # neeed to exchange the key
            mua.macsec()
            mua.batman

        #

        # try:
        #     while True:
        #         # Continue with other tasks here if needed
        #         pass
        #
        # except KeyboardInterrupt:
        #     pass

        # Wait for the monitoring module process to finish before exiting the main process
        event_process.join()


'''
TODO:
1) Beacon 
2) Test auth
3) Check how to use the context (for the secure channel)
4) Get Auth from server/client
5) generate session key (with XOR)
7) test macsec
8) test batman_adv implementation
9) ipsec

'''
