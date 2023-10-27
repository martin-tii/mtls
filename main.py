import signal
import threading
from mutauth import mutAuth
from tools.monitoring_wpa import WPAMonitor
from tools.utils import *
from secure_channel.secchannel import SecMessageHandler
from macsec import macsec
shutdown_event = threading.Event()


def start_up(mua):
    # Sets up wlp1s0 interface
    mua.check_mesh()

def mutual_authentication_lower(mua, in_queue):
    # Wait for wireless interface to be pingable before starting mtls server, multicast
    wait_for_interface_to_be_pingable(mua.meshiface, mua.ipAddress)
    # Start server to facilitate client auth requests, monitor ongoing auths and start client request if there is a new peer/ server baecon
    auth_server_thread, auth_server = mua.start_auth_server()
    # Start monitoring wpa for new peer connection
    wpa_ctrl_instance = WPAMonitor(mua.wpa_supplicant_ctrl_path)
    wpa_thread = threading.Thread(target=wpa_ctrl_instance.start_monitoring, args=(in_queue,))
    # Start multicast receiver that listens to multicasts from other mesh nodes
    receiver_thread = threading.Thread(target=mua.multicast_handler.receive_multicast)
    monitor_thread = threading.Thread(target=mua.monitor_wpa_multicast)
    wpa_thread.start()
    receiver_thread.start()
    monitor_thread.start()
    # Send periodic multicasts
    mua.sender_thread.start()

def mutual_authentication_upper(mua, in_queue):
    # Wait for bat0 to be pingable before starting mtls server, multicast
    wait_for_interface_to_be_pingable(mua.meshiface, mua.ipAddress)
    # Start server to facilitate client auth requests, monitor ongoing auths and start client request if there is a new peer/ server baecon
    auth_server_thread, auth_server = mua.start_auth_server()
    # Start multicast receiver that listens to multicasts from other mesh nodes
    receiver_thread = threading.Thread(target=mua.multicast_handler.receive_multicast)
    monitor_thread = threading.Thread(target=mua.monitor_wpa_multicast)
    receiver_thread.start()
    monitor_thread.start()
    # Send periodic multicasts
    mua.sender_thread.start()

def main():
    in_queue_lower = queue.Queue() # Queue to store wpa peer connected messages for wlp1s0
    lower_batman_setup_event = threading.Event() # Event that notifies that lower macsec and bat0 has been setup
    apply_nft_rules(rules_file='/root/mtls/socket/python3/tools/firewall.nft') # Apply firewall rules
    mua_lower = mutAuth(in_queue_lower, level="lower", meshiface="wlp1s0", port=15001, batman_interface="bat0", shutdown_event=shutdown_event, batman_setup_event=lower_batman_setup_event)
    start_up(mua_lower)
    mutual_authentication_lower(mua_lower, in_queue_lower)

    # Wait till lower batman is set to start mutauth for upper macsec
    lower_batman_setup_event.wait()
    in_queue_upper = queue.Queue() # Queue to store multicast messages received over bat0 for upper macsec
    upper_batman_setup_event = threading.Event()  # Event that notifies that upper macsec and bat1 has been setup
    mua_upper = mutAuth(in_queue_upper, level="upper", meshiface="bat0", port=15002, batman_interface="bat1", shutdown_event=shutdown_event, batman_setup_event=upper_batman_setup_event)
    mutual_authentication_upper(mua_upper, in_queue_upper)


def stop(wpa_thread, mutAuth_tread, mua):
    wpa_thread.join()
    mutAuth_tread.join()
    mua.stop()


if __name__ == "__main__":
    main()

'''
TODO:
1) DTLS beat

            # OpenSSL.SSL.Context(DTLS_METHOD, or DTLS_CLIENT_METHOD and DTLS_SERVER_METHOD) then
            # bio_read() and bio_write()
            # for using DTLS with Scapy instead of a socket
2) Test muti-hop scenario: check if multi-hop nodes receive multicast message over bat0
3) Handle simultaneous 2 way TLS and macsec setup between a set of peers by using separate SA for each direction
9) ipsec

'''
