import signal
import threading
from mutauth import mutAuth
from tools.monitoring_wpa import WPAMonitor
from tools.utils import *
from secure_channel.secchannel import SecMessageHandler
from macsec import macsec

shutdown_event = threading.Event()


def signal_handler(sig, frame):
    print("\nCaught signal. Shutting down gracefully...")
    shutdown_event.set()
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)


def on_message_received(data):
    return data


def manage_server(mua):
    print("------------------server ---------------------")
    return mua.start_auth_server()


def manage_client(out_queue, mua):
    source, message = out_queue.get()
    print("------------------client ---------------------")
    time.sleep(3)
    if "_server" in message:
        server_mac = message.split('_server')[0]
    #TODO: check why client is starting even when message does not contain '_server'
    else:
        server_mac = message
    cli = mua.start_auth_client(server_mac)
    cli.establish_connection() #TODO: check if secchan should be established only if server certificate is verified
    mua.setup_macsec(secure_client_socket=cli.secure_client_socket,
                     client_mac=server_mac)

def start_up(mua):
    # Sets up wlp1s0 interface
    mua.check_mesh()

def mutual_authentication(mua, in_queue):
    # Start server to facilitate client auth requests, monitor ongoing auths and start client request if there is a new peer/ server baecon
    auth_server_thread, auth_server = mua.start_auth_server()
    # Start monitoring wpa for new peer connection
    wpa_ctrl_instance = WPAMonitor(mua.wpa_supplicant_ctrl_path)
    wpa_thread = threading.Thread(target=wpa_ctrl_instance.start_monitoring, args=(in_queue,))
    mutAuth_tread = threading.Thread(target=mua.monitor_wpa)
    wpa_thread.start()
    mutAuth_tread.start()

def main():
    in_queue = queue.Queue()
    out_queue = queue.Queue()

    mua = mutAuth(in_queue, out_queue, shutdown_event)
    start_up(mua)
    mutual_authentication(mua, in_queue)

"""
def main():
    in_queue = queue.Queue()
    out_queue = queue.Queue()

    mua = mutAuth(in_queue, out_queue, shutdown_event)
    start_up(mua)

    wpa_ctrl_instance = WPAMonitor(mua.wpa_supplicant_ctrl_path)
    wpa_thread = threading.Thread(target=wpa_ctrl_instance.start_monitoring, args=(in_queue,))
    mutAuth_tread = threading.Thread(target=mua.multicast_message)

    wpa_thread.start()
    mutAuth_tread.start()

    mutAuth_start_time = time.time() #TODO: remove later (this is only for test)

    # Flags to prevent multiple instances of server/client
    is_server_started = False
    is_client_started = False
    server_wait_time = 40  # time in seconds to wait for a server to be available --> we have to improve this
    wait_start = time.time()

    while not shutdown_event.is_set():
        # If the node should be a server and hasn't already become one
        if mua.server_event.is_set() and not is_server_started and not is_client_started:
            print("Inside server event check")
            print("Time taken for server to start = ", time.time() - mutAuth_start_time) #TODO: remove later (this is only for test)
            server_thread, serv = manage_server(mua)
            is_server_started = True
            mua.server_event.clear()  # Clearing the event to prevent re-entry

        # If the node shouldn't be a server and hasn't already become a client
        elif not mua.server and not is_client_started and not is_server_started and time.time() - wait_start >= server_wait_time:
            print("entering as client")
            print("Time taken for client to start = ", time.time() - mutAuth_start_time) #TODO: remove later (this is only for test)
            manage_client(out_queue, mua)
            #macsec_key = client_secchan.set_callback(on_message_received)
            #print('Macsec key: ', macsec_key)
            is_client_started = True

        # If no decision can be made, we wait for a short period
        else:
            time.sleep(1)

        # Reset wait time if a server is detected
        if mua.server:
            wait_start = time.time()
"""

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
5) generate session key (with XOR)
7) test macsec 
8) test batman_adv implementation
9) ipsec

'''
