import signal
import threading
from mutauth import mutAuth
from tools.monitoring_wpa import WPAMonitor
from tools.utils import *
from secure_channel.secchannel import SecMessageHandler

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


def server_sechannel(serv, client):
    rand = generate_session_key()
    secchan = SecMessageHandler(serv.get_secure_socket(client))
    receiver_thread = threading.Thread(target=secchan.receive_message)
    receiver_thread.start()
    print(f"sending random value: {rand}")
    secchan.send_message(str(rand))
    return secchan, rand


def manage_client(out_queue, mua):
    source, message = out_queue.get()
    print("------------------client ---------------------")
    time.sleep(3)
    if "_server" in message:
        cli = mua.start_auth_client(message.split('_server')[0])
    else:
        cli = mua.start_auth_client(message)
    cli.establish_connection()
    client_secchan = SecMessageHandler(cli.secure_client_socket)
    receiver_thread = threading.Thread(target=client_secchan.receive_message)
    receiver_thread.start()
    return client_secchan


def main():
    in_queue = queue.Queue()
    out_queue = queue.Queue()

    mua = mutAuth(in_queue, out_queue, shutdown_event)
    mua.check_mesh()

    wpa_ctrl_instance = WPAMonitor(mua.wpa_supplicant_ctrl_path)
    wpa_thread = threading.Thread(target=wpa_ctrl_instance.start_monitoring, args=(in_queue,))
    mutAuth_tread = threading.Thread(target=mua.multicast_message)

    wpa_thread.start()
    mutAuth_tread.start()

    # Flags to prevent multiple instances of server/client
    is_server_started = False
    is_client_started = False
    server_wait_time = 40  # time in seconds to wait for a server to be available --> we have to improve this
    wait_start = time.time()

    while not shutdown_event.is_set():
        # If the node should be a server and hasn't already become one
        if mua.server_event.is_set() and not is_server_started and not is_client_started:
            print("Inside server event check")
            server_thread, serv = manage_server(mua)
            if serv.client_auth_results:
                print(serv.client_auth_results)
                for client in serv.client_auth_results:
                    return server_sechannel(serv, client)
            is_server_started = True
            mua.server_event.clear()  # Clearing the event to prevent re-entry

        # If the node shouldn't be a server and hasn't already become a client
        elif not mua.server and not is_client_started and not is_server_started and time.time() - wait_start >= server_wait_time:
            print("entering as client")
            client_secchan = manage_client(out_queue, mua)
            macsec_key = client_secchan.set_callback(on_message_received)
            print(macsec_key)
            is_client_started = True

        # If no decision can be made, we wait for a short period
        else:
            time.sleep(1)

        # Reset wait time if a server is detected
        if mua.server:
            wait_start = time.time()


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
