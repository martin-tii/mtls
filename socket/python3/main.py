from mutauth import mutAuth
from tools.monitoring_wpa import WPAMonitor
from tools.utils import  *
from secure_channel.secchannel import SecMessageHandler
import threading

def on_message_received(data):
    return data

def main():

    in_queue = queue.Queue()
    out_queue = queue.Queue()
    mua = mutAuth(in_queue, out_queue)
    mua.check_mesh()  # start mesh
    wpa_ctrl_instance = WPAMonitor(mua.wpa_supplicant_ctrl_path)
    wpa_thread = threading.Thread(target=wpa_ctrl_instance.start_monitoring, args=(in_queue,))
    mutAuth_tread = threading.Thread(target=mua.multicast_message)

    wpa_thread.start()
    mutAuth_tread.start()

    while not out_queue.empty(): #<-- not entering here
        if mua.server:
            ser_thread, serv = mua.start_auth_server()
            if serv.client_auth_results:
                for client in serv.client_auth_results:
                    rand = generate_session_key()
                    secchan = SecMessageHandler(serv.get_secure_socket(client))
                    receiver_thread = threading.Thread(target=secchan.receive_message)
                    receiver_thread.start()
                    secchan.send_message(rand)
        else:
            _, cli = mua.start_auth_client(out_queue.get())
            cli.establish_connection()
            client_secchan = SecMessageHandler(cli.secure_client_socket)
            receiver_thread = threading.Thread(target=client_secchan.receive_message)
            receiver_thread.start()

        data = client_secchan.set_callback(on_message_received)
        print(data)


main()

if __name__ == "__main__":
    equeue = queue.Queue()
    mua = mutAuth(equeue)
    mua.check_mesh() # start mesh
    wpa_ctrl_instance = WPAMonitor(mua.wpa_supplicant_ctrl_path)

    mutAuth_tread = threading.Thread(target=mua.multicast_message, args=(equeue,))

    wpa_thread.start()
    mutAuth_tread.start()

    while not equeue.empty():
        if mua.server:
            ser_thread, serv = mua.start_auth_server()
            if serv.client_auth_results:
                for client in serv.client_auth_results:
                    rand = generate_session_key()
                    secchan = SecMessageHandler(serv.get_secure_socket(client))
                    receiver_thread = threading.Thread(target=secchan.receive_message)
                    receiver_thread.start()
                    secchan.send_message(rand)
        else:
            cli = mua.start_auth_client(equeue.get())
            cli.establish_connection()
            client_secchan = SecMessageHandler(cli.secure_client_socket)
            receiver_thread = threading.Thread(target=client_secchan.receive_message)
            receiver_thread.start()

        data = client_secchan.set_callback(on_message_received)
        print(data)
        # mua.macsec()
        # mua.batman


    # Wait for the monitoring module process to finish before exiting the main process
    wpa_thread.join()
    mutAuth_tread.join()
    if receiver_thread:
        receiver_thread.join()
    if mua.server:
        serv.stop_server()
        ser_thread.join()


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
