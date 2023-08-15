import socket
import struct
import threading
import time
import logging
import argparse
import json
import sys
from queue import Queue
sys.path.insert(0, '../')
from tools.utils import get_mac_addr

logging.basicConfig(level=logging.INFO)


# Sender
def send_multicast_message(multicast_group, port, data):
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)

        data = {
            'mac_address': data,
            'message_type': 'mac_announcement'
        }

        logging.info(f'Sending data {data} to {multicast_group}:{port}')
        sock.sendto(json.dumps(data).encode('utf-8'), (multicast_group, port))


# Receiver
def receive_multicast(multicast_group, port, queue=None):  # default the queue to None
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
        sock.bind(('', port))

        group = socket.inet_pton(socket.AF_INET6, multicast_group)
        mreq = group + struct.pack('@I', 0)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)

        logging.info(f"Listening for messages on {multicast_group}:{port}...")
        while True:
            data, address = sock.recvfrom(1024)
            decoded_data = json.loads(data.decode())
            logging.info(f'Received data {decoded_data} from {address}')

            if 'mac_address' in decoded_data and queue:  # Ensure queue is not None
                queue.put(decoded_data['mac_address'])


def main():
    message = get_mac_addr("wlp1s0")
    parser = argparse.ArgumentParser(description="IPv6 Multicast Sender/Receiver")
    parser.add_argument('--mode', choices=['send', 'receive', 'both'], required=True, help='Run mode: send, receive, or both')
    parser.add_argument('--address', default='ff02::1', help='Multicast IPv6 address (default: ff02::1)')
    parser.add_argument('--port', type=int, default=12345, help='Port to use (default: 12345)')

    args = parser.parse_args()

    if args.mode == 'receive':
        # No need for a queue if just in receive mode
        receive_multicast(args.address, args.port, None)
    elif args.mode == 'send':
        send_multicast_message(args.address, args.port, message)
    elif args.mode == 'both':
        queue = Queue()
        receiver_thread = threading.Thread(target=receive_multicast, args=(args.address, args.port, queue))
        receiver_thread.start()

        # Wait a bit for the receiver thread to start
        time.sleep(2)

        send_multicast_message(args.address, args.port, message)

        received_mac = queue.get()  # This will block until a MAC address is received
        logging.info(f"Main thread received MAC: {received_mac}")

        try:
            # Keep the script running so the receiver continues listening.
            receiver_thread.join()
        except KeyboardInterrupt:
            logging.info("Shutting down...")
            sys.exit(0)


if __name__ == "__main__":
    main()
