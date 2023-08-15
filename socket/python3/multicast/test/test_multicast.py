import threading
import pytest
from unittest.mock import patch, MagicMock
from multicast.multicast import send_multicast_message, receive_multicast
import socket
import json

# Define mock data and address to return
mocked_data = json.dumps({
    'mac_address': '00:11:22:33:44:55',
    'message_type': 'mac_announcement'
}).encode('utf-8')
mocked_address = ('ff02::1', 12345)


@patch('socket.socket')
def test_end_to_end_communication(mocked_socket):
    # Given
    multicast_group = 'ff02::1'
    port = 12345
    queue = MagicMock()
    start_event = threading.Event()
    end_event = threading.Event()

    # Mock the socket's methods
    instance = mocked_socket.return_value
    instance.recvfrom.return_value = (mocked_data, mocked_address)

    # Start the receiver in a thread
    def receiver_thread():
        receive_multicast(multicast_group, port, queue)
        end_event.set()  # Signal the end of the receiving

    threading.Thread(target=receiver_thread).start()

    # Once the receiver is set up, signal the sender to start
    start_event.wait()

    # Start the sender
    send_multicast_message(multicast_group, port, "00:11:22:33:44:55")

    # Wait for receiver to finish
    end_event.wait()

    # Asserts
    queue.put.assert_called_with('00:11:22:33:44:55')
