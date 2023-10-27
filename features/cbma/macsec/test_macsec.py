import pytest
from macsec import Macsec
import threading

def test_assign_unique_port():
    # Test that assigned port is unique
    macsec_obj = Macsec()
    assigned_ports = set()
    for i in range(100):
        port = macsec_obj.assign_unique_port(f'client{i}')
        assert port == macsec_obj.used_ports[f'client{i}'] # assert that assigned port has been recorded correctly in used ports
        assert port not in assigned_ports # assert that assigned port is unique
        assert port not in macsec_obj.available_ports  # assert that assigned port has been removed from available ports
        assigned_ports.add(port)
    assert assigned_ports == set(macsec_obj.used_ports.values()) # assert that all assigned ports have been recorded in used ports

def test_release_port():
    # Test releasing a port
    macsec_obj = Macsec()
    port = macsec_obj.assign_unique_port('client')
    macsec_obj.release_port('client')
    assert 'client' not in macsec_obj.used_ports # assert that client has been removed from used ports
    assert port in macsec_obj.available_ports # assert that the assigned port has been released back as available port
  
def test_assign_unique_port_multithreaded():
    # Test that assigned port is unique
    macsec_obj = Macsec()
    num_clients = 100
    threads = []
    for i in range(num_clients):
        thread = threading.Thread(target=macsec_obj.assign_unique_port, args=(f'client{i}',))
        threads.append(thread)
        thread.start()
    for thread in threads:
        thread.join()
    assert len(set(macsec_obj.used_ports.values())) == num_clients # assert that all clients have been assigned unique ports

    assert len(macsec_obj.available_ports) == (2**16 - 1) - num_clients # assert that ports assigned to clients have been removed from available ports