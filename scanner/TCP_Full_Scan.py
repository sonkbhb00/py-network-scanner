import socket
import time
from utils.decoratives import decor
from utils.threading import threaded_port_scan

def _tcp_worker(target_ip, port, timeout):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        response = sock.connect_ex((target_ip, port))
        sock.close()
        if response == 0:
            return port
    except:
        pass
    return None

def TCP_Full_Scan(target_ip, target_ports, timeout=1, delay=0, parallel=False):
    
    if parallel:
        scan_func = lambda t_ip, p: _tcp_worker(t_ip, p, timeout)
        return threaded_port_scan(target_ip, target_ports, scan_func, progress_callback=decor)

    open_ports = []
    scanned_ports = 0
    for port in target_ports:
        port_res = _tcp_worker(target_ip, port, timeout)
        if port_res is not None:
             open_ports.append(port_res)

        # Add delay between probes
        if delay > 0:
            time.sleep(delay)
        
        scanned_ports = scanned_ports + 1
        decor(len(target_ports), scanned_ports)

    return open_ports

