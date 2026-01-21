import scapy.all as scapy
import time
from utils.decoratives import decor
from utils.threading import threaded_port_scan

def _ack_worker(target_ip, port, timeout):
    packet = scapy.IP(dst=target_ip)/scapy.TCP(dport=port, flags="A")
    response = scapy.sr1(packet, timeout=timeout, verbose=0)
    if response and response.haslayer(scapy.TCP):
        if response.getlayer(scapy.TCP).flags == 0x4:  # RST flag
            return (port, 'unfiltered')
    else:
        return (port, 'filtered')
    return None

def Ack_Full_Scan(target_ip, target_port, timeout=1, delay=0, parallel=False):
    if parallel:
        scan_func = lambda t_ip, p: _ack_worker(t_ip, p, timeout)
        results = threaded_port_scan(target_ip, target_port, scan_func, progress_callback=decor)
        unfiltered_ports = [r[0] for r in results if r and r[1] == 'unfiltered']
        filtered_ports = [r[0] for r in results if r and r[1] == 'filtered']
        return unfiltered_ports, filtered_ports

    unfiltered_ports = []
    filtered_ports = []
    scanned_port = 0
    for port in target_port:
        res = _ack_worker(target_ip, port, timeout)
        if res:
            if res[1] == 'unfiltered':
                unfiltered_ports.append(res[0])
            elif res[1] == 'filtered':
                filtered_ports.append(res[0])
        
        # Add delay between probes
        if delay > 0:
            time.sleep(delay)
        
        scanned_port = scanned_port + 1
        decor(len(target_port), scanned_port)
    return unfiltered_ports, filtered_ports


