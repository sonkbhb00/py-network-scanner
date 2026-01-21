import scapy.all as scapy
import time
from utils.decoratives import decor
from utils.threading import threaded_port_scan

def _xmas_worker(target_ip, port, timeout):
    packet = scapy.IP(dst=target_ip)/scapy.TCP(dport=port, flags="FPU")
    response = scapy.sr1(packet, timeout=timeout, verbose=0)
    if response and response.haslayer(scapy.TCP):
        if response.getlayer(scapy.TCP).flags == 0x4:  # RST flag
            return (port, 'closed')
    else:
        return (port, 'filtered') # Maps to open|filtered
    return None

def Xmas_Scan(target_ip, target_ports, timeout=1, delay=0, parallel=False):
    if parallel:
        scan_func = lambda t_ip, p: _xmas_worker(t_ip, p, timeout)
        results = threaded_port_scan(target_ip, target_ports, scan_func, progress_callback=decor)
        closed_ports = [r[0] for r in results if r and r[1] == 'closed']
        filtered_ports = [r[0] for r in results if r and r[1] == 'filtered']
        return closed_ports, filtered_ports

    closed_ports = []
    filtered_ports = []
    scanned_port = 0
    for port in target_ports:
        res = _xmas_worker(target_ip, port, timeout)
        if res:
             if res[1] == 'closed':
                 closed_ports.append(res[0])
             elif res[1] == 'filtered':
                 filtered_ports.append(res[0])
        
        # Add delay between probes
        if delay > 0:
            time.sleep(delay)
        
        scanned_port = scanned_port + 1
        decor(len(target_ports), scanned_port)
    return closed_ports, filtered_ports