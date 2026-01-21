import scapy.all as scapy
import time
from utils.decoratives import decor
from utils.threading import threaded_port_scan

def _syn_worker(target_ip, port, timeout):
    packet = scapy.IP(dst=target_ip)/scapy.TCP(dport=port, flags="S")
    response = scapy.sr1(packet, timeout=timeout, verbose=0)
    
    if response and response.haslayer(scapy.TCP):
        if response.getlayer(scapy.TCP).flags == 0x12:  # SYN-ACK
            # Send RST to close the connection
            rst_packet = scapy.IP(dst=target_ip)/scapy.TCP(dport=port, flags="R")
            scapy.send(rst_packet, verbose=0)
            return port
    return None

def SYN_Stealth_Scan(target_ip, target_ports, timeout=1, delay=0, parallel=False):
    if parallel:
        scan_func = lambda t_ip, p: _syn_worker(t_ip, p, timeout)
        return threaded_port_scan(target_ip, target_ports, scan_func, progress_callback=decor)

    open_ports = []
    scanned_ports = 0
    for port in target_ports:
        port_res = _syn_worker(target_ip, port, timeout)
        if port_res is not None:
             open_ports.append(port_res)
        
        # Add delay between probes
        if delay > 0:
            time.sleep(delay)
        
        scanned_ports = scanned_ports + 1
        decor(len(target_ports), scanned_ports)

    return open_ports