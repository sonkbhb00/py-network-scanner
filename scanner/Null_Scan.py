import scapy.all as scapy
import time
from utils.decoratives import decor
from utils.threading import threaded_port_scan

def _null_worker(target_ip, port, timeout):
    try:
        packet = scapy.IP(dst=target_ip)/scapy.TCP(dport=port, flags="")
        response = scapy.sr1(packet, timeout=timeout, verbose=0)
        
        if response is None:
            return (port, 'open_or_filtered')
        elif response.haslayer(scapy.TCP):
            if response.getlayer(scapy.TCP).flags == 0x14:  # RST+ACK or RST
                return (port, 'closed')
        elif response.haslayer(scapy.ICMP):
            return (port, 'filtered')
        else:
            return (port, 'open_or_filtered')
    except:
        return (port, 'open_or_filtered')
    return (port, 'open_or_filtered')

def Null_Scan(target_ip, target_ports, timeout=1, delay=0, parallel=False):
    if parallel:
        scan_func = lambda t_ip, p: _null_worker(t_ip, p, timeout)
        results = threaded_port_scan(target_ip, target_ports, scan_func, progress_callback=decor)
        closed_ports = [r[0] for r in results if r[1] == 'closed']
        open_or_filtered_ports = [r[0] for r in results if r[1] == 'open_or_filtered']
        filtered_ports = [r[0] for r in results if r[1] == 'filtered']
        return closed_ports, open_or_filtered_ports, filtered_ports

    closed_ports = []
    open_or_filtered_ports = []
    filtered_ports = []
    scanned_port = 0
    
    for port in target_ports:
        res = _null_worker(target_ip, port, timeout)
        status = res[1]
        
        if status == 'closed':
            closed_ports.append(port)
        elif status == 'filtered':
            filtered_ports.append(port)
        else:
            open_or_filtered_ports.append(port)
        
        # Add delay between probes
        if delay > 0:
            time.sleep(delay)
            
        scanned_port += 1
        decor(len(target_ports), scanned_port)
        
    return closed_ports, open_or_filtered_ports, filtered_ports
