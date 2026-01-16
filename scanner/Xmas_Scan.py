import scapy.all as scapy
from utils.decoratives import decor
def Xmas_Scan(target_ip, target_ports):
    closed_ports = []
    filtered_ports = []
    scanned_port = 0
    for port in target_ports:
        packet = scapy.IP(dst=target_ip)/scapy.TCP(dport=port, flags="FPU")
        response = scapy.sr1(packet, timeout=1, verbose=0)
        if response and response.haslayer(scapy.TCP):
            if response.getlayer(scapy.TCP).flags == 0x4:  # RST flag
                closed_ports.append(port)
        else:
            filtered_ports.append(port)
        scanned_port = scanned_port + 1
        decor(len(target_ports), scanned_port)
    return closed_ports, filtered_ports