import scapy.all as scapy
from utils.decoratives import decor

def Ack_Scan(target_ip, target_port):
    unfiltered_ports = []
    scanned_port = 0
    for port in target_port:
        packet = scapy.IP(dst=target_ip)/scapy.TCP(dport=port, flags="A")
        response = scapy.sr1(packet, timeout=1, verbose=0)
        if response and response.haslayer(scapy.TCP):
            if response.getlayer(scapy.TCP).flags == 0x4:  # RST flag
                unfiltered_ports.append(port)
        scanned_port = scanned_port + 1
        decor(len(target_port), scanned_port)
    return unfiltered_ports

            
    