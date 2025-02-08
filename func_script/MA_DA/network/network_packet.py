from scapy.all import *
from common import stop_event
import base64

result_network = {}
result_network["network"]=[]

def process_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        if protocol==6:
            protocol="TCP"
        elif protocol==17:
            protocol="UDP"
    else:
        return
    
    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    elif packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    if packet.haslayer(Raw) and src_port==80:
        payload = packet[Raw].load
        payload_len = len(payload)
    elif packet.haslayer(Raw):
        payload = packet[Raw].load
        payload_len = len(payload)
    
    if packet.haslayer(Raw):#실제 전송시에는 base64.b64encode(payload).decode('ascii') -> payload
        network_dict = {"protocol":protocol,"src":src_ip,"sport":src_port,"dst":dst_ip,"dport":dst_port,"payload_len":payload_len,"payload":base64.b64encode(payload).decode('ascii')}
    else:
        network_dict = {"protocol":protocol,"src":src_ip,"sport":src_port,"dst":dst_ip,"dport":dst_port,"payload_len":"","payload":""}

    result_network["network"].append(network_dict)
    

def process_network():
    packets = sniff(prn = process_packet, store = 1, stop_filter=lambda pkt: stop_event.is_set())
    wrpcap("captured_packets.pcap", packets)
    return result_network
