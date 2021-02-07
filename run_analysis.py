from datetime import datetime
from datetime import timedelta
from typing import Optional, Dict, Any, List

import pandas as pd
from scapy.all import PcapReader, raw
from scapy.layers.http import HTTP
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet

import cic_reader

pd.set_option('display.max_columns', None)
pd.set_option('display.expand_frame_repr', False)

PCAP_PATH: str = "data/wednesday1447-1451.pcap"
CSV_PATH: str = "data/cic-data-0948-1010.csv"

Socket_Pair = (str, str, int, int)


def datetime_with_timestamp(timestamp: int, offset_hours: int) -> datetime:
    return datetime.fromtimestamp(int(timestamp)) + timedelta(hours=offset_hours)


def ip_address(packet: Packet) -> (Optional[str], Optional[str]):
    if IP in packet:
        return packet[IP].src, packet[IP].dst
    elif IPv6 in packet:
        return packet[IPv6].src, packet[IPv6].dst
    else:
        return None, None


def port(packet: Packet) -> (Optional[int], Optional[int]):
    if TCP in packet:
        return packet[TCP].sport, packet[TCP].dport
    elif UDP in packet:
        return packet[UDP].sport, packet[UDP].dport
    else:
        return None, None


def contains_crlf(packet) -> bool:
    return b'\r\n\r\n' in raw(packet[TCP].payload)


def find_packets(socket_pair: Socket_Pair) -> None:
    with PcapReader(PCAP_PATH) as pcap_reader:
        frame_number: int = 0
        data: List[Dict[str, Any]] = []
        for packet in pcap_reader:
            frame_number += 1
            src: Optional[int]
            dst: Optional[int]
            src, dst = ip_address(packet)
            sport: Optional[int]
            dport: Optional[int]
            sport, dport = port(packet)

            cic_time: datetime = datetime_with_timestamp(packet.time, offset_hours=-5)
            if (src, dst, sport, dport) == socket_pair or (dst, src, dport, sport) == socket_pair:
                if TCP in packet:
                    row: Dict[str, Any] = {
                        "time": str(cic_time),
                        "frame_number": str(frame_number),
                        "sport": sport,
                        "dport": dport,
                        "window": packet[TCP].window,
                        "dataofs": packet[TCP].dataofs,
                        "http": True if HTTP in packet else "",
                        "crlf": True if HTTP in packet and contains_crlf(packet) else "",
                    }
                    data.append(row)
        if len(data) > 0:
            print(pd.DataFrame(data=data))


def find_flow(socket_pair: Socket_Pair) -> None:
    cic_data: List[Dict[str, str]] = cic_reader.read(CSV_PATH)
    for line in cic_data:
        timestamp: str = line["Timestamp"]
        source_ip: str = line["Source IP"]
        destination_ip: str = line["Destination IP"]
        source_port: int = int(line["Source Port"])
        destination_port: int = int(line["Destination Port"])
        label: str = str(line["Label"])
        total_fwd_packets: int = int(line["Total Fwd Packets"])
        total_backward_packets: int = int(line["Total Backward Packets"])
        flow_id: str = str(line["Flow ID"])

        if (source_ip, destination_ip, source_port, destination_port) == socket_pair or (
                destination_ip, source_ip, destination_port, source_port) == socket_pair:
            print({
                "time": timestamp,
                "flow_id": flow_id,
                "num_packets": total_fwd_packets + total_backward_packets,
                "label": label
            })


if __name__ == '__main__':
    socket_pair: (str, str, int, int) = ("172.16.0.1", "192.168.10.50", 53418, 80)
    find_flow(socket_pair)
    find_packets(socket_pair)
