from winpcapy import WinPcapDevices
from winpcapy import WinPcapUtils
from socket import *
import dpkt
import time
import datetime

global ans
ans = {}

def apply_callback(win_pcap, param, header, pkt_data):
    eth = dpkt.ethernet.Ethernet(pkt_data)
    apply_packet = eth.data.data.data
    
    if isinstance(apply_packet, dpkt.dns.DNS):
        doDNS(apply_packet)
    elif isinstance(apply_packet, dpkt.http):
        doHTTP(apply_packet)
    
    
# def doDNS(packet):
#     ans = {"protocol":"dns",
#            "length":,
#            "falgs":,
#            "questions":,
#            "answer rrs":,
#            "additional rrs":,
#            "queries":,
#         }




forIP("\\Device\\NPF_{5D0D792C-E3F1-484E-8D1F-9C224535DEB6}")
