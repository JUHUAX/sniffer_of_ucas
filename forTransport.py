from winpcapy import WinPcapDevices
from winpcapy import WinPcapUtils
from socket import *
import dpkt
import time
import datetime

ans = {}

def Transport_callback(win_pcap, param, header, pkt_data):
    eth = dpkt.ethernet.Ethernet(pkt_data)
    ip_packet = eth.data
    if isinstance(ip_packet.data, dpkt.udp.UDP):
        doUDP(ip_packet.data)
    elif isinstance(ip_packet.data, dpkt.tcp.TCP):
        doTCP(ip_packet.data)
    elif isinstance(ip_packet.data, dpkt.icmp.ICMP):
        doicmp(ip_packet.data)
    elif isinstance(ip_packet.data, dpkt.icmp6.ICMP6):
        doicmp6(ip_packet.data)
    
    
def doUDP(ucp_packet):
    global ans
    ans = {"protocol":"ucp",
           "sport":ucp_packet.sport,
           "dport":ucp_packet.dport,
           "sum":ucp_packet.sum,
           "ulen":ucp_packet.ulen
    }
    print(ans)

def doTCP(tcp_packet):
    # global ans
    ans = {"protocol":"tcp",
           "sport":tcp_packet.sport,
           "dport":tcp_packet.dport,
           "seq":tcp_packet.seq,
           "ack":tcp_packet.ack,
           "off":tcp_packet.off,
           "flags":tcp_packet.flags,
           "win":tcp_packet.win,
           "sum":tcp_packet.sum,
           "urp":tcp_packet.urp
    }
    print(ans)

def doicmp(icmp_packet):
    global ans
    ans = {"protocol":"icmp",
           "code":icmp_packet.code,
           "sum":icmp_packet.sum,
           "type":icmp_packet.type
    }
    print(ans)

def doicmp6(icmp6_packet):
    global ans
    ans = {"protocol":"icmp6",
           "code":icmp6_packet.code,
           "sum":icmp6_packet.sum,
           "type":icmp6_packet.type
    }
    print(ans)

def forTransport(device_name):
    WinPcapUtils.capture_on_device_name(device_name=device_name, callback=Transport_callback)
    global ans
    print(ans)
    return


forTransport("\\Device\\NPF_{5D0D792C-E3F1-484E-8D1F-9C224535DEB6}")
