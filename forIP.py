from winpcapy import WinPcapDevices
from winpcapy import WinPcapUtils
from socket import *
import dpkt
import time
import datetime

global ans
ans = {}

def IP_callback(win_pcap, param, header, pkt_data):
    eth = dpkt.ethernet.Ethernet(pkt_data)
    #判断是否为IP数据报
    # print(eth.data.__class__.__name__)
    if isinstance(eth.data, dpkt.ip.IP):
        doIP(eth.data)
    elif isinstance(eth.data, dpkt.ip6.IP6):
        doIP6(eth.data)  
    
    
def doIP(packet):
    ans = {"protocol":"ip",
        "time":time.strftime('%Y-%m-%d %H:%M:%S',(time.localtime())),
           'src':inet_ntop(AF_INET, packet.src) , 'dst':inet_ntop(AF_INET, packet.src),
           'protocol':packet.p, 'len':packet.len, 'ttl':packet.ttl,
           'df':packet.df, 'mf':packet.mf, 'offset':packet.offset, 'checksum':packet.sum
           }

def doIP6(packet):
    ans = {"protocol":"ipv6",
        "time":time.strftime('%Y-%m-%d %H:%M:%S',(time.localtime())),
           'src':inet_ntop(AF_INET6, packet.src) , 'dst':inet_ntop(AF_INET6, packet.dst),
           'protocol':packet.nxt, 'len':packet.plen, 'hop limit':packet.hlim
           }

def forIP(device_name):
    WinPcapUtils.capture_on_device_name(device_name=device_name, callback=IP_callback)
    print(ans)
    return


forIP("\\Device\\NPF_{5D0D792C-E3F1-484E-8D1F-9C224535DEB6}")
