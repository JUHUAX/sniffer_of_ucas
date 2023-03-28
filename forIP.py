from winpcapy import WinPcapDevices
from winpcapy import WinPcapUtils
from socket import *
import dpkt
import time
from dpkt.utils import inet_to_str
from forTransport import doicmp, doicmp6, doTCP, doUDP


curPacket = {}

def IP_callback(win_pcap, param, header, pkt_data):
    eth = dpkt.ethernet.Ethernet(pkt_data)
    #判断是否为IP数据报
    # print(eth.data.__class__.__name__)
    if isinstance(eth.data,dpkt.ip.IP):
        doIP(dpkt.ip.IP(eth.data))
    elif isinstance(eth.data, dpkt.ip6.IP6):
        doIP6(dpkt.ip6.IP6(eth.data))  
    
def getProtype(index):
    if index == 1:
        return "ICMP"
    if index == 6:
        return "TCP"
    if index == 17:
        return "UDP"
    if index == 58:
        return "IPv6-ICMP"

def doNextLayer(packet, index):
    if getProtype(index) == "TCP":
        doTCP(packet)
        return
    if getProtype(index) == "UDP":
        doUDP(packet)
        return
    if getProtype(index) == "ICMP":
        doicmp(packet)
        return
    if getProtype(index) == "IPv6-ICMP":
        doicmp6(packet)
        return
    
    
def doIP(packet):
    global curPacket
    curPacket = {"protocol":"ip",
        "time":time.strftime('%Y-%m-%d %H:%M:%S',(time.localtime())),
           'src':inet_ntop(AF_INET, packet.src) , 'dst':inet_ntop(AF_INET, packet.src),
           'protocol':getProtype(packet.p), 'len':packet.len, 'ttl':packet.ttl,
           'df':packet.df, 'mf':packet.mf, 'offset':packet.offset, 'checksum':packet.sum,
           "data": packet.data
           }
    return curPacket

def doIP6(packet):
    global curPacket
    curPacket = {"protocol":"ipv6",
        "time":time.strftime('%Y-%m-%d %H:%M:%S',(time.localtime())),
           'src':inet_ntop(AF_INET6, packet.src) , 'dst':inet_ntop(AF_INET6, packet.dst),
           'protocol':getProtype(packet.nxt), 'len':packet.plen, 'hop limit':packet.hlim,
           "data": packet.data
           }
    
    return curPacket

def readcurPacket():
    global curPacket
    return curPacket

def doIPChoose(packet):
    curPacket = {"protocol":"ip",
        "time":time.strftime('%Y-%m-%d %H:%M:%S',(time.localtime())),
           'src':inet_ntop(AF_INET, packet.src) , 'dst':inet_ntop(AF_INET, packet.src),
           'protocol':getProtype(packet.p), 'len':packet.len, 'ttl':packet.ttl,
           'df':packet.df, 'mf':packet.mf, 'offset':packet.offset, 'checksum':packet.sum,
           "data": packet.data
           }
    return curPacket

def doIP6Choose(packet):
    curPacket = {"protocol":"ipv6",
        "time":time.strftime('%Y-%m-%d %H:%M:%S',(time.localtime())),
           'src':inet_ntop(AF_INET6, packet.src) , 'dst':inet_ntop(AF_INET6, packet.dst),
           'protocol':getProtype(packet.nxt), 'len':packet.plen, 'hop limit':packet.hlim,
           "data": packet.data
           }
    return curPacket


def analysisIP(data):
    curPacket = {}
    if isinstance(data,dpkt.ip.IP):
        curPacket = doIPChoose(data)
        return curPacket
    elif isinstance(data, dpkt.ip6.IP6):
        curPacket = doIP6Choose(data)
        return curPacket
