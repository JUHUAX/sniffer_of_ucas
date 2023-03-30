from dpkt.utils import mac_to_str
from socket import *

def getType(t):
    if t == 0x0806:
        return "arp"
    if t == 0x86dd:
        return "ipv6"
    if t == 0x0800:
        return "ipv4"

def analysisEth(eth):
    ethCurPacket = {
        "protocol":"eth",
        "dst":mac_to_str(eth.dst),
        "src":mac_to_str(eth.src),
        "type":getType(eth.type),
        "data":eth.data
    }
    return ethCurPacket    

def analysisARP(data):
    arpCurPacket = {
        "protocol":"ARP",
        "hrd":data.hrd,
        "pro":data.pro,
        "len":data.hln,
        "pln":data.pln,
        "op":data.op,
        "src":mac_to_str(data.sha),
        "spa":data.spa,
        "dst":mac_to_str(data.tha),
        "tpa":data.tpa,
        "data":data.data
    }
    return arpCurPacket
