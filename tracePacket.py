from capture import allPacketRaw
from forIP import doIP6Choose, doIPChoose
from forTransport import doTCP
import dpkt

def traceIPandPort(index):
    curPacket = allPacketRaw()
    if not(isinstance(curPacket[index].data, dpkt.ip.IP or isinstance(curPacket[index].data, dpkt.ip6.IP6)) and (isinstance(curPacket[index].data.data, dpkt.tcp.TCP) or isinstance(curPacket[index].data.data, dpkt.udp.UDP))):
        return False
    traceAns = []
    traceIP = curPacket[index].data.src
    tracePort = curPacket[index].data.data.sport
    for i in range(len(curPacket)):
        if (i == index) or not(isinstance(curPacket[i].data, dpkt.ip.IP or isinstance(curPacket[i].data, dpkt.ip6.IP6)) and (isinstance(curPacket[i].data.data, dpkt.tcp.TCP) or isinstance(curPacket[i].data.data, dpkt.udp.UDP))):
            continue
        if traceIP == curPacket[i].data.src and tracePort == curPacket[i].data.data.sport:
            traceAns.append(curPacket[i])
    return traceAns